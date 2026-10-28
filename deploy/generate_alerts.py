#!/usr/bin/env python3
"""Genera las alert rules de Grafana a partir de las reglas Sigma.

Sigma define QUÉ detectar; deploy/rules-config.yaml define CÓMO alertar
(umbral, espera, stream de Loki, agrupación y destino).

Dos tipos de regla:
  - Con IP (default): agrupa por la primera IPv4 de la línea y notifica al
    SOAR (n8n), que enriquece, consulta al LLM y propone el ban.
  - Sin IP (`ip: false`): eventos del host (servicio detenido, cuenta
    creada...). No hay nada que banear: agrupa por `host` y notifica directo
    a Telegram (`receiver: telegram-alertas`) para que lo investigue un humano.
"""
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

BASE = Path(__file__).resolve().parent.parent
RULES_DIR = BASE / "rules"   # raiz: las claves de config traen la subruta
CONFIG_PATH = Path(__file__).resolve().parent / "rules-config.yaml"
OUT_PATH = Path(__file__).resolve().parent / "generated" / "alert-rules.yaml"

# Reglas con IP: la IP es el IOC que el SOAR enriquece y eventualmente banea.
LOGQL_ENVELOPE_IP = (
    "sum by (ip) (\n"
    "  count_over_time(\n"
    '    {{job="{job}"}} |~ `{regex}` '
    "| regexp `(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)` [{window}]\n"
    "  )\n"
    ")"
)

# Reglas sin IP: el "IOC" es el host donde pasó el evento.
LOGQL_ENVELOPE_HOST = (
    "sum by (host) (\n"
    "  count_over_time(\n"
    '    {{job="{job}"}} |~ `{regex}` [{window}]\n'
    "  )\n"
    ")"
)


class LiteralStr(str):
    """Marca strings multilinea para que yaml los emita como bloque |- legible."""


yaml.add_representer(
    LiteralStr,
    lambda dumper, data: dumper.represent_scalar(
        "tag:yaml.org,2002:str", data, style="|"
    ),
)


def compile_rule(rule_path: Path):
    """Compila la regla Sigma y devuelve (regex_logql, objeto SigmaRule)."""
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    query = LogQLBackend().convert(collection)[0]
    regex = query.split("|~", 1)[1].strip().strip("`")
    return regex, collection.rules[0]


def grafana_uid(sigma_rule) -> str:
    """UID determinista derivado del id de la regla Sigma."""
    return f"sigma-{sigma_rule.id.hex[:14]}"


def build_alert(regex: str, sigma_rule, per_rule: dict, cfg: dict) -> dict:
    """Arma una alert rule con la estructura exacta del export."""
    job = per_rule.get("job", cfg["default_job"])
    by_ip = per_rule.get("ip", True)
    receiver = per_rule.get("receiver", cfg["receiver"])
    envelope = LOGQL_ENVELOPE_IP if by_ip else LOGQL_ENVELOPE_HOST
    expr = envelope.format(regex=regex, window=cfg["window"], job=job)
    title = sigma_rule.title
    severity = sigma_rule.level.name.lower() if sigma_rule.level else "medium"

    if by_ip:
        # Mismo payload de siempre: el workflow de n8n lee ip y severity.
        annotations = {
            "ip": "{{ $labels.ip }}",
            "severity": severity,
            "summary": f"{title}: actividad desde {{{{ $labels.ip }}}}",
        }
    else:
        tactics = ", ".join(
            str(t) for t in sigma_rule.tags if str(t).startswith("attack.t")
        )
        annotations = {
            "severity": severity,
            "summary": f"{title} en {{{{ $labels.host }}}}",
            "description": " ".join(str(sigma_rule.description).split())
            + (f" ({tactics})" if tactics else ""),
        }

    # Reglas con IP: un webhook por IP. Sin group_by, Grafana junta en un
    # mismo envío todas las IPs que disparan la misma regla, y el workflow de
    # n8n solo evalúa alerts[0]: las demás IPs no se investigan nunca.
    notification = {"receiver": receiver}
    if by_ip:
        notification["group_by"] = ["grafana_folder", "alertname", "ip"]

    return {
        "uid": grafana_uid(sigma_rule),
        "title": title,
        "condition": "C",
        "data": [
            {
                "refId": "A",
                "queryType": "instant",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": cfg["datasource_uid"],
                "model": {
                    "editorMode": "code",
                    "expr": LiteralStr(expr),
                    "instant": True,
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "queryType": "instant",
                    "refId": "A",
                },
            },
            {
                "refId": "C",
                "queryType": "expression",
                "datasourceUid": "__expr__",
                "model": {
                    "conditions": [
                        {
                            "evaluator": {
                                "params": [per_rule["threshold"]],
                                "type": "gt",
                            },
                            "operator": {"type": "and"},
                            "query": {"params": ["C"]},
                            "reducer": {"params": [], "type": "last"},
                            "type": "query",
                        }
                    ],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "refId": "C",
                    "type": "threshold",
                },
            },
        ],
        # OK en vez de NoData: "nadie ataca" = estado Normal, no ambiguo
        "noDataState": "OK",
        "execErrState": "Error",
        "for": per_rule["for"],
        "annotations": annotations,
        "isPaused": False,
        "notification_settings": notification,
    }


def main() -> None:
    cfg = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))

    alerts = []
    for rule_file, per_rule in cfg["rules"].items():
        regex, sigma_rule = compile_rule(RULES_DIR / rule_file)
        alerts.append(build_alert(regex, sigma_rule, per_rule, cfg))
        dest = per_rule.get("receiver", cfg["receiver"])
        print(f"  [ok] {rule_file}  ->  '{sigma_rule.title}'  -> {dest}  regex: {regex}")

    doc = {
        "apiVersion": 1,
        "groups": [
            {
                "orgId": 1,
                "name": cfg["group"],
                "folder": cfg["folder"],
                "interval": cfg["interval"],
                "rules": alerts,
            }
        ],
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# =============================================================\n"
        "# ARCHIVO GENERADO - NO EDITAR A MANO\n"
        "# Fuente: rules/ + deploy/rules-config.yaml\n"
        "# Regenerar con: python3 deploy/generate_alerts.py\n"
        "# =============================================================\n"
    )
    OUT_PATH.write_text(
        header + yaml.dump(doc, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"\nGenerado: {OUT_PATH} ({len(alerts)} alertas)")


if __name__ == "__main__":
    main()
