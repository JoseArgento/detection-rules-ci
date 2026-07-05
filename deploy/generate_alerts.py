#!/usr/bin/env python3
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

BASE = Path(__file__).resolve().parent.parent
RULES_DIR = BASE / "rules" / "linux"
CONFIG_PATH = Path(__file__).resolve().parent / "rules-config.yaml"
OUT_PATH = Path(__file__).resolve().parent / "generated" / "alert-rules.yaml"

LOGQL_ENVELOPE = (
    "sum by (ip) (\n"
    "  count_over_time(\n"
    '    {{job="systemd-journal"}} |~ `{regex}` '
    "| regexp `(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)` [{window}]\n"
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
    collection = SigmaCollection.from_yaml(rule_path.read_text())
    query = LogQLBackend().convert(collection)[0]
    regex = query.split("|~", 1)[1].strip().strip("`")
    return regex, collection.rules[0]


def grafana_uid(sigma_rule) -> str:
    """UID determinista derivado del id de la regla Sigma."""
    return f"sigma-{sigma_rule.id.hex[:14]}"


def build_alert(regex: str, sigma_rule, per_rule: dict, cfg: dict) -> dict:
    """Arma una alert rule con la estructura exacta del export."""
    expr = LOGQL_ENVELOPE.format(regex=regex, window=cfg["window"])
    title = sigma_rule.title
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
        "annotations": {
            "ip": "{{ $labels.ip }}",
            "summary": f"{title}: actividad desde {{{{ $labels.ip }}}}",
        },
        "isPaused": False,
        "notification_settings": {"receiver": cfg["receiver"]},
    }


def main() -> None:
    cfg = yaml.safe_load(CONFIG_PATH.read_text())

    alerts = []
    for rule_file, per_rule in cfg["rules"].items():
        regex, sigma_rule = compile_rule(RULES_DIR / rule_file)
        alerts.append(build_alert(regex, sigma_rule, per_rule, cfg))
        print(f"  [ok] {rule_file}  ->  '{sigma_rule.title}'  regex: {regex}")

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
        "# ARCHIVO GENERADO — NO EDITAR A MANO\n"
        "# Fuente: rules/linux/ + deploy/rules-config.yaml\n"
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
