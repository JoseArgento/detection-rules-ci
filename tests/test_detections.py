"""Suite de tests parametrizada para reglas de deteccion Sigma.

Cada regla se compila a LogQL con pySigma (backend Loki) y se testea
el regex compilado — el mismo artefacto que se deploya en Grafana.

Criterio de asserts (decision de diseno):
  - Deteccion positiva:  >= 1 match  -> flexible, tolera tuning de la regla
  - Falsos positivos:    == 0 match  -> estricto, innegociable

El log de actividad normal es un corpus COMPARTIDO: toda regla nueva
debe pasar limpia contra todo el trafico legitimo acumulado.

Correr con:  pytest -v
"""

import re
from functools import lru_cache
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

RULES = Path(__file__).parent.parent / "rules"
LOGS = Path(__file__).parent / "logs"
NORMAL_LOG = "normal_activity.log"  # corpus benigno compartido

# ---------------------------------------------------------------------------
# Tabla de casos: (archivo de regla, log de ataque)
# Agregar una regla nueva = agregar un pytest.param aca.
# ---------------------------------------------------------------------------
CASES = [
    # --- Familia Linux / SSH ---
    pytest.param("linux/ssh_brute_force.yaml", "ssh_bruteforce.log",
                 id="ssh-brute-force"),
    pytest.param("linux/ssh_preauth_disconnect.yaml", "ssh_preauth.log",
                 id="ssh-preauth"),
    # --- Familia VMaNGOS / realmd ---
    pytest.param("vmangos/vmangos_wrong_password.yaml", "vmangos_wrong_password.log",
                 id="vmangos-wrong-password"),
    pytest.param("vmangos/vmangos_ip_lockout.yaml", "vmangos_ip_lockout.log",
                 id="vmangos-ip-lockout"),
    pytest.param("vmangos/vmangos_protocol_scan.yaml", "vmangos_protocol_scan.log",
                 id="vmangos-protocol-scan"),
]


# Compila la regla Sigma a LogQL y extrae el regex del filtro de linea.
# lru_cache: cada regla se compila una sola vez aunque corran varios tests.
@lru_cache(maxsize=None)
def compiled_regex(rule_file: str) -> re.Pattern:
    rule = SigmaCollection.from_yaml((RULES / rule_file).read_text())
    query = LogQLBackend().convert(rule)[0]
    pattern = query.split("|~", 1)[1].strip().strip("`")
    return re.compile(pattern)


def matching_lines(regex: re.Pattern, logfile: str) -> list[str]:
    lines = (LOGS / logfile).read_text().splitlines()
    return [line for line in lines if regex.search(line)]


# ---------------------------------------------------------------------------
# Tests: la clase entera se parametriza -> cada regla corre ambos tests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rule_file,attack_log", CASES)
class TestDetectionRules:
    # True positive: el ataque debe generar al menos una deteccion
    def test_detects_attack(self, rule_file, attack_log):
        hits = matching_lines(compiled_regex(rule_file), attack_log)
        assert len(hits) >= 1, (
            f"{rule_file} no detecto nada en {attack_log} — deteccion rota"
        )

    # Regresion de falsos positivos: cero tolerancia contra el corpus benigno
    def test_no_false_positives(self, rule_file, attack_log):
        hits = matching_lines(compiled_regex(rule_file), NORMAL_LOG)
        assert hits == [], (
            f"{rule_file} genero {len(hits)} falso(s) positivo(s): {hits}"
        )
