import re
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.backends.loki import LogQLBackend

RULE_PATH = Path(__file__).parent.parent / "rules" / "linux" / "ssh_brute_force.yaml"
LOGS = Path(__file__).parent / "logs"


#Compila la regla Sigma a LogQL y extrae el regex del filtro de linea
def get_compiled_regex():
    rule = SigmaCollection.from_yaml(RULE_PATH.read_text())
    query = LogQLBackend().convert(rule)[0]
    pattern = query.split("|~", 1)[1].strip().strip("`")
    return re.compile(pattern)


def matching_lines(regex, logfile):
    lines = (LOGS / logfile).read_text().splitlines()
    return [line for line in lines if regex.search(line)]


#True positive: el ataque de Hydra debe generar deteccion
def test_detects_ssh_brute_force():
    hits = matching_lines(get_compiled_regex(), "ssh_bruteforce.log")
    assert len(hits) == 5, f"Se esperaban 5 detecciones, hubo {len(hits)}"


#Regresion de falsos positivos: actividad legitima no debe alertar
def test_no_false_positives_on_normal_activity():
    hits = matching_lines(get_compiled_regex(), "normal_activity.log")
    assert hits == [], f"Falsos positivos detectados: {hits}"