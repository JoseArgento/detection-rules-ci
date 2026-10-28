#!/usr/bin/env python3
"""Compara dos reportes JSON de attack-mapper (antes / después).

Uso:  python docs/coverage/compare.py ANTES.json DESPUES.json
"""
import json
import sys


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


antes, despues = load(sys.argv[1]), load(sys.argv[2])

tec_a = {t["id"]: t["name"] for t in antes["covered_techniques"]}
tec_d = {t["id"]: t["name"] for t in despues["covered_techniques"]}
tac_a = {t["name"] for t in antes["tactics"] if t["covered"] > 0}
tac_d = {t["name"] for t in despues["tactics"] if t["covered"] > 0}

print(f"ATT&CK: {despues['version']}")
print(f"Reglas analizadas : {antes['rules_analyzed']} -> {despues['rules_analyzed']}")
print(f"Tecnicas cubiertas: {len(tec_a)} -> {len(tec_d)}")
print(f"Tacticas cubiertas: {len(tac_a)} -> {len(tac_d)}")
print("\nTacticas nuevas:")
for t in sorted(tac_d - tac_a):
    print(f"  + {t}")
print("\nTecnicas nuevas:")
for tid in sorted(tec_d.keys() - tec_a.keys()):
    print(f"  + {tid:10} {tec_d[tid]}")
if tec_a.keys() - tec_d.keys():
    print("\nATENCION, tecnicas que se PERDIERON:")
    for tid in sorted(tec_a.keys() - tec_d.keys()):
        print(f"  - {tid:10} {tec_a[tid]}")
unk = despues.get("unknown_technique_ids") or []
if unk:
    print(f"\nATENCION, IDs de tecnica que ATT&CK no reconoce: {unk}")
