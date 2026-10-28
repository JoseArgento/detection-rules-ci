#!/usr/bin/env bash
# Despliega las reglas en el SIEM del lab (v3).
#
# Corre en la PC (Git Bash o Linux), con los dos repos clonados uno al lado
# del otro, y con un alias "observabilidad" en ~/.ssh/config:
#
#   Documentos/
#   ├── detection-rules-ci/      <- este repo
#   └── wow-classic-secure-lab/  <- recibe el snapshot desplegado
#
# Pasos: tests -> generar -> copiar al repo del lab -> subir a la VM -> recargar Grafana.
set -euo pipefail

cd "$(dirname "$0")/.."
LAB_REPO="${LAB_REPO:-../wow-classic-secure-lab}"
SIEM_HOST="${SIEM_HOST:-observabilidad}"
REMOTE_DIR="${REMOTE_DIR:-grafana}"
DEST="provisioning/alerting/alert-rules.yaml"

# En Windows "python3" puede ser el acceso directo de la Microsoft Store.
PY=""
for c in python python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c "import sigma" 2>/dev/null; then PY="$c"; break; fi
done
[[ -n "$PY" ]] || { echo "No encuentro un Python con pySigma instalado." >&2; exit 1; }

echo "[1/5] Tests de detección..."
"$PY" -m pytest -q tests/

echo "[2/5] Generando alertas desde las reglas Sigma..."
"$PY" deploy/generate_alerts.py

echo "[3/5] Copiando al repo del lab..."
[[ -d "$LAB_REPO/grafana" ]] || { echo "No encuentro $LAB_REPO/grafana (definí LAB_REPO)." >&2; exit 1; }
cp deploy/generated/alert-rules.yaml "$LAB_REPO/grafana/$DEST"

echo "[4/5] Subiendo a $SIEM_HOST..."
scp -q deploy/generated/alert-rules.yaml "$SIEM_HOST:$REMOTE_DIR/$DEST"

echo "[5/5] Recargando Grafana..."
ssh "$SIEM_HOST" "cd $REMOTE_DIR && docker compose restart grafana"

echo "Listo. Verificar en Grafana: Alerting > Alert rules > Security > sigma-generated."
echo "No olvides commitear el snapshot en $LAB_REPO (grafana/$DEST)."
