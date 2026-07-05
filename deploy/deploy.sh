#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$HOME/detection-rules-ci"
PROVISIONING_DIR="$HOME/grafana/provisioning/alerting"
GRAFANA_CONTAINER="grafana"

echo "[1/4] Actualizando repo..."
cd "$REPO_DIR"
git pull --ff-only

echo "[2/4] Generando alertas desde reglas Sigma..."
python3 deploy/generate_alerts.py

echo "[3/4] Copiando a provisioning de Grafana..."
cp deploy/generated/alert-rules.yaml "$PROVISIONING_DIR/"

echo "[4/4] Recargando Grafana..."
docker restart "$GRAFANA_CONTAINER"

echo "Deploy completo. Verifica en Grafana: Alerting > Alert rules > Security"
