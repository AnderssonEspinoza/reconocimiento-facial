#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/2] Levantando servicios con Docker..."
sudo docker compose up -d --build

echo "[2/2] Estado de servicios:"
sudo docker compose ps

echo ""
echo "Dashboard: http://localhost:8000"
echo "Si agregaste nuevas fotos en data/known_faces, reinicia face-service:"
echo "  sudo docker compose restart face-service"
