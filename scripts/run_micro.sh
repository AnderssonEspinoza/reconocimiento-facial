#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Levantando arquitectura microservicios en paralelo..."
echo "Gateway: http://localhost:8002"
sudo docker compose -p pdp-micro -f docker-compose.micro.yml up -d --build

sudo docker compose -p pdp-micro -f docker-compose.micro.yml ps
