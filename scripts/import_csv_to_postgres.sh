#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/4] Levantando postgres-service..."
sudo docker compose up -d postgres-service

echo "[2/4] Esperando a que Postgres esté healthy..."
for i in {1..30}; do
  status=$(sudo docker inspect -f '{{.State.Health.Status}}' postgres-service-pdp 2>/dev/null || echo "starting")
  if [[ "$status" == "healthy" ]]; then
    echo "Postgres listo."
    break
  fi
  sleep 2
  if [[ "$i" -eq 30 ]]; then
    echo "Postgres no llegó a healthy a tiempo." >&2
    exit 1
  fi
done

echo "[3/4] Copiando CSV al contenedor..."
sudo docker cp "$ROOT_DIR/registro_accesos.csv" postgres-service-pdp:/tmp/registro_accesos.csv

echo "[4/4] Importando historial sin duplicados..."
sudo docker compose exec -T postgres-service psql -U faceaccess -d faceaccess <<'SQL'
CREATE TABLE IF NOT EXISTS access_logs (
  id BIGSERIAL PRIMARY KEY,
  fecha_hora TIMESTAMP NOT NULL DEFAULT NOW(),
  evento VARCHAR(64) NOT NULL,
  persona VARCHAR(128) NOT NULL,
  distancia DOUBLE PRECISION
);

CREATE TEMP TABLE import_access_logs (
  fecha_hora TEXT,
  evento TEXT,
  persona TEXT,
  distancia_text TEXT
);

\copy import_access_logs(fecha_hora, evento, persona, distancia_text)
FROM '/tmp/registro_accesos.csv'
WITH (FORMAT csv, HEADER true);

INSERT INTO access_logs (fecha_hora, evento, persona, distancia)
SELECT
  fecha_hora::timestamp,
  evento,
  persona,
  NULLIF(distancia_text, '-')::double precision
FROM import_access_logs i
WHERE NOT EXISTS (
  SELECT 1
  FROM access_logs a
  WHERE a.fecha_hora = i.fecha_hora::timestamp
    AND a.evento = i.evento
    AND a.persona = i.persona
    AND COALESCE(a.distancia, -9999.0) = COALESCE(NULLIF(i.distancia_text, '-')::double precision, -9999.0)
);

SELECT COUNT(*) AS total_registros FROM access_logs;
SQL

echo "Importación completada."
