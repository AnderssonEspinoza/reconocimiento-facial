#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Compat:
# - API_BASE (historico)
# - API_URL  (nuevo nombre mas intuitivo)
API_BASE="${API_BASE:-${API_URL:-http://localhost:8002}}"
CSV_FILE="${1:-$ROOT_DIR/docs/usuarios_empresa_ejemplo.csv}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "ERROR: falta ADMIN_TOKEN." >&2
  echo "Ejemplo:" >&2
  echo "  ADMIN_TOKEN='TU_TOKEN' ./scripts/bootstrap_empresa.sh" >&2
  echo "  API_URL='http://localhost:8002' ADMIN_TOKEN='TU_TOKEN' ./scripts/bootstrap_empresa.sh" >&2
  exit 1
fi

if [[ ! -f "$CSV_FILE" ]]; then
  echo "ERROR: no existe CSV: $CSV_FILE" >&2
  exit 1
fi

echo "[1/4] Verificando API en $API_BASE ..."
curl -fsS "$API_BASE/api/status" >/dev/null

echo "[2/4] Cargando usuarios desde: $CSV_FILE"
echo "Formato esperado: username,role,requires_2fa,active"
echo "Base URL objetivo: $API_BASE"

ok_count=0
err_count=0
line_no=0

while IFS=, read -r raw_username raw_role raw_requires_2fa raw_active; do
  line_no=$((line_no + 1))

  username="$(echo "${raw_username:-}" | xargs)"
  role="$(echo "${raw_role:-empleado}" | xargs)"
  requires_2fa="$(echo "${raw_requires_2fa:-true}" | xargs | tr '[:upper:]' '[:lower:]')"
  active="$(echo "${raw_active:-true}" | xargs | tr '[:upper:]' '[:lower:]')"

  if [[ $line_no -eq 1 && "$username" == "username" ]]; then
    continue
  fi

  if [[ -z "$username" || "$username" == \#* ]]; then
    continue
  fi

  if [[ "$requires_2fa" != "true" && "$requires_2fa" != "false" ]]; then
    requires_2fa="true"
  fi
  if [[ "$active" != "true" && "$active" != "false" ]]; then
    active="true"
  fi

  enroll_payload=$(printf '{"username":"%s","role":"%s","requires_2fa":%s}' "$username" "$role" "$requires_2fa")
  enroll_resp="$(curl -sS -w "\n%{http_code}" -X POST "$API_BASE/api/admin/users_security/enroll" \
    -H "Content-Type: application/json" \
    -H "X-Admin-Token: $ADMIN_TOKEN" \
    -d "$enroll_payload")"
  enroll_body="$(echo "$enroll_resp" | sed '$d')"
  enroll_code="$(echo "$enroll_resp" | tail -n1)"

  if [[ "$enroll_code" -lt 200 || "$enroll_code" -ge 300 ]]; then
    echo "  [ERROR] $username -> enroll fallo ($enroll_code): $enroll_body"
    err_count=$((err_count + 1))
    continue
  fi

  active_payload=$(printf '{"active":%s}' "$active")
  active_resp="$(curl -sS -w "\n%{http_code}" -X POST "$API_BASE/api/admin/users_security/$username/active" \
    -H "Content-Type: application/json" \
    -H "X-Admin-Token: $ADMIN_TOKEN" \
    -d "$active_payload")"
  active_code="$(echo "$active_resp" | tail -n1)"
  if [[ "$active_code" -lt 200 || "$active_code" -ge 300 ]]; then
    echo "  [WARN] $username -> no se pudo actualizar active ($active_code)"
  fi

  echo "  [OK] $username | role=$role | requires_2fa=$requires_2fa | active=$active"
  ok_count=$((ok_count + 1))
done <"$CSV_FILE"

echo "[3/4] Listado final de seguridad"
curl -fsS "$API_BASE/api/admin/users_security" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | sed 's/},{/},\n{/g'

echo "[4/4] Resumen"
echo "  OK: $ok_count"
echo "  ERROR: $err_count"
echo "Tip QR (reemplaza USUARIO):"
echo "  $API_BASE/api/2fa/qr?token=<ADMIN_TOKEN_URL_ENCODED>&username=USUARIO"
echo "Listo."
