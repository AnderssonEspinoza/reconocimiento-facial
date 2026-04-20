param(
  [string]$PythonCmd = "py"
)

$ErrorActionPreference = "Stop"

Write-Host "[1/5] Iniciando stack Docker (sin recognition-service en contenedor)..."
docker compose -f docker-compose.micro.yml -f docker-compose.hybrid-windows.yml up -d --build
docker compose -f docker-compose.micro.yml -f docker-compose.hybrid-windows.yml stop recognition-service

Write-Host "[2/5] Preparando entorno local para recognition-service..."
if (!(Test-Path ".venv-rec")) {
  & $PythonCmd -m venv .venv-rec
}

Write-Host "[3/5] Activando entorno..."
. .\.venv-rec\Scripts\Activate.ps1

Write-Host "[4/5] Instalando dependencias de recognition-service..."
pip install --upgrade pip
pip install -r .\services\micro\recognition\requirements.txt

Write-Host "[5/5] Ejecutando recognition-service local en puerto 8101..."
Write-Host "Dashboard: http://localhost:8002"
Write-Host "Admin: http://localhost:8002/admin"
python .\services\micro\recognition\app.py
