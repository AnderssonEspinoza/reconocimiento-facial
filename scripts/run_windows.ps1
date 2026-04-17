param(
    [string]$AdminToken = "CAMBIA_ESTE_TOKEN_ADMIN",
    [string]$PlexUrl = "http://localhost:8097/web/index.html#/dashboard"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

Write-Host "[1/5] Levantando servicios Docker de soporte (DB + device-service)..."
docker compose up -d postgres-service device-service

if (-not (Test-Path ".\venv\Scripts\python.exe")) {
    Write-Host "[2/5] Creando entorno virtual..."
    py -3.10 -m venv venv
}

Write-Host "[3/5] Instalando dependencias Python..."
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r .\services\face\requirements.txt

Write-Host "[4/5] Configurando variables de entorno..."
$env:DB_URL = "postgresql://faceaccess:faceaccess@localhost:5432/faceaccess"
$env:DEVICE_SERVICE_URL = "http://localhost:8001"
$env:PLEX_URL = $PlexUrl
$env:FOTO_REFERENCIA_PATH = Join-Path $root "data\foto_referencia.png"
$env:KNOWN_FACES_DIR = Join-Path $root "data\known_faces"
$env:TWO_FA_ADMIN_TOKEN = $AdminToken

Write-Host "[5/5] Iniciando face-service local (camara Windows)..."
Write-Host "Dashboard: http://localhost:8000"
.\venv\Scripts\python.exe .\services\face\app.py
