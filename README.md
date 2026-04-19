# Proyecto PDP - Seguridad Biométrica (Microservicios)

Sistema de control de acceso facial con arquitectura de microservicios, 2FA por usuario, panel administrativo, telemetría y exportes de datos.

## Stack actual
- `gateway-service` (UI + API gateway)
- `recognition-service` (OpenCV/face_recognition)
- `auth-service` (roles, usuarios seguridad, TOTP)
- `access-service` (orquestación, logs, métricas, intrusos)
- `analytics-service` (KPIs derivados)
- `device-ms` (integración Arduino/serial)
- `postgres-ms`
- `prometheus-lite` + `grafana-lite`

## Requisitos
- Docker + Docker Compose
- Linux recomendado para cámara en contenedor

## Arranque rápido Linux (1 comando)
```bash
cd /home/andersson/Escritorio/proyecto-pdp
./scripts/run_micro.sh
```

Alternativa manual:
```bash
sudo docker compose -f docker-compose.micro.yml up -d --build
```

## Arranque rápido Windows (1 comando)
En PowerShell, desde la raíz del proyecto:

```powershell
docker compose -f docker-compose.micro.yml up -d --build
```

También puedes usar Git Bash/WSL:

```bash
bash ./scripts/run_micro.sh
```

Nota importante sobre cámara en Windows:
- Docker Desktop + webcam puede fallar en algunos equipos/drivers.
- Si pasa eso, API/admin/métricas sí levantan, pero el stream de cámara puede no abrir.
- Para demos con cámara estable, Linux es la opción recomendada.

## URLs principales
- App: `http://localhost:8002`
- Admin: `http://localhost:8002/admin`
- Analytics API: `http://localhost:8002/api/analytics/health`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (admin/admin)

## Alta masiva de usuarios de seguridad
Edita `docs/usuarios_empresa_ejemplo.csv` y ejecuta:

```bash
API_URL='http://localhost:8002' ADMIN_TOKEN='TU_TOKEN_ADMIN' ./scripts/bootstrap_empresa.sh
```

## QR 2FA por usuario
```text
http://localhost:8002/api/2fa/qr?token=TU_TOKEN_ADMIN&username=USUARIO
```

## Endpoints clave (gateway)
- Estado: `GET /api/status`
- Logs: `GET /api/logs?limit=120`
- Iniciar escaneo: `POST /api/start_scan`
- Reset: `POST /api/reset`
- Malla facial: `POST /api/mesh`
- Cámara on/off: `POST /api/camera`
- Recargar rostros: `POST /api/reload_faces`
- Reportes: `GET /api/reportes`
- Métricas: `GET /api/metricas/raw|clean|live|resumen`
- Intrusos: `GET /api/intrusos`
- Analytics: `GET /api/analytics/*`

## Túnel para compartir con equipo
- Cloudflared (recomendado): `./scripts/tunnel_cloudflared.sh`
- Ngrok: `./scripts/tunnel_ngrok.sh`

## Archivos sensibles (no versionar)
- `intrusos/`
- `registro_accesos.csv`
- `data/known_faces/**` (excepto README)
- `data/foto_referencia.png`
- `data/totp_secret.txt`
