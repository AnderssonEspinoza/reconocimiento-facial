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

## Modo híbrido Windows (recomendado si falla la cámara en Docker)
En este modo:
- Todo el stack corre en Docker.
- Solo `recognition-service` corre local en Windows para usar la cámara directamente.

Archivo de override:
- `docker-compose.hybrid-windows.yml`

Comando recomendado (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_hybrid_windows.ps1
```

Esto hace:
1. Levanta Docker con override híbrido.
2. Crea/activa un venv local para recognition.
3. Instala dependencias de `services/micro/recognition/requirements.txt`.
4. Ejecuta `recognition-service` local en `http://localhost:8101`.
5. Mantiene app/admin funcionando en `http://localhost:8002`.

## Troubleshooting cámara en Windows
Si la cámara sale en negro o da `Camera index out of range`:

1. Cierra apps que usan cámara (Teams, Zoom, navegador con webcam abierta).
2. Prueba modo híbrido (`run_hybrid_windows.ps1`).
3. Si sigue fallando, cambia índice de cámara local:
   - Edita `services/micro/recognition/app.py` o define `CAMERA_INDEX` en entorno local.
4. Verifica permisos de cámara en Windows:
   - Configuración -> Privacidad y seguridad -> Cámara.
5. Reinicia el servicio local de reconocimiento y vuelve a abrir `http://localhost:8002`.

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
