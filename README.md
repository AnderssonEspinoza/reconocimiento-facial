# PROYECTO PDP - Seguridad Biometrica

Sistema de control de acceso con:
- Reconocimiento facial en tiempo real.
- 2FA TOTP por usuario (QR + autenticador).
- Roles y estado de usuarios (`admin`, `seguridad`, `empleado`, `visita`).
- Alertas de seguridad via `n8n` (Telegram).
- Arquitectura de microservicios (`face-service`, `device-service`, `postgres-service`).

## Estructura
```text
services/
  face/
    app.py
    faceaccess.html
    Dockerfile
    requirements.txt
  device/
    app.py
    Dockerfile
    requirements.txt
db/
  init.sql
scripts/
  run_linux.sh
  run_windows.ps1
  bootstrap_empresa.sh
  import_csv_to_postgres.sh
docs/
  usuarios_empresa_ejemplo.csv
  n8n_workflow_alertas_seguridad.json
data/
  known_faces/
    README.md
docker-compose.yml
```

## Configuracion minima
En `docker-compose.yml` (servicio `face-service`) revisa:
- `TWO_FA_ADMIN_TOKEN`: token admin para operaciones sensibles (QR/enrolamiento/roles).
- `N8N_WEBHOOK_URL`: webhook de n8n (opcional).
- `PLEX_URL`: URL de Jellyfin/Plex/CasaOS a abrir tras acceso concedido.

Tambien agrega fotos de entrenamiento por usuario:
- `data/known_faces/<Usuario>/foto1.jpg`
- `data/known_faces/<Usuario>/foto2.jpg`

## Arranque rapido Linux (recomendado)
Desde la raiz del proyecto:
```bash
./scripts/run_linux.sh
```

O manual:
```bash
sudo docker compose up -d --build
```

Dashboard:
- `http://localhost:8000`

## Arranque rapido Windows
En Windows, la webcam dentro de Docker Desktop puede fallar.  
Modo recomendado: DB + device en Docker, `face-service` local.

En PowerShell (raiz del proyecto):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_windows.ps1 -AdminToken "CAMBIA_ESTE_TOKEN_ADMIN"
```

Dashboard:
- `http://localhost:8000`

## Alta masiva de usuarios (empresa)
1. Edita `docs/usuarios_empresa_ejemplo.csv`:
```csv
username,role,requires_2fa,active
Andersson,admin,true,true
Roberto,empleado,true,true
Invitado1,visita,false,false
```

2. Ejecuta bootstrap:
```bash
ADMIN_TOKEN="TU_TOKEN_ADMIN" ./scripts/bootstrap_empresa.sh
```

El script crea/actualiza usuarios en `users_security` y aplica rol/estado/2FA.

## Enrolamiento QR por usuario
El secreto TOTP real queda guardado en DB y no se muestra completo.
Para mostrar QR de un usuario (solo admin):

```text
http://localhost:8000/api/2fa/qr?token=TU_TOKEN_ADMIN&username=Roberto
```

Nota: si el token tiene `#`, en URL debe ir como `%23`.

## Endpoints clave
- `GET /api/status`
- `POST /api/start_scan`
- `POST /api/reset`
- `POST /api/2fa/verify`
- `GET /api/security/panel`
- `GET /api/metricas/raw`
- `GET /api/metricas/raw.csv`
- `GET /api/metricas/resumen`

Admin:
- `GET /api/admin/users_security`
- `POST /api/admin/users_security/enroll`
- `POST /api/admin/users_security/<username>/active`
- `POST /api/admin/users_security/<username>/role`
- `POST /api/admin/users_security/<username>/rotate_2fa`

## n8n + Telegram
Importa:
- `docs/n8n_workflow_alertas_seguridad.json`

Variables requeridas en n8n:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Y configura en `face-service`:
- `N8N_WEBHOOK_URL=http://TU_N8N/webhook/pdp-security-events`

## Archivos sensibles que no se suben
Ignorados por `.gitignore`:
- Fotos personales (`foto_referencia.png`, `data/known_faces/**` excepto README).
- Capturas de intrusos (`intrusos/`).
- Secreto local TOTP (`data/totp_secret.txt`).
- Logs locales (`registro_accesos.csv`).
