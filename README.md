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

## Endpoints (metodo, uso y funcion)
Base local del sistema:
- `http://localhost:8000`

Nota de red:
- `localhost` solo funciona en la misma PC.
- Si tu companero esta en otra red/equipo, compartan archivos CSV/JSON exportados o desplieguen una URL publica.

### UI y stream
- `GET /`
  Funcion: abre el panel web principal.
  Respuesta: HTML.
- `GET /video_feed`
  Funcion: stream de camara en tiempo real para el panel.
  Respuesta: `multipart/x-mixed-replace` (video MJPEG).

### Operacion del escaneo
- `GET /api/status`
  Funcion: estado vivo del motor (scan, usuario actual, confianza, 2FA, lock, etc.).
  Respuesta: JSON.
- `POST /api/start_scan`
  Funcion: inicia ciclo de escaneo biometrico.
  Respuesta: JSON (`ok`).
- `POST /api/reset`
  Funcion: limpia estado actual y reinicia flujo.
  Respuesta: JSON (`ok`).
- `POST /api/mesh`
  Funcion: activar/desactivar malla facial.
  Body JSON: `{"enabled": true|false}`.
  Respuesta: JSON.
- `POST /api/performance`
  Funcion: cambiar modo de rendimiento (`normal` o `ahorro`).
  Body JSON: `{"mode":"normal"}` o `{"mode":"ahorro"}`.
  Respuesta: JSON.
- `POST /api/reload_faces`
  Funcion: recargar base de rostros desde `data/known_faces`.
  Respuesta: JSON (`ok`, `identidades`, `encodings`, `requires_restart`).

### Usuarios e identidades
- `GET /api/users`
  Funcion: lista de identidades cargadas para reconocimiento.
  Respuesta: JSON.
- `POST /api/users`
  Funcion: crear identidad (carpeta base para fotos).
  Body JSON: `{"name":"Roberto"}`.
  Respuesta: JSON.
- `DELETE /api/users/<name>`
  Funcion: eliminar identidad del sistema.
  Respuesta: JSON.

### Logs, intrusos y reportes
- `GET /api/logs?limit=120`
  Funcion: logs de eventos del sistema para panel/depuracion.
  Respuesta: JSON.
- `GET /api/intrusos`
  Funcion: lista de capturas de intrusos detectados.
  Respuesta: JSON.
- `GET /api/reportes`
  Funcion: resumen rapido de accesos (total/concedidos/denegados).
  Respuesta: JSON.

### Metricas y export de data
- `GET /api/metricas/raw`
  Funcion: metricas crudas para analisis/limpieza de datos.
  Respuesta: JSON.
- `GET /api/metricas/raw.csv`
  Funcion: descarga CSV de metricas crudas.
  Respuesta: CSV.
- `GET /api/metricas/clean`
  Funcion: metricas normalizadas (mas consistentes para analitica).
  Respuesta: JSON.
- `GET /api/metricas/clean.csv`
  Funcion: descarga CSV de metricas normalizadas.
  Respuesta: CSV.
- `GET /api/metricas/resumen`
  Funcion: resumen de metricas (`raw_total`, `clean_total`, latencias).
  Respuesta: JSON.

Filtros disponibles en endpoints de metricas:
- `from=YYYY-MM-DD HH:MM:SS`
- `to=YYYY-MM-DD HH:MM:SS`
- `metrica=<nombre_metrica>`
- `limit=<n>`

### 2FA y panel de seguridad
- `GET /api/2fa/setup`
  Funcion: estado de 2FA y metadata de configuracion.
  Respuesta: JSON.
- `GET /api/2fa/qr?token=...&username=...`
  Funcion: QR de enrolamiento TOTP (solo admin).
  Respuesta: PNG (imagen QR).
- `POST /api/2fa/verify`
  Funcion: validar codigo TOTP durante acceso.
  Body JSON: `{"code":"123456"}`.
  Respuesta: JSON.
- `GET /api/security/panel`
  Funcion: estado de bloqueo, alertas criticas e incidentes.
  Respuesta: JSON.

### Endpoints admin (requieren token)
Token via header `X-Admin-Token` o query `token`.
- `GET /api/admin/users_security`
  Funcion: listar usuarios de seguridad (rol, activo, 2FA, secreto enmascarado).
  Respuesta: JSON.
- `POST /api/admin/users_security/enroll`
  Funcion: alta/actualizacion de usuario de seguridad.
  Body JSON: `{"username":"Roberto","role":"empleado","requires_2fa":true,"active":true}`.
  Respuesta: JSON.
- `POST /api/admin/users_security/<username>/active`
  Funcion: activar/desactivar usuario.
  Body JSON: `{"active":true}`.
  Respuesta: JSON.
- `POST /api/admin/users_security/<username>/role`
  Funcion: cambiar rol.
  Body JSON: `{"role":"seguridad"}`.
  Respuesta: JSON.
- `POST /api/admin/users_security/<username>/rotate_2fa`
  Funcion: regenerar secreto 2FA y retornar URL de nuevo QR.
  Respuesta: JSON.

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
