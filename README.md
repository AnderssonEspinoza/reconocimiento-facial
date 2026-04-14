# FaceAccess PDP

Plataforma de control de acceso biometrico basada en reconocimiento facial, construida con arquitectura de microservicios y preparada para despliegue con Docker.

## Caracteristicas
- Verificacion facial en tiempo real con OpenCV + `face_recognition`
- Buffer biometrico (frames consecutivos) para evitar falsos positivos
- Deteccion y captura de intrusos
- Mensajeria a Arduino/LCD por microservicio dedicado (`device-service`)
- Apertura de Plex/CasaOS tras acceso valido
- Auditoria dual:
  - `registro_accesos.csv` (respaldo local)
  - PostgreSQL (`access_logs`) para analitica y reportes
- Dashboard web con estado en vivo y metricas de base de datos

## Arquitectura (Microservicios)
- `face-service` (puerto `8000`):
  - Camara, reconocimiento facial, reglas de acceso, dashboard y reportes
- `device-service` (puerto `8001`):
  - Integracion serial con Arduino/LCD
- `postgres-service` (puerto `5432`):
  - Persistencia de auditoria (`access_logs`)

## Estructura del proyecto
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
  import_csv_to_postgres.sh
data/
  README.md

docker-compose.yml
README.md
```

## Requisitos
- Docker y Docker Compose
- Camara local (`/dev/video0` en Linux)
- (Opcional) Arduino conectado por USB (`/dev/ttyACM0` o `/dev/ttyUSB0`)

## Configuracion de datos sensibles (obligatorio)
Este repositorio **no incluye** datos biometricos personales.

1. Coloca tu foto de referencia en:
```bash
data/foto_referencia.png
```
2. Asegurate de que sea una foto frontal, bien iluminada y con un solo rostro.

## Ejecutar el sistema
### 1) Build inicial
```bash
sudo docker compose build
```

### 2) Levantar servicios
```bash
sudo docker compose up
```

### 3) Abrir dashboard
- URL: `http://127.0.0.1:8000`

## Variables relevantes
En `docker-compose.yml`:
- `PLEX_URL`: URL de Plex/CasaOS para abrir al conceder acceso
- `DEVICE_SERVICE_URL`: URL interna del microservicio de Arduino
- `DB_URL`: conexion PostgreSQL usada por `face-service`
- `FOTO_REFERENCIA_PATH`: ruta interna de la imagen de referencia (`/app/data/foto_referencia.png`)

## Importar historial CSV a PostgreSQL
Si ya tienes eventos en `registro_accesos.csv`:
```bash
./scripts/import_csv_to_postgres.sh
```

El script:
- levanta `postgres-service`
- espera estado healthy
- importa CSV a `access_logs`
- evita duplicados

## Endpoints principales
### face-service
- `GET /api/status`
- `GET /api/logs?limit=120`
- `GET /api/reportes`
- `GET /api/users`
- `POST /api/users`
- `DELETE /api/users/<name>`
- `POST /api/start_scan`
- `POST /api/reset`
- `GET /video_feed`

### device-service
- `GET /health`
- `GET /status`
- `POST /notify`

## Consultas SQL utiles
```sql
SELECT evento, COUNT(*)
FROM access_logs
GROUP BY evento;
```

```sql
SELECT fecha_hora, evento, persona, distancia
FROM access_logs
ORDER BY fecha_hora DESC
LIMIT 20;
```

## Documentacion en Jupyter (equipo)
Se incluye plantilla para informe tecnico:
- `docs/JUPYTER_MARKDOWN_TEMPLATE.md`

Tu compañero puede copiar esa estructura a una celda Markdown de JupyterLab y completar evidencia, capturas y conclusiones.

## Buenas practicas de versionado
Este proyecto ignora automaticamente:
- fotos biometricas (`data/foto_referencia.png`)
- capturas de intrusos (`intrusos/`)
- bitacora local (`registro_accesos.csv`)
- archivo `faceaccess.html` legacy en raiz

## Estado del proyecto
Listo para:
- demo academica
- sustentacion con enfoque enterprise
- evolucion a observabilidad, auth y alertas (fase siguiente)
