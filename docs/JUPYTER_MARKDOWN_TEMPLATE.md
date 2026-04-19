# Reconocimiento Facial - Informe Tecnico (Plantilla)

## 1. Objetivo
Describir el objetivo del sistema y el alcance del proyecto.

## 2. Arquitectura
### 2.1 Servicios
- `recognition-service` + `access-service`: deteccion facial, reglas de acceso, dashboard y reportes.
- `device-service`: comunicacion serial con Arduino/LCD.
- `postgres-service`: persistencia de eventos de auditoria.

### 2.2 Flujo principal
1. Captura de camara en `recognition-service`.
2. Verificacion biometrica por frames consecutivos.
3. Envio de mensaje a `device-service` (`/notify`).
4. Registro de evento en CSV + PostgreSQL.
5. Render de estado y metricas en dashboard.

## 3. Tecnologias y dependencias
### 3.1 Docker Compose
Extraer servicios y variables desde `docker-compose.micro.yml`.

### 3.2 Dependencias Python
- `services/micro/recognition/requirements.txt`
- `services/device/requirements.txt`

## 4. Seguridad y robustez
- Buffer biometrico (frames consecutivos)
- Captura de intrusos
- Bitacora de acceso
- Arquitectura desacoplada por microservicios

## 5. Evidencia de ejecucion
### 5.1 Comandos usados
```bash
sudo docker compose build
sudo docker compose up
```

### 5.2 Evidencia API
- `GET /api/status`
- `GET /api/reportes`
- `GET /api/logs`

## 6. Base de datos
### 6.1 Esquema
Tabla `access_logs`:
- `id`
- `fecha_hora`
- `evento`
- `persona`
- `distancia`

### 6.2 Consultas sugeridas
```sql
SELECT evento, COUNT(*) FROM access_logs GROUP BY evento;
```

## 7. Conclusiones
- Que resultados se obtuvieron
- Que limitaciones quedaron
- Siguientes mejoras propuestas
