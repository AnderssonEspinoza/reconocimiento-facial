# Carpeta de Rostros (Multi-Encodings)

Estructura:

- `data/known_faces/Andersson/foto1.jpg`
- `data/known_faces/Andersson/foto2.png`
- `data/known_faces/Maria/maria_1.jpg`
- `data/known_faces/Juan/juan_1.jpg`

Recomendaciones:

- 2 a 5 fotos por persona.
- Iluminación distinta (día/noche).
- Ángulos ligeramente diferentes.
- Un solo rostro principal por imagen.

Despues de agregar fotos, reinicia `face-service` para recargar la base:

```bash
sudo docker compose restart face-service
```
