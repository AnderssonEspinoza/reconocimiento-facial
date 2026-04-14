import csv
import time
from collections import deque
from datetime import datetime
from pathlib import Path
import webbrowser

import cv2
import face_recognition

def mock_arduino_write(mensaje):
    print(f"\n[ARDUINO LCD] -> {mensaje}\n")

PERSONA_AUTORIZADA = "Andersson"
UMBRAL_ENTRADA_AUTORIZADO = 0.50
UMBRAL_SALIDA_AUTORIZADO = 0.56
VENTANA_SUAVIZADO = 6
FRAMES_CONSECUTIVOS_REQUERIDOS = 10
SEGUNDOS_INTRUSO = 3
COOLDOWN_CAPTURA_INTRUSO = 5
RUTA_LOG = Path("registro_accesos.csv")
CARPETA_INTRUSOS = Path("intrusos")


def inicializar_log():
    if RUTA_LOG.exists():
        return
    with RUTA_LOG.open("w", newline="", encoding="utf-8") as archivo:
        writer = csv.writer(archivo)
        writer.writerow(["fecha_hora", "evento", "persona", "distancia"])


def registrar_evento(evento, persona, distancia=None):
    fecha_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    distancia_txt = f"{distancia:.4f}" if distancia is not None else "-"
    with RUTA_LOG.open("a", newline="", encoding="utf-8") as archivo:
        writer = csv.writer(archivo)
        writer.writerow([fecha_hora, evento, persona, distancia_txt])


def guardar_intruso(frame):
    CARPETA_INTRUSOS.mkdir(parents=True, exist_ok=True)
    marca_tiempo = datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta = CARPETA_INTRUSOS / f"intruso_{marca_tiempo}.jpg"
    cv2.imwrite(str(ruta), frame)
    return ruta


print("Cargando modelo de reconocimiento...")
try:
    imagen_conocida = face_recognition.load_image_file("foto_referencia.png")
    encoding_conocido = face_recognition.face_encodings(imagen_conocida)[0]
except FileNotFoundError:
    print("Error: No se encontro la imagen 'foto_referencia.png'.")
    exit()
except IndexError:
    print("Error: No se detecto ningun rostro en 'foto_referencia.png'.")
    exit()

inicializar_log()

video_capture = cv2.VideoCapture(0)
print("Cámara iniciada. Mirando... (Presiona 'q' en la ventana de video para salir)")

# Usamos una bandera para que el navegador se abra SOLO UNA VEZ
sistema_ya_abierto = False
frames_consecutivos_autorizados = 0
inicio_desconocido = None
ultima_captura_intruso = 0.0
historial_distancias = deque(maxlen=VENTANA_SUAVIZADO)
estado_autorizado_estable = False

while True:
    ret, frame = video_capture.read()
    if not ret:
        print("No se pudo leer frame de la camara. Reintentando...")
        continue

    # Achicamos la imagen para procesar rapidísimo
    small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
    rgb_small_frame = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)

    # Buscamos caras en la imagen
    face_locations = face_recognition.face_locations(rgb_small_frame)
    face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)

    rostro_autorizado_en_frame = False
    rostro_desconocido_en_frame = False
    mejor_distancia_autorizada = None
    mejor_distancia_frame = None
    idx_cara_objetivo = None

    # Analizamos cada cara detectada
    for idx, ((top, right, bottom, left), face_encoding) in enumerate(zip(face_locations, face_encodings)):
        distancia = face_recognition.face_distance([encoding_conocido], face_encoding)[0]
        if mejor_distancia_frame is None or distancia < mejor_distancia_frame:
            mejor_distancia_frame = distancia
            idx_cara_objetivo = idx

    if mejor_distancia_frame is not None:
        historial_distancias.append(mejor_distancia_frame)
        distancia_suavizada = sum(historial_distancias) / len(historial_distancias)
        if estado_autorizado_estable:
            estado_autorizado_estable = distancia_suavizada <= UMBRAL_SALIDA_AUTORIZADO
        else:
            estado_autorizado_estable = distancia_suavizada <= UMBRAL_ENTRADA_AUTORIZADO
    else:
        historial_distancias.clear()
        estado_autorizado_estable = False
        distancia_suavizada = None

    for idx, (top, right, bottom, left) in enumerate(face_locations):
        nombre = "Desconocido"
        color_caja = (0, 0, 255)  # Rojo en formato BGR

        if idx == idx_cara_objetivo and estado_autorizado_estable:
            nombre = PERSONA_AUTORIZADA
            color_caja = (0, 255, 0)  # Verde en formato BGR
            rostro_autorizado_en_frame = True
            mejor_distancia_autorizada = distancia_suavizada
        else:
            rostro_desconocido_en_frame = True

        # Multiplicamos por 4 las coordenadas porque antes achicamos la imagen a 1/4
        top *= 4
        right *= 4
        bottom *= 4
        left *= 4

        # Dibujamos el rectángulo alrededor del rostro
        cv2.rectangle(frame, (left, top), (right, bottom), color_caja, 2)

        # Dibujamos una etiqueta debajo para poner el nombre
        cv2.rectangle(frame, (left, bottom - 35), (right, bottom), color_caja, cv2.FILLED)
        cv2.putText(frame, nombre, (left + 6, bottom - 6), cv2.FONT_HERSHEY_DUPLEX, 0.8, (0, 0, 0), 1)

    if rostro_autorizado_en_frame:
        frames_consecutivos_autorizados = min(
            frames_consecutivos_autorizados + 1, FRAMES_CONSECUTIVOS_REQUERIDOS
        )
        inicio_desconocido = None
    else:
        frames_consecutivos_autorizados = 0

    progreso = int((frames_consecutivos_autorizados / FRAMES_CONSECUTIVOS_REQUERIDOS) * 100)

    if (
        not sistema_ya_abierto
        and frames_consecutivos_autorizados >= FRAMES_CONSECUTIVOS_REQUERIDOS
        and mejor_distancia_autorizada is not None
    ):
        mock_arduino_write(f"Bienvenido, {PERSONA_AUTORIZADA}!")
        print("Identidad verificada. Abriendo sistema de video...")
        webbrowser.open("https://www.youtube.com")
        registrar_evento("ACCESO_CONCEDIDO", PERSONA_AUTORIZADA, mejor_distancia_autorizada)
        sistema_ya_abierto = True

    ahora = time.time()
    if rostro_desconocido_en_frame and not rostro_autorizado_en_frame:
        if inicio_desconocido is None:
            inicio_desconocido = ahora

        segundos_desconocido = ahora - inicio_desconocido
        if (
            segundos_desconocido >= SEGUNDOS_INTRUSO
            and (ahora - ultima_captura_intruso) >= COOLDOWN_CAPTURA_INTRUSO
        ):
            ruta_intruso = guardar_intruso(frame)
            registrar_evento("ACCESO_DENEGADO", "Desconocido")
            print(f"Alerta: intruso detectado. Captura guardada en {ruta_intruso}")
            ultima_captura_intruso = ahora
    elif not rostro_autorizado_en_frame:
        inicio_desconocido = None

    if sistema_ya_abierto:
        texto_estado = "Estado: ACCESO CONCEDIDO"
        color_estado = (0, 255, 0)
    elif rostro_autorizado_en_frame:
        texto_estado = f"Analizando biometria: {progreso}%"
        color_estado = (0, 255, 255)
    elif rostro_desconocido_en_frame:
        segundos_desconocido = 0.0 if inicio_desconocido is None else (time.time() - inicio_desconocido)
        if distancia_suavizada is not None:
            texto_estado = f"Rostro desconocido: {segundos_desconocido:.1f}s | dist={distancia_suavizada:.3f}"
        else:
            texto_estado = f"Rostro desconocido: {segundos_desconocido:.1f}s"
        color_estado = (0, 0, 255)
    else:
        texto_estado = "Buscando rostro..."
        color_estado = (255, 255, 255)

    cv2.putText(frame, texto_estado, (12, 30), cv2.FONT_HERSHEY_DUPLEX, 0.8, color_estado, 2)

    # Mostramos el video en vivo
    cv2.imshow('FaceAccess - Proyecto PDP', frame)

    # Ya no usamos 'break' al reconocer, solo si presionas 'q'
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

video_capture.release()
cv2.destroyAllWindows()
