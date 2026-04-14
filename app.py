import csv
import os
import threading
import time
import webbrowser
from collections import deque
from datetime import datetime
from pathlib import Path

import cv2
import face_recognition
from flask import Flask, Response, jsonify, request, send_file
import serial
import serial.tools.list_ports

BASE_DIR = Path(__file__).resolve().parent
RUTA_LOG = BASE_DIR / "registro_accesos.csv"
CARPETA_INTRUSOS = BASE_DIR / "intrusos"
FOTO_REFERENCIA = BASE_DIR / "foto_referencia.png"

PERSONA_AUTORIZADA = "Andersson"
UMBRAL_ENTRADA_AUTORIZADO = 0.50
UMBRAL_SALIDA_AUTORIZADO = 0.56
VENTANA_SUAVIZADO = 6
FRAMES_CONSECUTIVOS_REQUERIDOS = 10
SEGUNDOS_INTRUSO = 3
COOLDOWN_CAPTURA_INTRUSO = 5
SERIAL_BAUDRATE = 9600
PLEX_URL = os.getenv("PLEX_URL", "http://localhost:32400/web")
ARDUINO_PUERTO = os.getenv("ARDUINO_PORT", "").strip()
PUERTOS_CANDIDATOS = ["/dev/ttyUSB0", "/dev/ttyACM0", "COM3", "COM4", "COM5"]


class ArduinoSerial:
    def __init__(self, baudrate=SERIAL_BAUDRATE, preferred_port=""):
        self.baudrate = baudrate
        self.preferred_port = preferred_port
        self.serial_conn = None
        self.port = None
        self.last_connect_attempt = 0.0

    def _puertos_disponibles(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        ordered = []
        if self.preferred_port:
            ordered.append(self.preferred_port)
        for p in PUERTOS_CANDIDATOS:
            if p not in ordered:
                ordered.append(p)
        for p in ports:
            if p not in ordered:
                ordered.append(p)
        return ordered

    def connect(self):
        now = time.time()
        if now - self.last_connect_attempt < 2:
            return False
        self.last_connect_attempt = now

        for port in self._puertos_disponibles():
            try:
                conn = serial.Serial(port=port, baudrate=self.baudrate, timeout=1)
                time.sleep(2.0)
                self.serial_conn = conn
                self.port = port
                return True
            except Exception:
                continue
        return False

    def ensure_connected(self):
        if self.serial_conn and self.serial_conn.is_open:
            return True
        return self.connect()

    def write_line(self, msg):
        if not self.ensure_connected():
            return False, "Arduino no conectado"
        try:
            self.serial_conn.write((msg + "\n").encode("utf-8"))
            return True, f"Mensaje enviado por {self.port}"
        except Exception as exc:
            try:
                self.serial_conn.close()
            except Exception:
                pass
            self.serial_conn = None
            self.port = None
            return False, f"Fallo serial: {exc}"

    def close(self):
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()


class FaceAccessEngine:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = True
        self.scan_active = False
        self.system_open = False

        self.state = "idle"
        self.progress = 0
        self.current_user = None
        self.confidence = None
        self.distance = None
        self.unknown_seconds = 0.0

        self.arduino_text = "Esperando..."
        self.led_on = False
        self.users = [PERSONA_AUTORIZADA, "Admin"]

        self.frames_consecutivos_autorizados = 0
        self.inicio_desconocido = None
        self.ultima_captura_intruso = 0.0
        self.historial_distancias = deque(maxlen=VENTANA_SUAVIZADO)
        self.estado_autorizado_estable = False

        self.frame_jpeg = None
        self.fps = 0.0
        self.resolution = "--"

        self.logs = deque(maxlen=300)
        self.last_arduino_message = None

        self.video_capture = cv2.VideoCapture(0)
        self.encoding_conocido = self._cargar_encoding_referencia()
        self.arduino = ArduinoSerial(preferred_port=ARDUINO_PUERTO)

        self._inicializar_log_csv()
        self._add_log("FaceAccess backend iniciado.", "ok")
        if self.arduino.ensure_connected():
            self._add_log(f"Arduino conectado en {self.arduino.port} @ {SERIAL_BAUDRATE}", "ok")
        else:
            self._add_log(
                "Arduino no detectado. Sistema en modo fallback (sin LCD fisico).",
                "warn",
            )

        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _cargar_encoding_referencia(self):
        if not FOTO_REFERENCIA.exists():
            raise FileNotFoundError(f"No se encontro la imagen de referencia: {FOTO_REFERENCIA}")
        imagen_conocida = face_recognition.load_image_file(str(FOTO_REFERENCIA))
        encodings = face_recognition.face_encodings(imagen_conocida)
        if not encodings:
            raise RuntimeError("No se detecto ningun rostro en foto_referencia.png")
        return encodings[0]

    def _inicializar_log_csv(self):
        if RUTA_LOG.exists():
            return
        with RUTA_LOG.open("w", newline="", encoding="utf-8") as archivo:
            writer = csv.writer(archivo)
            writer.writerow(["fecha_hora", "evento", "persona", "distancia"])

    def _registrar_evento_csv(self, evento, persona, distancia=None):
        fecha_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        distancia_txt = f"{distancia:.4f}" if distancia is not None else "-"
        with RUTA_LOG.open("a", newline="", encoding="utf-8") as archivo:
            writer = csv.writer(archivo)
            writer.writerow([fecha_hora, evento, persona, distancia_txt])

    def _add_log(self, msg, log_type="info"):
        now = datetime.now().strftime("%H:%M:%S")
        self.logs.appendleft({"time": now, "msg": msg, "type": log_type})

    def _set_arduino_state(self, text, led_on=False, force_send=False):
        self.arduino_text = text
        self.led_on = led_on

        if not force_send and self.last_arduino_message == text:
            return

        ok, info = self.arduino.write_line(text)
        if ok:
            self.last_arduino_message = text
            self._add_log(f"[SERIAL] {text} ({info})", "warn")
        else:
            self._add_log(f"[SERIAL-OFF] {text} ({info})", "warn")

    def start_scan(self):
        with self.lock:
            self.scan_active = True
            self.state = "scanning"
            self.system_open = False
            self.current_user = None
            self.progress = 0
            self.confidence = None
            self.distance = None
            self.unknown_seconds = 0.0
            self.frames_consecutivos_autorizados = 0
            self.inicio_desconocido = None
            self.historial_distancias.clear()
            self.estado_autorizado_estable = False
            self.last_arduino_message = None
            self._set_arduino_state("Esperando...", led_on=False, force_send=True)
            self._add_log("Camara iniciada. Buscando rostros...", "info")

    def reset(self):
        with self.lock:
            self.scan_active = False
            self.system_open = False
            self.state = "idle"
            self.current_user = None
            self.progress = 0
            self.confidence = None
            self.distance = None
            self.unknown_seconds = 0.0
            self.frames_consecutivos_autorizados = 0
            self.inicio_desconocido = None
            self.historial_distancias.clear()
            self.estado_autorizado_estable = False
            self.last_arduino_message = None
            self._set_arduino_state("Esperando...", led_on=False, force_send=True)
            self._add_log("Sistema reseteado.", "info")

    def add_user(self, name):
        cleaned = name.strip()
        if not cleaned:
            return False, "Nombre vacio"
        with self.lock:
            if cleaned in self.users:
                return False, "Usuario ya existe"
            self.users.append(cleaned)
            self._add_log(f"Usuario registrado: {cleaned}", "ok")
        return True, "ok"

    def remove_user(self, name):
        with self.lock:
            if name not in self.users:
                return False
            self.users.remove(name)
            self._add_log(f"Usuario eliminado: {name}", "warn")
            return True

    def list_intruders(self, limit=20):
        CARPETA_INTRUSOS.mkdir(parents=True, exist_ok=True)
        files = sorted(CARPETA_INTRUSOS.glob("intruso_*.jpg"), reverse=True)
        return [f.name for f in files[:limit]]

    def _guardar_intruso(self, frame):
        CARPETA_INTRUSOS.mkdir(parents=True, exist_ok=True)
        marca_tiempo = datetime.now().strftime("%Y%m%d_%H%M%S")
        ruta = CARPETA_INTRUSOS / f"intruso_{marca_tiempo}.jpg"
        cv2.imwrite(str(ruta), frame)
        return ruta

    def _loop(self):
        last_fps_ts = time.time()
        frames_count = 0

        while self.running:
            if not self.video_capture.isOpened():
                self.video_capture.open(0)
                time.sleep(0.2)

            ret, frame = self.video_capture.read()
            if not ret:
                time.sleep(0.05)
                continue

            frames_count += 1
            now = time.time()
            delta = now - last_fps_ts
            if delta >= 1:
                self.fps = frames_count / delta
                frames_count = 0
                last_fps_ts = now

            self.resolution = f"{frame.shape[1]}x{frame.shape[0]}"

            with self.lock:
                scan_active = self.scan_active

            if not scan_active:
                frame_idle = frame.copy()
                cv2.putText(
                    frame_idle,
                    "IDLE - Esperando inicio de escaneo",
                    (12, 28),
                    cv2.FONT_HERSHEY_DUPLEX,
                    0.7,
                    (180, 180, 180),
                    2,
                )
                self._update_frame(frame_idle)
                continue

            processed = self._process_frame(frame)
            self._update_frame(processed)

        self.video_capture.release()

    def _process_frame(self, frame):
        small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
        rgb_small_frame = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)

        face_locations = face_recognition.face_locations(rgb_small_frame)
        face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)

        rostro_autorizado_en_frame = False
        rostro_desconocido_en_frame = False
        mejor_distancia_autorizada = None
        mejor_distancia_frame = None
        idx_cara_objetivo = None

        for idx, face_encoding in enumerate(face_encodings):
            distancia = face_recognition.face_distance([self.encoding_conocido], face_encoding)[0]
            if mejor_distancia_frame is None or distancia < mejor_distancia_frame:
                mejor_distancia_frame = distancia
                idx_cara_objetivo = idx

        if mejor_distancia_frame is not None:
            self.historial_distancias.append(mejor_distancia_frame)
            distancia_suavizada = sum(self.historial_distancias) / len(self.historial_distancias)
            if self.estado_autorizado_estable:
                self.estado_autorizado_estable = distancia_suavizada <= UMBRAL_SALIDA_AUTORIZADO
            else:
                self.estado_autorizado_estable = distancia_suavizada <= UMBRAL_ENTRADA_AUTORIZADO
        else:
            self.historial_distancias.clear()
            self.estado_autorizado_estable = False
            distancia_suavizada = None

        for idx, (top, right, bottom, left) in enumerate(face_locations):
            nombre = "Desconocido"
            color_caja = (0, 0, 255)

            if idx == idx_cara_objetivo and self.estado_autorizado_estable:
                nombre = PERSONA_AUTORIZADA
                color_caja = (0, 255, 0)
                rostro_autorizado_en_frame = True
                mejor_distancia_autorizada = distancia_suavizada
            else:
                rostro_desconocido_en_frame = True

            top *= 4
            right *= 4
            bottom *= 4
            left *= 4

            cv2.rectangle(frame, (left, top), (right, bottom), color_caja, 2)
            cv2.rectangle(frame, (left, bottom - 35), (right, bottom), color_caja, cv2.FILLED)
            cv2.putText(frame, nombre, (left + 6, bottom - 8), cv2.FONT_HERSHEY_DUPLEX, 0.7, (0, 0, 0), 1)

        if rostro_autorizado_en_frame:
            self.frames_consecutivos_autorizados = min(
                self.frames_consecutivos_autorizados + 1, FRAMES_CONSECUTIVOS_REQUERIDOS
            )
            self.inicio_desconocido = None
        else:
            self.frames_consecutivos_autorizados = 0

        self.progress = int((self.frames_consecutivos_autorizados / FRAMES_CONSECUTIVOS_REQUERIDOS) * 100)

        if (
            not self.system_open
            and self.frames_consecutivos_autorizados >= FRAMES_CONSECUTIVOS_REQUERIDOS
            and mejor_distancia_autorizada is not None
        ):
            self.system_open = True
            self.current_user = PERSONA_AUTORIZADA
            self.state = "detected"
            self._set_arduino_state(f"Bienvenido, {PERSONA_AUTORIZADA}!", led_on=True, force_send=True)
            self.distance = mejor_distancia_autorizada
            self.confidence = max(0.0, min(100.0, (1.0 - mejor_distancia_autorizada) * 100))
            self._registrar_evento_csv("ACCESO_CONCEDIDO", PERSONA_AUTORIZADA, mejor_distancia_autorizada)
            self._add_log(f"Rostro reconocido: {PERSONA_AUTORIZADA} ({self.confidence:.1f}%)", "ok")
            try:
                webbrowser.open(PLEX_URL)
                self._add_log(f"Plex/CasaOS abierto: {PLEX_URL}", "ok")
            except Exception as exc:
                self._add_log(f"No se pudo abrir Plex/CasaOS: {exc}", "err")

        ahora = time.time()
        if rostro_desconocido_en_frame and not rostro_autorizado_en_frame:
            if self.inicio_desconocido is None:
                self.inicio_desconocido = ahora
            self.unknown_seconds = ahora - self.inicio_desconocido

            if (
                self.unknown_seconds >= SEGUNDOS_INTRUSO
                and (ahora - self.ultima_captura_intruso) >= COOLDOWN_CAPTURA_INTRUSO
            ):
                ruta_intruso = self._guardar_intruso(frame)
                self._registrar_evento_csv("ACCESO_DENEGADO", "Desconocido")
                self._add_log(f"Intruso detectado. Captura guardada: {ruta_intruso.name}", "err")
                self.ultima_captura_intruso = ahora

            if not self.system_open:
                self.state = "denied"
                self.current_user = None
                self._set_arduino_state("Acceso Denegado!", led_on=True)
        elif not rostro_autorizado_en_frame:
            self.inicio_desconocido = None
            self.unknown_seconds = 0.0
            if not self.system_open:
                self.state = "scanning"
                self._set_arduino_state("Esperando...", led_on=False)

        if self.system_open:
            texto_estado = "Estado: ACCESO CONCEDIDO"
            color_estado = (0, 255, 0)
        elif rostro_autorizado_en_frame:
            self.state = "scanning"
            self.current_user = PERSONA_AUTORIZADA
            self.distance = distancia_suavizada
            if distancia_suavizada is not None:
                self.confidence = max(0.0, min(100.0, (1.0 - distancia_suavizada) * 100))
            texto_estado = f"Analizando biometria: {self.progress}%"
            color_estado = (0, 255, 255)
        elif rostro_desconocido_en_frame:
            self.current_user = None
            self.distance = distancia_suavizada
            if distancia_suavizada is not None:
                self.confidence = max(0.0, min(100.0, (1.0 - distancia_suavizada) * 100))
            texto_estado = f"Rostro desconocido: {self.unknown_seconds:.1f}s"
            color_estado = (0, 0, 255)
        else:
            self.current_user = None
            self.distance = None
            self.confidence = None
            if not self.system_open:
                self.state = "scanning"
            texto_estado = "Buscando rostro..."
            color_estado = (255, 255, 255)

        cv2.putText(frame, texto_estado, (12, 30), cv2.FONT_HERSHEY_DUPLEX, 0.8, color_estado, 2)
        return frame

    def _update_frame(self, frame):
        ok, buffer = cv2.imencode(".jpg", frame)
        if ok:
            self.frame_jpeg = buffer.tobytes()

    def generate_stream(self):
        while self.running:
            frame = self.frame_jpeg
            if frame is None:
                time.sleep(0.05)
                continue
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
            )
            time.sleep(0.03)

    def get_status(self):
        with self.lock:
            return {
                "scan_active": self.scan_active,
                "state": self.state,
                "progress": self.progress,
                "current_user": self.current_user,
                "system_open": self.system_open,
                "confidence": round(self.confidence, 1) if self.confidence is not None else None,
                "distance": round(self.distance, 4) if self.distance is not None else None,
                "unknown_seconds": round(self.unknown_seconds, 1),
                "arduino_text": self.arduino_text,
                "led_on": self.led_on,
                "fps": round(self.fps, 1),
                "resolution": self.resolution,
                "users_count": len(self.users),
                "arduino_port": self.arduino.port,
                "plex_url": PLEX_URL,
            }

    def get_logs(self, limit=100):
        with self.lock:
            return list(self.logs)[:limit]

    def get_users(self):
        with self.lock:
            return list(self.users)

    def shutdown(self):
        self.running = False
        if self.thread.is_alive():
            self.thread.join(timeout=1)
        self.arduino.close()


app = Flask(__name__)
engine = FaceAccessEngine()


@app.route("/")
def home():
    return send_file(BASE_DIR / "faceaccess.html")


@app.route("/video_feed")
def video_feed():
    return Response(
        engine.generate_stream(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@app.get("/api/status")
def api_status():
    return jsonify(engine.get_status())


@app.get("/api/logs")
def api_logs():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    return jsonify({"logs": engine.get_logs(limit=max(1, min(200, limit)))})


@app.get("/api/users")
def api_users():
    users = engine.get_users()
    return jsonify({"users": users, "count": len(users)})


@app.post("/api/users")
def api_add_user():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    ok, msg = engine.add_user(name)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True})


@app.delete("/api/users/<name>")
def api_delete_user(name):
    ok = engine.remove_user(name)
    if not ok:
        return jsonify({"ok": False, "error": "Usuario no encontrado"}), 404
    return jsonify({"ok": True})


@app.post("/api/start_scan")
def api_start_scan():
    engine.start_scan()
    return jsonify({"ok": True})


@app.post("/api/reset")
def api_reset():
    engine.reset()
    return jsonify({"ok": True})


@app.get("/api/intrusos")
def api_intrusos():
    return jsonify({"files": engine.list_intruders()})


if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)
    finally:
        engine.shutdown()
