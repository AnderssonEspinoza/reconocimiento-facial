import csv
import io
import json
import os
import base64
import hashlib
import hmac
import secrets
import struct
import shutil
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
import webbrowser
from collections import Counter
from collections import deque
from datetime import datetime
from pathlib import Path

import cv2
import face_recognition
from flask import Flask, Response, jsonify, request, send_file
import psycopg2
from psycopg2.extras import Json
import qrcode

BASE_DIR = Path(__file__).resolve().parent
RUTA_LOG = BASE_DIR / "registro_accesos.csv"
CARPETA_INTRUSOS = BASE_DIR / "intrusos"
FOTO_REFERENCIA = Path(
    os.getenv("FOTO_REFERENCIA_PATH", str(BASE_DIR / "data" / "foto_referencia.png"))
)
KNOWN_FACES_DIR = Path(
    os.getenv("KNOWN_FACES_DIR", str(BASE_DIR / "data" / "known_faces"))
)

PERSONA_AUTORIZADA = "Andersson"
UMBRAL_ENTRADA_AUTORIZADO = 0.50
UMBRAL_SALIDA_AUTORIZADO = 0.56
VENTANA_SUAVIZADO = 6
FRAMES_CONSECUTIVOS_REQUERIDOS = 10
SEGUNDOS_INTRUSO = 3
COOLDOWN_CAPTURA_INTRUSO = 5

PLEX_URL = os.getenv("PLEX_URL", "http://localhost:8097/web/index.html#/dashboard")
DEVICE_SERVICE_URL = os.getenv("DEVICE_SERVICE_URL", "http://device-service:8001")
DB_URL = os.getenv("DB_URL", "postgresql://faceaccess:faceaccess@postgres-service:5432/faceaccess")
FRAME_SCALE = float(os.getenv("FRAME_SCALE", "0.22"))
PROCESS_EVERY_N_FRAMES = int(os.getenv("PROCESS_EVERY_N_FRAMES", "2"))
LANDMARK_EVERY_N_FRAMES = int(os.getenv("LANDMARK_EVERY_N_FRAMES", "3"))
ENABLE_FACE_MESH = os.getenv("ENABLE_FACE_MESH", "0").strip().lower() not in {"0", "false", "no"}
CAMERA_IDLE_RELEASE_SECONDS = float(os.getenv("CAMERA_IDLE_RELEASE_SECONDS", "3.0"))
LIVE_RELOAD_FACE_DB = os.getenv("LIVE_RELOAD_FACE_DB", "0").strip().lower() in {"1", "true", "yes"}
CAMERA_WIDTH = int(os.getenv("CAMERA_WIDTH", "960"))
CAMERA_HEIGHT = int(os.getenv("CAMERA_HEIGHT", "540"))
JPEG_QUALITY = int(os.getenv("JPEG_QUALITY", "75"))
MAX_FACES_PER_FRAME = int(os.getenv("MAX_FACES_PER_FRAME", "4"))
MIN_FACE_SIZE_PX = int(os.getenv("MIN_FACE_SIZE_PX", "24"))
LOW_LIGHT_THRESHOLD = float(os.getenv("LOW_LIGHT_THRESHOLD", "35.0"))
BLUR_THRESHOLD = float(os.getenv("BLUR_THRESHOLD", "55.0"))
AUTO_PERFORMANCE_MODE = os.getenv("AUTO_PERFORMANCE_MODE", "1").strip().lower() in {"1", "true", "yes"}
TARGET_FPS_MIN = float(os.getenv("TARGET_FPS_MIN", "12.0"))
HIGH_LOAD_FRAME_SCALE = float(os.getenv("HIGH_LOAD_FRAME_SCALE", "0.18"))
HIGH_LOAD_PROCESS_EVERY_N_FRAMES = int(os.getenv("HIGH_LOAD_PROCESS_EVERY_N_FRAMES", "4"))
ENABLE_2FA = os.getenv("ENABLE_2FA", "1").strip().lower() in {"1", "true", "yes"}
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "PROYECTO_PDP")
TOTP_ACCOUNT = os.getenv("TOTP_ACCOUNT", "acceso@pdp.local")
TOTP_PERIOD_SECONDS = int(os.getenv("TOTP_PERIOD_SECONDS", "30"))
TOTP_DIGITS = int(os.getenv("TOTP_DIGITS", "6"))
TWO_FA_GRACE_SECONDS = int(os.getenv("TWO_FA_GRACE_SECONDS", "20"))
TWO_FA_TRUST_SECONDS = int(os.getenv("TWO_FA_TRUST_SECONDS", "180"))
SECURITY_LOCK_MAX_FAILS = int(os.getenv("SECURITY_LOCK_MAX_FAILS", "3"))
SECURITY_LOCK_WINDOW_SECONDS = int(os.getenv("SECURITY_LOCK_WINDOW_SECONDS", "60"))
SECURITY_LOCK_SECONDS = int(os.getenv("SECURITY_LOCK_SECONDS", "45"))
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "").strip()
TWO_FA_ADMIN_TOKEN = os.getenv("TWO_FA_ADMIN_TOKEN", "").strip()
ENABLE_LIVENESS_CHALLENGE = os.getenv("ENABLE_LIVENESS_CHALLENGE", "1").strip().lower() in {"1", "true", "yes"}
LIVENESS_DELTA_PX = int(os.getenv("LIVENESS_DELTA_PX", "18"))


class DeviceServiceClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def notify(self, text, led_on=False, force=False):
        payload = {"text": text, "led_on": led_on, "force": force}
        req = urllib.request.Request(
            f"{self.base_url}/notify",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return bool(data.get("ok")), data.get("info", "")
        except urllib.error.URLError as exc:
            return False, f"device-service sin respuesta: {exc}"
        except Exception as exc:
            return False, f"error notify: {exc}"

    def status(self):
        req = urllib.request.Request(f"{self.base_url}/status", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return True, data
        except Exception:
            return False, {"connected": False, "port": None}


class FaceAccessEngine:
    def __init__(self):
        # RLock evita deadlocks cuando un metodo con lock llama otro metodo que tambien usa lock.
        self.lock = threading.RLock()
        self.face_ops_lock = threading.Lock()
        self.running = True
        self.reload_faces_requested = False
        self.reload_faces_event = threading.Event()
        self.last_reload_result = {"ok": True, "encodings": 0, "identidades": 0}
        self.last_reload_request_ts = 0.0
        self.scan_active = False
        self.system_open = False

        self.state = "idle"
        self.progress = 0
        self.current_user = None
        self.current_role = None
        self.confidence = None
        self.distance = None
        self.unknown_seconds = 0.0

        self.arduino_text = "Esperando..."
        self.led_on = False
        self.users = []

        self.frames_consecutivos_autorizados = 0
        self.inicio_desconocido = None
        self.ultima_captura_intruso = 0.0
        self.historial_distancias = deque(maxlen=VENTANA_SUAVIZADO)
        self.historial_nombres = deque(maxlen=VENTANA_SUAVIZADO)
        self.estado_autorizado_estable = False
        self.nombre_autorizado_estable = None

        self.frame_jpeg = None
        self.fps = 0.0
        self.resolution = "--"

        self.logs = deque(maxlen=300)
        self.last_device_message = None
        self.db_connected = False
        self.frame_index = 0
        self.cached_face_locations = []
        self.cached_face_encodings = []
        self.cached_face_landmarks = []
        self.user_mesh_enabled = ENABLE_FACE_MESH
        self.enable_face_mesh = ENABLE_FACE_MESH
        self.current_frame_scale = FRAME_SCALE
        self.current_process_every_n_frames = PROCESS_EVERY_N_FRAMES
        self.current_landmark_every_n_frames = LANDMARK_EVERY_N_FRAMES
        self.auto_performance = AUTO_PERFORMANCE_MODE
        self.perf_mode = "normal"
        self.last_quality_info = {"blur": None, "luma": None, "quality_ok": True}
        self.last_detected_people = []
        self.scan_started_at = None
        self.two_fa_enabled = ENABLE_2FA
        self.two_fa_pending = False
        self.two_fa_user = None
        self.two_fa_distance = None
        self.two_fa_confidence = None
        self.two_fa_expires_at = 0.0
        self.two_fa_trusted_until = 0.0
        self.two_fa_fail_count = 0
        self.security_lock_until = 0.0
        self.failed_attempt_timestamps = deque(maxlen=40)
        self.two_fa_secret = self._load_or_create_totp_secret()
        self.security_events = deque(maxlen=200)
        self.user_security = {}
        self.liveness_enabled = ENABLE_LIVENESS_CHALLENGE
        self.liveness_ok = not self.liveness_enabled
        self.liveness_direction = "derecha"
        self.liveness_baseline_x = None

        self.device_client = DeviceServiceClient(DEVICE_SERVICE_URL)

        self.video_capture = None
        self.active_stream_clients = 0
        self.last_stream_activity_ts = 0.0
        self.camera_is_open = False
        self.known_encodings = []
        self.known_names = []
        self._reload_face_database(log=False)

        self._inicializar_log_csv()
        self._init_db()
        self._add_log(
            f"Base biometrica cargada: {len(self.known_encodings)} encodings / "
            f"{len(set(self.known_names))} identidades.",
            "ok",
        )
        self.last_reload_result = {
            "ok": True,
            "encodings": len(self.known_encodings),
            "identidades": len(set(self.known_names)),
        }
        self._add_log("face-service iniciado.", "ok")
        ok, ds = self.device_client.status()
        if ok and ds.get("connected"):
            self._add_log(f"device-service conectado a Arduino en {ds.get('port')}", "ok")
        else:
            self._add_log("device-service activo, Arduino aun no conectado.", "warn")

        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _load_or_create_totp_secret(self):
        secret_file = BASE_DIR / "data" / "totp_secret.txt"
        env_secret = os.getenv("TOTP_SECRET", "").strip().replace(" ", "").upper()
        if env_secret:
            return env_secret
        try:
            secret_file.parent.mkdir(parents=True, exist_ok=True)
            if secret_file.exists():
                value = secret_file.read_text(encoding="utf-8").strip().replace(" ", "").upper()
                if value:
                    return value
            generated = base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")
            secret_file.write_text(generated, encoding="utf-8")
            return generated
        except Exception:
            return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")

    @staticmethod
    def _mask_secret(secret):
        if not secret:
            return ""
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    @staticmethod
    def _admin_token_valid(token):
        if not TWO_FA_ADMIN_TOKEN:
            return False
        incoming = (token or "").strip()
        if not incoming:
            return False
        return hmac.compare_digest(incoming, TWO_FA_ADMIN_TOKEN)

    @staticmethod
    def _totp_code_for_secret(secret, unix_ts):
        if not secret:
            return None
        key = secret.upper()
        padded = key + "=" * ((8 - len(key) % 8) % 8)
        key_bytes = base64.b32decode(padded)
        counter = int(unix_ts // TOTP_PERIOD_SECONDS)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key_bytes, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code_int = (
            ((digest[offset] & 0x7F) << 24)
            | (digest[offset + 1] << 16)
            | (digest[offset + 2] << 8)
            | digest[offset + 3]
        )
        return str(code_int % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)

    def _totp_code_at(self, unix_ts):
        return self._totp_code_for_secret(self.two_fa_secret, unix_ts)

    def _verify_totp(self, code, secret=None):
        clean = str(code or "").strip()
        if not clean.isdigit() or len(clean) != TOTP_DIGITS:
            return False
        secret_to_use = secret or self.two_fa_secret
        now = time.time()
        for step in (-1, 0, 1):
            if self._totp_code_for_secret(secret_to_use, now + step * TOTP_PERIOD_SECONDS) == clean:
                return True
        return False

    def _totp_otpauth_uri(self):
        label = urllib.parse.quote(f"{TOTP_ISSUER}:{TOTP_ACCOUNT}")
        issuer = urllib.parse.quote(TOTP_ISSUER)
        secret = urllib.parse.quote(self.two_fa_secret)
        return (
            f"otpauth://totp/{label}"
            f"?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
        )

    @staticmethod
    def _totp_otpauth_uri_for(username, secret):
        label = urllib.parse.quote(f"{TOTP_ISSUER}:{username}")
        issuer = urllib.parse.quote(TOTP_ISSUER)
        secret_q = urllib.parse.quote(secret)
        return (
            f"otpauth://totp/{label}"
            f"?secret={secret_q}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
        )

    def _record_security_event(self, event_type, level, detail, extra=None):
        event = {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "level": level,
            "detail": detail,
            "extra": extra or {},
        }
        self.security_events.appendleft(event)

    def _notify_n8n(self, event_type, payload):
        if not N8N_WEBHOOK_URL:
            return
        body = json.dumps({"event_type": event_type, "source": "face-service", "payload": payload}).encode("utf-8")
        req = urllib.request.Request(
            N8N_WEBHOOK_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        def _send():
            try:
                with urllib.request.urlopen(req, timeout=2.0):
                    pass
            except Exception:
                return

        threading.Thread(target=_send, daemon=True).start()

    def _register_failed_attempt(self):
        now = time.time()
        self.failed_attempt_timestamps.append(now)
        window_start = now - SECURITY_LOCK_WINDOW_SECONDS
        fails_in_window = sum(1 for ts in self.failed_attempt_timestamps if ts >= window_start)
        if fails_in_window >= SECURITY_LOCK_MAX_FAILS:
            self.security_lock_until = now + SECURITY_LOCK_SECONDS
            self._record_security_event(
                "lock_activado",
                "crit",
                f"Bloqueo temporal activado por {fails_in_window} fallos consecutivos.",
                {"locked_until": datetime.fromtimestamp(self.security_lock_until).strftime("%H:%M:%S")},
            )
            self._notify_n8n(
                "lock_activado",
                {"fails_in_window": fails_in_window, "lock_seconds": SECURITY_LOCK_SECONDS},
            )

    @staticmethod
    def _normalize_username(name):
        return " ".join(str(name or "").strip().split())

    @staticmethod
    def _generate_new_totp_secret():
        return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")

    def _load_users_security_from_db(self):
        cache = {}
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT username, role, active, requires_2fa, totp_secret, created_at, updated_at
                        FROM users_security
                        """
                    )
                    for row in cur.fetchall():
                        username = row[0]
                        cache[username] = {
                            "username": username,
                            "role": row[1] or "empleado",
                            "active": bool(row[2]),
                            "requires_2fa": bool(row[3]),
                            "totp_secret": row[4],
                            "created_at": row[5].strftime("%Y-%m-%d %H:%M:%S") if row[5] else None,
                            "updated_at": row[6].strftime("%Y-%m-%d %H:%M:%S") if row[6] else None,
                        }
        except Exception:
            return
        with self.lock:
            self.user_security = cache

    def _upsert_user_security(self, username, role="empleado", active=True, requires_2fa=True, totp_secret=None):
        uname = self._normalize_username(username)
        if not uname:
            return False, "username vacio", None
        role_clean = (role or "empleado").strip().lower()
        if role_clean not in {"admin", "seguridad", "empleado", "visita"}:
            role_clean = "empleado"
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO users_security (username, role, active, requires_2fa, totp_secret, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT (username) DO UPDATE
                        SET role = EXCLUDED.role,
                            active = EXCLUDED.active,
                            requires_2fa = EXCLUDED.requires_2fa,
                            totp_secret = COALESCE(EXCLUDED.totp_secret, users_security.totp_secret),
                            updated_at = NOW()
                        RETURNING username, role, active, requires_2fa, totp_secret, created_at, updated_at
                        """,
                        (uname, role_clean, bool(active), bool(requires_2fa), totp_secret),
                    )
                    row = cur.fetchone()
                conn.commit()
            record = {
                "username": row[0],
                "role": row[1],
                "active": bool(row[2]),
                "requires_2fa": bool(row[3]),
                "totp_secret": row[4],
                "created_at": row[5].strftime("%Y-%m-%d %H:%M:%S") if row[5] else None,
                "updated_at": row[6].strftime("%Y-%m-%d %H:%M:%S") if row[6] else None,
            }
            with self.lock:
                self.user_security[uname] = record
            return True, "ok", record
        except Exception as exc:
            return False, str(exc), None

    def _get_user_security(self, username):
        uname = self._normalize_username(username)
        with self.lock:
            return dict(self.user_security.get(uname, {})) if uname in self.user_security else None

    def list_user_security(self):
        with self.lock:
            rows = []
            for uname in sorted(self.user_security.keys()):
                rec = dict(self.user_security[uname])
                rec["totp_secret_masked"] = self._mask_secret(rec.get("totp_secret") or "")
                rec.pop("totp_secret", None)
                rows.append(rec)
            return rows

    def enroll_user_2fa(self, username, role="empleado", requires_2fa=True):
        uname = self._normalize_username(username)
        if not uname:
            return False, "username vacio", None
        secret = self._generate_new_totp_secret() if requires_2fa else None
        ok, msg, record = self._upsert_user_security(
            uname,
            role=role,
            active=True,
            requires_2fa=bool(requires_2fa),
            totp_secret=secret,
        )
        if not ok:
            return False, msg, None
        otpauth_uri = None
        if requires_2fa and secret:
            otpauth_uri = self._totp_otpauth_uri_for(uname, secret)
        self._record_security_event("usuario_enrolado", "ok", f"Usuario {uname} enrolado", {"role": role, "requires_2fa": requires_2fa})
        return True, "ok", {
            "username": record["username"],
            "role": record["role"],
            "active": record["active"],
            "requires_2fa": record["requires_2fa"],
            "otpauth_uri": otpauth_uri,
            "secret_masked": self._mask_secret(secret or ""),
        }

    def set_user_active(self, username, active):
        rec = self._get_user_security(username)
        if not rec:
            return False, "usuario no existe"
        ok, msg, _ = self._upsert_user_security(
            username,
            role=rec.get("role", "empleado"),
            active=bool(active),
            requires_2fa=bool(rec.get("requires_2fa", True)),
            totp_secret=rec.get("totp_secret"),
        )
        return ok, msg

    def set_user_role(self, username, role):
        rec = self._get_user_security(username)
        if not rec:
            return False, "usuario no existe"
        ok, msg, _ = self._upsert_user_security(
            username,
            role=role,
            active=bool(rec.get("active", True)),
            requires_2fa=bool(rec.get("requires_2fa", True)),
            totp_secret=rec.get("totp_secret"),
        )
        return ok, msg

    def rotate_user_2fa(self, username):
        rec = self._get_user_security(username)
        if not rec:
            return False, "usuario no existe", None
        secret = self._generate_new_totp_secret()
        ok, msg, updated = self._upsert_user_security(
            username,
            role=rec.get("role", "empleado"),
            active=bool(rec.get("active", True)),
            requires_2fa=True,
            totp_secret=secret,
        )
        if not ok:
            return False, msg, None
        uri = self._totp_otpauth_uri_for(updated["username"], secret)
        return True, "ok", {"username": updated["username"], "otpauth_uri": uri, "secret_masked": self._mask_secret(secret)}

    def _iter_known_images(self):
        if KNOWN_FACES_DIR.exists() and KNOWN_FACES_DIR.is_dir():
            for person_dir in sorted([p for p in KNOWN_FACES_DIR.iterdir() if p.is_dir()]):
                person_name = person_dir.name.strip()
                if not person_name:
                    continue
                for ext in ("*.jpg", "*.jpeg", "*.png", "*.webp"):
                    for img_path in sorted(person_dir.glob(ext)):
                        if img_path.is_file():
                            yield person_name, img_path

        # Compatibilidad con versión previa: mantiene foto única.
        if FOTO_REFERENCIA.exists() and FOTO_REFERENCIA.is_file():
            yield PERSONA_AUTORIZADA, FOTO_REFERENCIA

    def _reload_face_database(self, log=True):
        new_encodings = []
        new_names = []
        folder_names = set()
        errores = 0

        KNOWN_FACES_DIR.mkdir(parents=True, exist_ok=True)

        if KNOWN_FACES_DIR.exists() and KNOWN_FACES_DIR.is_dir():
            folder_names = {
                p.name.strip()
                for p in KNOWN_FACES_DIR.iterdir()
                if p.is_dir() and p.name.strip()
            }

        for person_name, img_path in self._iter_known_images():
            try:
                with self.face_ops_lock:
                    image = face_recognition.load_image_file(str(img_path))
                    encodings = face_recognition.face_encodings(image)
                if not encodings:
                    errores += 1
                    if log:
                        self._add_log(
                            f"Sin rostro detectable en: {img_path.name} ({person_name})",
                            "warn",
                        )
                    continue
                # Solo 1 rostro por imagen para mantener rendimiento estable.
                new_encodings.append(encodings[0])
                new_names.append(person_name)
            except Exception as exc:
                errores += 1
                if log:
                    self._add_log(f"Error cargando {img_path.name}: {exc}", "err")

        if not new_encodings:
            raise RuntimeError(
                "No hay caras válidas. Agrega fotos en "
                "data/known_faces/<persona>/*.jpg o data/foto_referencia.png."
            )

        with self.lock:
            self.known_encodings = new_encodings
            self.known_names = new_names
            self.users = sorted(set(new_names) | folder_names)
            self.historial_distancias.clear()
            self.historial_nombres.clear()
            self.estado_autorizado_estable = False
            self.nombre_autorizado_estable = None

        if log:
            self._add_log(
                f"Base biometrica recargada: {len(new_encodings)} encodings / "
                f"{len(set(new_names))} identidades ({errores} omitidas).",
                "ok",
            )

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

    def _init_db(self):
        for _ in range(8):
            try:
                with psycopg2.connect(DB_URL) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS access_logs (
                                id BIGSERIAL PRIMARY KEY,
                                fecha_hora TIMESTAMP NOT NULL DEFAULT NOW(),
                                evento VARCHAR(64) NOT NULL,
                                persona VARCHAR(128) NOT NULL,
                                distancia DOUBLE PRECISION
                            )
                            """
                        )
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS metricas_raw (
                                id BIGSERIAL PRIMARY KEY,
                                fecha_hora TIMESTAMP NOT NULL DEFAULT NOW(),
                                metrica VARCHAR(64) NOT NULL,
                                valor DOUBLE PRECISION,
                                unidad VARCHAR(32),
                                etiquetas JSONB NOT NULL DEFAULT '{}'::jsonb,
                                origen VARCHAR(64) NOT NULL DEFAULT 'face-service'
                            )
                            """
                        )
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS metricas_clean (
                                id BIGSERIAL PRIMARY KEY,
                                fecha_hora TIMESTAMP NOT NULL,
                                metrica VARCHAR(64) NOT NULL,
                                valor DOUBLE PRECISION,
                                unidad VARCHAR(32),
                                dimension_1 VARCHAR(64),
                                dimension_2 VARCHAR(64),
                                notas TEXT
                            )
                            """
                        )
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS users_security (
                                username VARCHAR(128) PRIMARY KEY,
                                role VARCHAR(32) NOT NULL DEFAULT 'empleado',
                                active BOOLEAN NOT NULL DEFAULT TRUE,
                                requires_2fa BOOLEAN NOT NULL DEFAULT TRUE,
                                totp_secret VARCHAR(128),
                                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                            )
                            """
                        )
                    conn.commit()
                self.db_connected = True
                self._add_log("PostgreSQL conectado (logs y metricas listos).", "ok")
                self._load_users_security_from_db()
                return
            except Exception as exc:
                self.db_connected = False
                ultimo_error = str(exc)
                time.sleep(1.5)
        self._add_log(f"PostgreSQL no disponible, usando solo CSV. ({ultimo_error})", "warn")

    def _registrar_evento_db(self, evento, persona, distancia=None):
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO access_logs (evento, persona, distancia)
                        VALUES (%s, %s, %s)
                        """,
                        (evento, persona, distancia),
                    )
                conn.commit()
            self.db_connected = True
        except Exception:
            self.db_connected = False
            self._add_log("No se pudo escribir en PostgreSQL (se mantiene CSV).", "warn")

    def _registrar_evento(self, evento, persona, distancia=None):
        self._registrar_evento_csv(evento, persona, distancia)
        self._registrar_evento_db(evento, persona, distancia)

    def _registrar_metrica_raw_db(self, metrica, valor=None, unidad=None, etiquetas=None):
        payload_etiquetas = etiquetas or {}
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO metricas_raw (metrica, valor, unidad, etiquetas, origen)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (metrica, valor, unidad, Json(payload_etiquetas), "face-service"),
                    )
                conn.commit()
            self.db_connected = True
            clean = self._normalizar_metrica_clean(
                metrica=metrica,
                valor=valor,
                unidad=unidad,
                etiquetas=payload_etiquetas,
            )
            self._registrar_metrica_clean_db(
                metrica=clean["metrica"],
                valor=clean["valor"],
                unidad=clean["unidad"],
                etiquetas=clean["etiquetas"],
            )
        except Exception:
            self.db_connected = False

    def _normalizar_metrica_clean(self, *, metrica, valor=None, unidad=None, etiquetas=None):
        etiquetas_in = etiquetas or {}
        persona = str(etiquetas_in.get("persona") or "").strip()
        evento = str(etiquetas_in.get("evento") or "").strip().upper()
        desconocido = persona.lower() in {"", "desconocido", "unknown", "id_desconocida"}

        mapa_metricas = {
            "intento_acceso_total": ("acceso_intento", "conteo"),
            "acceso_concedido": ("acceso_concedido", "conteo"),
            "acceso_denegado": ("acceso_denegado", "conteo"),
            "distancia_facial": ("biometria_distancia_facial", "distancia"),
            "confianza_biometrica": ("biometria_confianza", "porcentaje"),
            "latencia_reconocimiento": ("rendimiento_latencia_reconocimiento", "ms"),
        }
        metrica_clean, unidad_default = mapa_metricas.get(metrica, (metrica, unidad or "sin_unidad"))

        valor_clean = valor
        try:
            if valor is not None:
                valor_clean = round(float(valor), 4)
        except Exception:
            valor_clean = None

        if unidad_default == "conteo":
            valor_clean = 1.0

        etiquetas_clean = {
            "evento": evento or "SIN_EVENTO",
            "persona": persona or "Desconocido",
            "persona_normalizada": re.sub(r"\s+", "_", (persona or "Desconocido").strip().lower()),
            "es_desconocido": bool(desconocido),
            "metrica_origen": metrica,
        }

        for key, raw_val in etiquetas_in.items():
            if key in etiquetas_clean:
                continue
            etiquetas_clean[key] = raw_val

        return {
            "metrica": metrica_clean,
            "valor": valor_clean,
            "unidad": unidad_default,
            "etiquetas": etiquetas_clean,
        }

    def _registrar_metrica_clean_db(self, metrica, valor=None, unidad=None, etiquetas=None):
        payload_etiquetas = etiquetas or {}
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO metricas_clean (metrica, valor, unidad, etiquetas, origen)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (metrica, valor, unidad, Json(payload_etiquetas), "face-service"),
                    )
                conn.commit()
            self.db_connected = True
        except Exception:
            self.db_connected = False

    def _registrar_metricas_reconocimiento(self, *, evento, persona, distancia=None, confidence=None):
        etiquetas_base = {"evento": evento, "persona": persona}
        self._registrar_metrica_raw_db(
            "intento_acceso_total",
            valor=1.0,
            unidad="conteo",
            etiquetas=etiquetas_base,
        )
        self._registrar_metrica_raw_db(
            "acceso_concedido" if evento == "ACCESO_CONCEDIDO" else "acceso_denegado",
            valor=1.0,
            unidad="conteo",
            etiquetas=etiquetas_base,
        )
        if distancia is not None:
            self._registrar_metrica_raw_db(
                "distancia_facial",
                valor=float(distancia),
                unidad="distancia",
                etiquetas=etiquetas_base,
            )
        if confidence is not None:
            self._registrar_metrica_raw_db(
                "confianza_biometrica",
                valor=float(confidence),
                unidad="porcentaje",
                etiquetas=etiquetas_base,
            )
        if self.scan_started_at is not None:
            latencia_ms = max(0.0, (time.time() - self.scan_started_at) * 1000.0)
            self._registrar_metrica_raw_db(
                "latencia_reconocimiento",
                valor=latencia_ms,
                unidad="ms",
                etiquetas=etiquetas_base,
            )

    def _finalize_access_granted(self, user, distancia):
        user_sec = self._get_user_security(user) or {}
        self.system_open = True
        self.two_fa_pending = False
        self.two_fa_user = None
        self.state = "detected"
        self.current_user = user
        self.current_role = user_sec.get("role", "empleado")
        self.distance = distancia
        self.confidence = max(0.0, min(100.0, (1.0 - distancia) * 100)) if distancia is not None else None
        self._set_device_state(f"Bienvenido, {self.current_user}!", led_on=True, force_send=True)
        self._registrar_evento("ACCESO_CONCEDIDO", self.current_user, distancia)
        self._registrar_metricas_reconocimiento(
            evento="ACCESO_CONCEDIDO",
            persona=self.current_user,
            distancia=distancia,
            confidence=self.confidence,
        )
        self._record_security_event(
            "acceso_concedido",
            "ok",
            f"Acceso concedido a {self.current_user}",
            {"distance": distancia, "confidence": self.confidence},
        )
        self._notify_n8n(
            "acceso_concedido",
            {
                "persona": self.current_user,
                "distance": distancia,
                "confidence": self.confidence,
            },
        )
        self._add_log(f"Rostro reconocido: {self.current_user} ({self.confidence:.1f}%)", "ok")
        try:
            webbrowser.open(PLEX_URL)
            self._add_log(f"Jellyfin/CasaOS abierto: {PLEX_URL}", "ok")
        except Exception as exc:
            self._add_log(f"No se pudo abrir Jellyfin/CasaOS: {exc}", "err")

    def verify_second_factor(self, code):
        with self.lock:
            if not self.two_fa_enabled:
                return False, "2FA desactivado"
            if not self.two_fa_pending:
                return False, "No hay verificacion 2FA pendiente"
            now = time.time()
            if now > self.two_fa_expires_at:
                self.two_fa_pending = False
                self.two_fa_user = None
                self.state = "scanning"
                return False, "Codigo expirado. Escanea nuevamente."
            if now < self.security_lock_until:
                return False, f"Sistema bloqueado por seguridad hasta {datetime.fromtimestamp(self.security_lock_until).strftime('%H:%M:%S')}"

            user_sec = self._get_user_security(self.two_fa_user) or {}
            if not user_sec.get("active", True):
                return False, "Usuario inactivo"
            user_secret = user_sec.get("totp_secret") or self.two_fa_secret

            if not self._verify_totp(code, secret=user_secret):
                self.two_fa_fail_count += 1
                self._register_failed_attempt()
                self._record_security_event("2fa_fallido", "warn", "Intento de 2FA invalido")
                self._notify_n8n("2fa_fallido", {"persona": self.two_fa_user, "fail_count": self.two_fa_fail_count})
                return False, "Codigo 2FA invalido"

            user = self.two_fa_user
            distancia = self.two_fa_distance
            self.two_fa_trusted_until = now + TWO_FA_TRUST_SECONDS
            self.two_fa_fail_count = 0
            self._record_security_event("2fa_exitoso", "ok", f"2FA valido para {user}")
            self._notify_n8n("2fa_exitoso", {"persona": user})
            self._finalize_access_granted(user, distancia)
            return True, "2FA verificado. Acceso concedido."

    def _add_log(self, msg, log_type="info"):
        now = datetime.now().strftime("%H:%M:%S")
        self.logs.appendleft({"time": now, "msg": msg, "type": log_type})

    def _set_device_state(self, text, led_on=False, force_send=False):
        self.arduino_text = text
        self.led_on = led_on

        if not force_send and self.last_device_message == text:
            return

        ok, info = self.device_client.notify(text=text, led_on=led_on, force=force_send)
        if ok:
            self.last_device_message = text
            self._add_log(f"[DEVICE] {text} ({info})", "warn")
        else:
            self._add_log(f"[DEVICE-OFF] {text} ({info})", "warn")

    def start_scan(self):
        with self.lock:
            self.scan_active = True
            self.scan_started_at = time.time()
            self.state = "scanning"
            self.system_open = False
            self.current_user = None
            self.current_role = None
            self.two_fa_pending = False
            self.two_fa_user = None
            self.progress = 0
            self.confidence = None
            self.distance = None
            self.unknown_seconds = 0.0
            self.frames_consecutivos_autorizados = 0
            self.inicio_desconocido = None
            self.historial_distancias.clear()
            self.historial_nombres.clear()
            self.estado_autorizado_estable = False
            self.nombre_autorizado_estable = None
            self.last_device_message = None
            self.cached_face_landmarks = []
            self.last_detected_people = []
            self.liveness_ok = not self.liveness_enabled
            self.liveness_direction = "derecha" if secrets.randbelow(2) == 0 else "izquierda"
            self.liveness_baseline_x = None
            self._set_device_state("Esperando...", led_on=False, force_send=True)
            self._add_log("Camara iniciada. Buscando rostros...", "info")

    def reset(self):
        with self.lock:
            self.scan_active = False
            self.scan_started_at = None
            self.system_open = False
            self.state = "idle"
            self.current_user = None
            self.current_role = None
            self.two_fa_pending = False
            self.two_fa_user = None
            self.progress = 0
            self.confidence = None
            self.distance = None
            self.unknown_seconds = 0.0
            self.frames_consecutivos_autorizados = 0
            self.inicio_desconocido = None
            self.historial_distancias.clear()
            self.historial_nombres.clear()
            self.estado_autorizado_estable = False
            self.nombre_autorizado_estable = None
            self.last_device_message = None
            self.cached_face_landmarks = []
            self.last_detected_people = []
            self.liveness_ok = not self.liveness_enabled
            self.liveness_baseline_x = None
            self._set_device_state("Esperando...", led_on=False, force_send=True)
            self._add_log("Sistema reseteado.", "info")

    def set_mesh_enabled(self, enabled):
        with self.lock:
            self.user_mesh_enabled = bool(enabled)
            self.enable_face_mesh = bool(enabled) if self.perf_mode == "normal" else False
            if not self.enable_face_mesh:
                self.cached_face_landmarks = []
            self._add_log(
                f"Malla facial {'activada' if self.user_mesh_enabled else 'desactivada'}.",
                "info",
            )

    def set_auto_performance(self, enabled):
        with self.lock:
            self.auto_performance = bool(enabled)
            if not self.auto_performance:
                self._set_performance_mode("normal")
            self._add_log(
                f"Auto rendimiento {'activado' if self.auto_performance else 'desactivado'}.",
                "info",
            )

    def set_performance_mode(self, mode):
        with self.lock:
            self._set_performance_mode("ahorro" if mode == "ahorro" else "normal")

    def add_user(self, name):
        cleaned = name.strip()
        if not cleaned:
            return False, "Nombre vacio"
        with self.lock:
            if cleaned in self.users:
                return False, "Usuario ya existe"
        user_dir = KNOWN_FACES_DIR / cleaned
        user_dir.mkdir(parents=True, exist_ok=True)
        try:
            user_dir.chmod(0o777)
        except Exception:
            pass
        self._add_log(
            f"Carpeta creada para {cleaned}: {user_dir}. Agrega fotos y recarga base.",
            "ok",
        )
        try:
            self._reload_face_database(log=True)
        except RuntimeError:
            # Si aún no hay fotos válidas de ese usuario, mantenemos el alta de carpeta.
            with self.lock:
                if cleaned not in self.users:
                    self.users.append(cleaned)
        if not self._get_user_security(cleaned):
            self.enroll_user_2fa(cleaned, role="empleado", requires_2fa=self.two_fa_enabled)
        return True, "ok"

    def remove_user(self, name):
        with self.lock:
            if name not in self.users:
                return False
        user_dir = KNOWN_FACES_DIR / name
        if user_dir.exists() and user_dir.is_dir():
            shutil.rmtree(user_dir, ignore_errors=True)
        self._add_log(f"Usuario eliminado: {name}", "warn")
        try:
            self._reload_face_database(log=True)
        except RuntimeError:
            with self.lock:
                self.users = []
                self.known_encodings = []
                self.known_names = []
            self._add_log("Sin identidades biométricas válidas tras eliminar usuario.", "warn")
        sec = self._get_user_security(name)
        if sec:
            self.set_user_active(name, False)
        return True

    def request_reload_faces(self, timeout_seconds=15.0):
        now = time.time()
        with self.lock:
            if (now - self.last_reload_request_ts) < 5.0:
                return {"ok": False, "error": "Espera 5 segundos antes de recargar de nuevo"}
            self.last_reload_request_ts = now
            self.reload_faces_requested = True
            self.reload_faces_event.clear()

        done = self.reload_faces_event.wait(timeout=timeout_seconds)
        if not done:
            return {"ok": False, "error": "Timeout recargando base biometrica"}
        with self.lock:
            return dict(self.last_reload_result)

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

    def _draw_face_mesh_overlay(self, frame, landmarks, scale_factor):
        color_line = (255, 220, 120)
        color_point = (255, 255, 255)

        def scaled(points):
            return [(int(x * scale_factor), int(y * scale_factor)) for (x, y) in points]

        for feature_points in landmarks.values():
            pts = scaled(feature_points)
            if len(pts) < 2:
                continue
            for i in range(len(pts) - 1):
                cv2.line(frame, pts[i], pts[i + 1], color_line, 1, cv2.LINE_AA)
            for p in pts:
                cv2.circle(frame, p, 2, color_point, -1, cv2.LINE_AA)

        # Conexiones extras para estilo "mesh" entre rasgos clave.
        if "nose_tip" in landmarks and "chin" in landmarks:
            nose = scaled(landmarks["nose_tip"])
            chin = scaled(landmarks["chin"])
            if nose and len(chin) > 8:
                cv2.line(frame, nose[len(nose) // 2], chin[len(chin) // 2], color_line, 1, cv2.LINE_AA)

        if "left_eye" in landmarks and "right_eye" in landmarks and "nose_tip" in landmarks:
            left_eye = scaled(landmarks["left_eye"])
            right_eye = scaled(landmarks["right_eye"])
            nose = scaled(landmarks["nose_tip"])
            if left_eye and right_eye and nose:
                left_center = left_eye[len(left_eye) // 2]
                right_center = right_eye[len(right_eye) // 2]
                nose_center = nose[len(nose) // 2]
                cv2.line(frame, left_center, nose_center, color_line, 1, cv2.LINE_AA)
                cv2.line(frame, right_center, nose_center, color_line, 1, cv2.LINE_AA)
                cv2.line(frame, left_center, right_center, color_line, 1, cv2.LINE_AA)

    def _ensure_camera_open(self):
        if self.video_capture is None:
            self.video_capture = cv2.VideoCapture(0)
        elif not self.video_capture.isOpened():
            self.video_capture.open(0)

        is_open = self.video_capture.isOpened()
        if is_open and not self.camera_is_open:
            self.video_capture.set(cv2.CAP_PROP_FRAME_WIDTH, CAMERA_WIDTH)
            self.video_capture.set(cv2.CAP_PROP_FRAME_HEIGHT, CAMERA_HEIGHT)
            self.video_capture.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.camera_is_open = True
            self._add_log("Camara activada.", "info")
        return is_open

    def _set_performance_mode(self, mode):
        desired = "ahorro" if mode == "ahorro" else "normal"
        if desired == self.perf_mode:
            return
        self.perf_mode = desired
        if desired == "ahorro":
            self.current_frame_scale = min(self.current_frame_scale, HIGH_LOAD_FRAME_SCALE)
            self.current_process_every_n_frames = max(
                self.current_process_every_n_frames, HIGH_LOAD_PROCESS_EVERY_N_FRAMES
            )
            self.current_landmark_every_n_frames = max(self.current_landmark_every_n_frames, 5)
            self.enable_face_mesh = False
            self.cached_face_landmarks = []
            self._add_log("Modo ahorro activado (CPU alta).", "warn")
        else:
            self.current_frame_scale = FRAME_SCALE
            self.current_process_every_n_frames = PROCESS_EVERY_N_FRAMES
            self.current_landmark_every_n_frames = LANDMARK_EVERY_N_FRAMES
            self.enable_face_mesh = self.user_mesh_enabled
            self._add_log("Modo rendimiento normal restaurado.", "ok")

    def _auto_tune_performance(self):
        if not self.auto_performance:
            return
        if self.fps and self.fps < TARGET_FPS_MIN:
            self._set_performance_mode("ahorro")
        elif self.fps and self.fps >= (TARGET_FPS_MIN + 4.0):
            self._set_performance_mode("normal")

    def _release_camera(self):
        if self.video_capture is not None and self.video_capture.isOpened():
            self.video_capture.release()
        if self.camera_is_open:
            self.camera_is_open = False
            self._add_log("Camara en espera (sin clientes).", "info")
        self.frame_jpeg = None

    def _loop(self):
        last_fps_ts = time.time()
        frames_count = 0

        while self.running:
            do_reload = False
            with self.lock:
                if self.reload_faces_requested:
                    self.reload_faces_requested = False
                    do_reload = True

            if do_reload:
                try:
                    with self.lock:
                        self.scan_active = False
                        self.scan_started_at = None
                        self.system_open = False
                        self.state = "idle"
                        self.current_user = None
                        self.progress = 0
                        self.confidence = None
                        self.distance = None
                        self.frames_consecutivos_autorizados = 0
                        self.historial_distancias.clear()
                        self.historial_nombres.clear()
                        self.cached_face_locations = []
                        self.cached_face_encodings = []
                        self.cached_face_landmarks = []
                    self._release_camera()
                    time.sleep(0.25)
                    self._reload_face_database(log=True)
                    with self.lock:
                        self.last_reload_result = {
                            "ok": True,
                            "encodings": len(self.known_encodings),
                            "identidades": len(set(self.known_names)),
                        }
                except RuntimeError as exc:
                    with self.lock:
                        self.last_reload_result = {"ok": False, "error": str(exc)}
                finally:
                    self.reload_faces_event.set()

            now = time.time()
            with self.lock:
                scan_active = self.scan_active
                stream_clients = self.active_stream_clients
                last_stream_ts = self.last_stream_activity_ts

            keep_camera_on = (
                scan_active
                or stream_clients > 0
                or (now - last_stream_ts) <= CAMERA_IDLE_RELEASE_SECONDS
            )

            if not keep_camera_on:
                self._release_camera()
                time.sleep(0.15)
                continue

            if not self._ensure_camera_open():
                time.sleep(0.2)
                continue

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
                self._auto_tune_performance()

            self.resolution = f"{frame.shape[1]}x{frame.shape[0]}"

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

        self._release_camera()

    def _process_frame(self, frame):
        with self.lock:
            known_encodings = list(self.known_encodings)
            known_names = list(self.known_names)
            frame_scale = self.current_frame_scale
            process_every = self.current_process_every_n_frames
            landmark_every = self.current_landmark_every_n_frames
            two_fa_pending = self.two_fa_pending
            two_fa_user = self.two_fa_user
            two_fa_expires_at = self.two_fa_expires_at

        if two_fa_pending:
            ttl = max(0, int(two_fa_expires_at - time.time()))
            if ttl <= 0:
                with self.lock:
                    self.two_fa_pending = False
                    self.two_fa_user = None
                    if not self.system_open:
                        self.state = "scanning"
                cv2.putText(
                    frame,
                    "2FA expiro. Escanea nuevamente.",
                    (12, 30),
                    cv2.FONT_HERSHEY_DUPLEX,
                    0.75,
                    (0, 0, 255),
                    2,
                )
                return frame

            with self.lock:
                self.state = "awaiting_2fa"
                self.current_user = two_fa_user
            cv2.putText(
                frame,
                f"2FA pendiente para {two_fa_user} ({ttl}s)",
                (12, 30),
                cv2.FONT_HERSHEY_DUPLEX,
                0.75,
                (0, 165, 255),
                2,
            )
            cv2.putText(
                frame,
                "Ingrese el codigo TOTP en el panel",
                (12, 58),
                cv2.FONT_HERSHEY_DUPLEX,
                0.6,
                (230, 230, 230),
                1,
            )
            return frame

        if not known_encodings:
            cv2.putText(
                frame,
                "Sin base biometrica. Agrega fotos en data/known_faces/<persona>/",
                (12, 30),
                cv2.FONT_HERSHEY_DUPLEX,
                0.6,
                (0, 0, 255),
                2,
            )
            return frame

        self.frame_index += 1
        scale_factor = 1.0 / frame_scale

        should_process = (
            self.frame_index % max(1, process_every) == 0
            or not self.cached_face_locations
        )

        if should_process:
            small_frame = cv2.resize(frame, (0, 0), fx=frame_scale, fy=frame_scale)
            rgb_small_frame = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)
            gray_small = cv2.cvtColor(small_frame, cv2.COLOR_BGR2GRAY)
            blur_score = float(cv2.Laplacian(gray_small, cv2.CV_64F).var())
            luma_score = float(gray_small.mean())
            quality_ok = blur_score >= BLUR_THRESHOLD and luma_score >= LOW_LIGHT_THRESHOLD
            self.last_quality_info = {
                "blur": round(blur_score, 1),
                "luma": round(luma_score, 1),
                "quality_ok": quality_ok,
            }

            if quality_ok:
                with self.face_ops_lock:
                    face_locations = face_recognition.face_locations(rgb_small_frame)
                face_locations = [
                    loc
                    for loc in face_locations
                    if (loc[1] - loc[3]) >= MIN_FACE_SIZE_PX and (loc[2] - loc[0]) >= MIN_FACE_SIZE_PX
                ][: max(1, MAX_FACES_PER_FRAME)]
                with self.face_ops_lock:
                    face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)
            else:
                face_locations = []
                face_encodings = []
            self.cached_face_locations = face_locations
            self.cached_face_encodings = face_encodings

            if self.enable_face_mesh and (
                self.frame_index % max(1, landmark_every) == 0 or not self.cached_face_landmarks
            ):
                with self.face_ops_lock:
                    self.cached_face_landmarks = face_recognition.face_landmarks(rgb_small_frame, face_locations)
        else:
            face_locations = self.cached_face_locations
            face_encodings = self.cached_face_encodings

        face_landmarks_list = self.cached_face_landmarks if self.enable_face_mesh else []

        rostro_autorizado_en_frame = False
        rostro_desconocido_en_frame = False
        mejor_distancia_autorizada = None
        mejor_distancia_frame = None
        mejor_nombre_frame = None
        idx_cara_objetivo = None
        face_results = []
        detected_people = []

        for idx, face_encoding in enumerate(face_encodings):
            with self.face_ops_lock:
                distances = face_recognition.face_distance(known_encodings, face_encoding)
            if len(distances) == 0:
                continue
            best_local_idx = min(range(len(distances)), key=lambda i: distances[i])
            distancia = float(distances[best_local_idx])
            nombre = known_names[best_local_idx]
            reconocido = distancia <= UMBRAL_ENTRADA_AUTORIZADO
            label = nombre if reconocido else "Desconocido"
            face_results.append(
                {
                    "idx": idx,
                    "distancia": distancia,
                    "nombre": nombre,
                    "reconocido": reconocido,
                    "label": label,
                }
            )
            detected_people.append(label)
            if mejor_distancia_frame is None or distancia < mejor_distancia_frame:
                mejor_distancia_frame = distancia
                mejor_nombre_frame = nombre
                idx_cara_objetivo = idx

        if mejor_distancia_frame is not None:
            self.historial_distancias.append(mejor_distancia_frame)
            self.historial_nombres.append(mejor_nombre_frame)
            distancia_suavizada = sum(self.historial_distancias) / len(self.historial_distancias)
            nombre_suavizado, repeticiones = Counter(self.historial_nombres).most_common(1)[0]
            min_repeticiones = max(2, len(self.historial_nombres) // 2)
            if (
                self.estado_autorizado_estable
                and self.nombre_autorizado_estable == nombre_suavizado
            ):
                self.estado_autorizado_estable = distancia_suavizada <= UMBRAL_SALIDA_AUTORIZADO
            else:
                self.estado_autorizado_estable = (
                    distancia_suavizada <= UMBRAL_ENTRADA_AUTORIZADO
                    and repeticiones >= min_repeticiones
                )
            if self.estado_autorizado_estable:
                self.nombre_autorizado_estable = nombre_suavizado
            else:
                self.nombre_autorizado_estable = None
        else:
            self.historial_distancias.clear()
            self.historial_nombres.clear()
            self.estado_autorizado_estable = False
            self.nombre_autorizado_estable = None
            distancia_suavizada = None

        self.last_detected_people = sorted(set(detected_people))

        for item in face_results:
            if item["reconocido"]:
                rostro_autorizado_en_frame = True
                if mejor_distancia_autorizada is None or item["distancia"] < mejor_distancia_autorizada:
                    mejor_distancia_autorizada = item["distancia"]
            else:
                rostro_desconocido_en_frame = True

        for idx, (top, right, bottom, left) in enumerate(face_locations):
            result = next((r for r in face_results if r["idx"] == idx), None)
            if result is None:
                continue
            nombre = result["label"]
            if idx == idx_cara_objetivo and self.estado_autorizado_estable and self.nombre_autorizado_estable:
                nombre = self.nombre_autorizado_estable
                color_caja = (0, 255, 0)
            else:
                color_caja = (0, 255, 0) if result["reconocido"] else (0, 0, 255)
            top = int(top * scale_factor)
            right = int(right * scale_factor)
            bottom = int(bottom * scale_factor)
            left = int(left * scale_factor)

            cv2.rectangle(frame, (left, top), (right, bottom), color_caja, 2)
            cv2.rectangle(frame, (left, bottom - 35), (right, bottom), color_caja, cv2.FILLED)
            cv2.putText(frame, nombre, (left + 6, bottom - 8), cv2.FONT_HERSHEY_DUPLEX, 0.7, (0, 0, 0), 1)

            if self.enable_face_mesh and idx < len(face_landmarks_list):
                self._draw_face_mesh_overlay(frame, face_landmarks_list[idx], scale_factor=scale_factor)

        if self.liveness_enabled and idx_cara_objetivo is not None and idx_cara_objetivo < len(face_locations):
            top, right, bottom, left = face_locations[idx_cara_objetivo]
            center_x = (left + right) / 2.0
            if self.liveness_baseline_x is None:
                self.liveness_baseline_x = center_x
            delta_x = center_x - self.liveness_baseline_x
            if self.liveness_direction == "derecha" and delta_x >= LIVENESS_DELTA_PX:
                self.liveness_ok = True
            elif self.liveness_direction == "izquierda" and delta_x <= -LIVENESS_DELTA_PX:
                self.liveness_ok = True

        if rostro_autorizado_en_frame:
            self.frames_consecutivos_autorizados = min(
                self.frames_consecutivos_autorizados + 1, FRAMES_CONSECUTIVOS_REQUERIDOS
            )
            self.inicio_desconocido = None
        else:
            self.frames_consecutivos_autorizados = 0

        self.progress = int((self.frames_consecutivos_autorizados / FRAMES_CONSECUTIVOS_REQUERIDOS) * 100)
        ahora = time.time()
        security_locked = ahora < self.security_lock_until

        if (
            not self.system_open
            and self.frames_consecutivos_autorizados >= FRAMES_CONSECUTIVOS_REQUERIDOS
            and mejor_distancia_autorizada is not None
            and self.nombre_autorizado_estable
            and self.liveness_ok
        ):
            user_sec = self._get_user_security(self.nombre_autorizado_estable) or {
                "active": True,
                "requires_2fa": self.two_fa_enabled,
                "role": "empleado",
            }
            if not user_sec.get("active", True):
                self.state = "denied"
                self.current_user = None
                self.current_role = None
                self._set_device_state("Usuario inactivo", led_on=True)
                self._add_log(f"Intento bloqueado: usuario inactivo ({self.nombre_autorizado_estable})", "err")
                self._record_security_event(
                    "acceso_bloqueado_usuario_inactivo",
                    "crit",
                    f"Usuario inactivo intento acceso: {self.nombre_autorizado_estable}",
                )
                return frame
            if security_locked:
                self.state = "denied"
                self.current_user = None
                self.current_role = None
                self._set_device_state("Bloqueo temporal activo", led_on=True)
            elif user_sec.get("requires_2fa", self.two_fa_enabled) and ahora > self.two_fa_trusted_until:
                self.two_fa_pending = True
                self.two_fa_user = self.nombre_autorizado_estable
                self.two_fa_distance = mejor_distancia_autorizada
                self.two_fa_confidence = max(0.0, min(100.0, (1.0 - mejor_distancia_autorizada) * 100))
                self.two_fa_expires_at = ahora + TWO_FA_GRACE_SECONDS
                self.state = "awaiting_2fa"
                self.current_user = self.two_fa_user
                self.current_role = user_sec.get("role", "empleado")
                self.distance = self.two_fa_distance
                self.confidence = self.two_fa_confidence
                self._set_device_state("Confirma 2FA en celular", led_on=True, force_send=True)
                self._add_log(f"Rostro validado. 2FA requerido para {self.two_fa_user}.", "warn")
                self._record_security_event(
                    "2fa_requerido",
                    "warn",
                    f"2FA requerido para {self.two_fa_user}",
                    {"expires_in": TWO_FA_GRACE_SECONDS},
                )
                self._notify_n8n("2fa_requerido", {"persona": self.two_fa_user})
            else:
                self._finalize_access_granted(self.nombre_autorizado_estable, mejor_distancia_autorizada)

        if rostro_desconocido_en_frame and not rostro_autorizado_en_frame:
            if self.inicio_desconocido is None:
                self.inicio_desconocido = ahora
            self.unknown_seconds = ahora - self.inicio_desconocido

            if (
                self.unknown_seconds >= SEGUNDOS_INTRUSO
                and (ahora - self.ultima_captura_intruso) >= COOLDOWN_CAPTURA_INTRUSO
            ):
                ruta_intruso = self._guardar_intruso(frame)
                self._registrar_evento("ACCESO_DENEGADO", "Desconocido")
                self._registrar_metricas_reconocimiento(
                    evento="ACCESO_DENEGADO",
                    persona="Desconocido",
                    distancia=distancia_suavizada,
                    confidence=max(0.0, min(100.0, (1.0 - distancia_suavizada) * 100))
                    if distancia_suavizada is not None
                    else None,
                )
                self._record_security_event(
                    "intruso_detectado",
                    "crit",
                    f"Intruso detectado: {ruta_intruso.name}",
                    {"archivo": ruta_intruso.name},
                )
                self._notify_n8n("intruso_detectado", {"archivo": ruta_intruso.name})
                self._add_log(f"Intruso detectado. Captura guardada: {ruta_intruso.name}", "err")
                self.ultima_captura_intruso = ahora
                self._register_failed_attempt()

            if not self.system_open:
                self.state = "denied"
                self.current_user = None
                self.current_role = None
                self._set_device_state("Acceso Denegado!", led_on=True)
        elif not rostro_autorizado_en_frame:
            self.inicio_desconocido = None
            self.unknown_seconds = 0.0
            if not self.system_open:
                self.state = "scanning"
                self._set_device_state("Esperando...", led_on=False)

        if security_locked:
            texto_estado = f"BLOQUEO TEMPORAL: {int(self.security_lock_until - ahora)}s"
            color_estado = (0, 0, 255)
        elif rostro_autorizado_en_frame and not self.liveness_ok and self.liveness_enabled:
            texto_estado = f"Prueba de vida: gire cabeza a la {self.liveness_direction}"
            color_estado = (0, 165, 255)
        elif self.state == "awaiting_2fa" and self.two_fa_pending:
            ttl = max(0, int(self.two_fa_expires_at - ahora))
            texto_estado = f"2FA PENDIENTE: confirma codigo ({ttl}s)"
            color_estado = (0, 165, 255)
        elif self.system_open:
            texto_estado = "Estado: ACCESO CONCEDIDO"
            color_estado = (0, 255, 0)
        elif rostro_autorizado_en_frame:
            self.state = "scanning"
            self.current_user = self.nombre_autorizado_estable
            user_sec = self._get_user_security(self.current_user) or {}
            self.current_role = user_sec.get("role", "empleado")
            self.distance = distancia_suavizada
            if distancia_suavizada is not None:
                self.confidence = max(0.0, min(100.0, (1.0 - distancia_suavizada) * 100))
            texto_estado = f"Analizando biometria: {self.progress}%"
            color_estado = (0, 255, 255)
        elif rostro_desconocido_en_frame:
            self.current_user = None
            self.current_role = None
            self.distance = distancia_suavizada
            if distancia_suavizada is not None:
                self.confidence = max(0.0, min(100.0, (1.0 - distancia_suavizada) * 100))
            texto_estado = f"Rostro desconocido: {self.unknown_seconds:.1f}s"
            color_estado = (0, 0, 255)
        else:
            self.current_user = None
            self.current_role = None
            self.distance = None
            self.confidence = None
            if not self.system_open:
                self.state = "scanning"
            texto_estado = "Buscando rostro..."
            color_estado = (255, 255, 255)

        cv2.putText(frame, texto_estado, (12, 30), cv2.FONT_HERSHEY_DUPLEX, 0.8, color_estado, 2)
        cv2.putText(
            frame,
            f"Modo: {self.perf_mode} | Rostros: {len(face_locations)}",
            (12, 58),
            cv2.FONT_HERSHEY_DUPLEX,
            0.55,
            (220, 220, 220),
            1,
        )
        quality = self.last_quality_info
        if quality.get("quality_ok") is False:
            cv2.putText(
                frame,
                "Calidad baja (luz/borroso). Acercate y mejora iluminacion.",
                (12, 84),
                cv2.FONT_HERSHEY_DUPLEX,
                0.55,
                (0, 165, 255),
                1,
            )
        return frame

    def _update_frame(self, frame):
        ok, buffer = cv2.imencode(
            ".jpg",
            frame,
            [int(cv2.IMWRITE_JPEG_QUALITY), max(40, min(95, JPEG_QUALITY))],
        )
        if ok:
            self.frame_jpeg = buffer.tobytes()

    def generate_stream(self):
        with self.lock:
            self.active_stream_clients += 1
            self.last_stream_activity_ts = time.time()
        try:
            while self.running:
                with self.lock:
                    self.last_stream_activity_ts = time.time()
                frame = self.frame_jpeg
                if frame is None:
                    time.sleep(0.05)
                    continue
                yield (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
                )
                time.sleep(0.03)
        finally:
            with self.lock:
                self.active_stream_clients = max(0, self.active_stream_clients - 1)
                self.last_stream_activity_ts = time.time()

    def get_status(self):
        ok, device = self.device_client.status()
        with self.lock:
            return {
                "scan_active": self.scan_active,
                "state": self.state,
                "progress": self.progress,
                "current_user": self.current_user,
                "current_role": self.current_role,
                "system_open": self.system_open,
                "confidence": round(self.confidence, 1) if self.confidence is not None else None,
                "distance": round(self.distance, 4) if self.distance is not None else None,
                "unknown_seconds": round(self.unknown_seconds, 1),
                "arduino_text": self.arduino_text,
                "led_on": self.led_on,
                "fps": round(self.fps, 1),
                "resolution": self.resolution,
                "users_count": len(self.users),
                "users_security_count": len(self.user_security),
                "device_service_url": DEVICE_SERVICE_URL,
                "arduino_port": device.get("port") if ok else None,
                "arduino_connected": bool(device.get("connected")) if ok else False,
                "plex_url": PLEX_URL,
                "db_connected": self.db_connected,
                "mesh_enabled": self.enable_face_mesh,
                "mesh_user_enabled": self.user_mesh_enabled,
                "camera_on": self.camera_is_open,
                "detected_people": list(self.last_detected_people),
                "perf_mode": self.perf_mode,
                "auto_performance": self.auto_performance,
                "frame_scale": round(self.current_frame_scale, 3),
                "process_every_n_frames": self.current_process_every_n_frames,
                "quality": dict(self.last_quality_info),
                "two_fa_enabled": self.two_fa_enabled,
                "two_fa_pending": self.two_fa_pending,
                "two_fa_user": self.two_fa_user,
                "two_fa_expires_in": max(0, int(self.two_fa_expires_at - time.time())) if self.two_fa_pending else 0,
                "security_locked": time.time() < self.security_lock_until,
                "security_lock_remaining": max(0, int(self.security_lock_until - time.time())),
                "liveness_enabled": self.liveness_enabled,
                "liveness_ok": self.liveness_ok,
                "liveness_direction": self.liveness_direction if self.liveness_enabled else None,
            }

    def get_logs(self, limit=100):
        with self.lock:
            return list(self.logs)[:limit]

    def get_users(self):
        with self.lock:
            return list(self.users)

    def get_reportes(self):
        reporte_base = {
            "db_connected": self.db_connected,
            "total": 0,
            "concedidos": 0,
            "denegados": 0,
            "hoy_concedidos": 0,
            "hoy_denegados": 0,
            "ultimas_24h": 0,
            "recent": [],
        }

        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            COUNT(*) AS total,
                            COUNT(*) FILTER (WHERE evento = 'ACCESO_CONCEDIDO') AS concedidos,
                            COUNT(*) FILTER (WHERE evento = 'ACCESO_DENEGADO') AS denegados,
                            COUNT(*) FILTER (
                                WHERE evento = 'ACCESO_CONCEDIDO'
                                AND fecha_hora::date = CURRENT_DATE
                            ) AS hoy_concedidos,
                            COUNT(*) FILTER (
                                WHERE evento = 'ACCESO_DENEGADO'
                                AND fecha_hora::date = CURRENT_DATE
                            ) AS hoy_denegados,
                            COUNT(*) FILTER (
                                WHERE fecha_hora >= NOW() - INTERVAL '24 hours'
                            ) AS ultimas_24h
                        FROM access_logs
                        """
                    )
                    row = cur.fetchone()
                    reporte_base.update(
                        {
                            "db_connected": True,
                            "total": int(row[0] or 0),
                            "concedidos": int(row[1] or 0),
                            "denegados": int(row[2] or 0),
                            "hoy_concedidos": int(row[3] or 0),
                            "hoy_denegados": int(row[4] or 0),
                            "ultimas_24h": int(row[5] or 0),
                        }
                    )

                    cur.execute(
                        """
                        SELECT fecha_hora, evento, persona, distancia
                        FROM access_logs
                        ORDER BY fecha_hora DESC
                        LIMIT 8
                        """
                    )
                    recent_rows = cur.fetchall()
                    reporte_base["recent"] = [
                        {
                            "fecha_hora": r[0].strftime("%Y-%m-%d %H:%M:%S"),
                            "evento": r[1],
                            "persona": r[2],
                            "distancia": round(float(r[3]), 4) if r[3] is not None else None,
                        }
                        for r in recent_rows
                    ]
            self.db_connected = True
        except Exception:
            self.db_connected = False
            reporte_base["db_connected"] = False

        return reporte_base

    @staticmethod
    def _parse_datetime_filter(value):
        if not value:
            return None
        raw = value.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def _fetch_metric_rows(self, table_name, from_dt=None, to_dt=None, metrica=None, limit=1000):
        rows = []
        filters = []
        params = []
        if from_dt is not None:
            filters.append("fecha_hora >= %s")
            params.append(from_dt)
        if to_dt is not None:
            filters.append("fecha_hora <= %s")
            params.append(to_dt)
        if metrica:
            filters.append("metrica = %s")
            params.append(metrica)
        where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
        query = (
            f"SELECT * FROM {table_name} "
            f"{where_sql} "
            "ORDER BY fecha_hora DESC "
            "LIMIT %s"
        )
        params.append(limit)
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(query, tuple(params))
                    columns = [desc[0] for desc in cur.description]
                    data = cur.fetchall()
            self.db_connected = True
            for row in data:
                record = {}
                for idx, col in enumerate(columns):
                    val = row[idx]
                    if isinstance(val, datetime):
                        record[col] = val.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        record[col] = val
                rows.append(record)
        except Exception:
            self.db_connected = False
        return rows

    def get_metricas_raw(self, from_dt=None, to_dt=None, metrica=None, limit=1000):
        rows = self._fetch_metric_rows(
            "metricas_raw",
            from_dt=from_dt,
            to_dt=to_dt,
            metrica=metrica,
            limit=limit,
        )
        return {
            "db_connected": self.db_connected,
            "count": len(rows),
            "items": rows,
        }

    def get_metricas_clean(self, from_dt=None, to_dt=None, metrica=None, limit=1000):
        rows = self._fetch_metric_rows(
            "metricas_clean",
            from_dt=from_dt,
            to_dt=to_dt,
            metrica=metrica,
            limit=limit,
        )
        return {
            "db_connected": self.db_connected,
            "count": len(rows),
            "items": rows,
        }

    def get_metricas_resumen(self):
        resumen = {
            "db_connected": self.db_connected,
            "raw_total": 0,
            "clean_total": 0,
            "latencia_promedio_ms": None,
            "latencia_p95_ms": None,
        }
        try:
            with psycopg2.connect(DB_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM metricas_raw")
                    resumen["raw_total"] = int(cur.fetchone()[0] or 0)
                    cur.execute("SELECT COUNT(*) FROM metricas_clean")
                    resumen["clean_total"] = int(cur.fetchone()[0] or 0)
                    cur.execute(
                        """
                        SELECT
                            AVG(valor) FILTER (WHERE metrica = 'latencia_reconocimiento') AS lat_avg,
                            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY valor)
                                FILTER (WHERE metrica = 'latencia_reconocimiento') AS lat_p95
                        FROM metricas_raw
                        """
                    )
                    row = cur.fetchone()
                    if row:
                        resumen["latencia_promedio_ms"] = round(float(row[0]), 2) if row[0] is not None else None
                        resumen["latencia_p95_ms"] = round(float(row[1]), 2) if row[1] is not None else None
            self.db_connected = True
        except Exception:
            self.db_connected = False
            resumen["db_connected"] = False
        return resumen

    def get_two_fa_setup(self, username=None):
        uname = self._normalize_username(username) if username else None
        user_sec = self._get_user_security(uname) if uname else None
        secret_masked = self._mask_secret((user_sec or {}).get("totp_secret") or self.two_fa_secret)
        return {
            "enabled": self.two_fa_enabled,
            "issuer": TOTP_ISSUER,
            "account": uname or TOTP_ACCOUNT,
            "username": uname,
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD_SECONDS,
            "secret_masked": secret_masked,
            "otpauth_uri": None,
            "qr_endpoint": None,
            "user_exists": bool(user_sec) if uname else None,
        }

    def get_security_panel(self):
        now = time.time()
        last_24h = now - 86400
        recent_events = list(self.security_events)[:20]
        critical = sum(1 for e in recent_events if e.get("level") == "crit")
        warnings = sum(1 for e in recent_events if e.get("level") == "warn")
        incidents_24h = sum(
            1
            for e in self.security_events
            if e.get("event_type") in {"intruso_detectado", "2fa_fallido", "lock_activado"}
            and datetime.strptime(e["ts"], "%Y-%m-%d %H:%M:%S").timestamp() >= last_24h
        )
        return {
            "security_locked": now < self.security_lock_until,
            "security_lock_remaining": max(0, int(self.security_lock_until - now)),
            "two_fa_enabled": self.two_fa_enabled,
            "two_fa_pending": self.two_fa_pending,
            "critical_alerts": critical,
            "warning_alerts": warnings,
            "incidents_24h": incidents_24h,
            "recent_events": recent_events,
        }

    def shutdown(self):
        self.running = False
        if self.thread.is_alive():
            self.thread.join(timeout=1)


app = Flask(__name__)
engine = FaceAccessEngine()


def _admin_token_from_request():
    return request.headers.get("X-Admin-Token") or request.args.get("token") or ""


def _require_admin():
    token = _admin_token_from_request()
    if not engine._admin_token_valid(token):
        return None, (jsonify({"ok": False, "error": "Admin token invalido"}), 403)
    return token, None


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


@app.get("/api/reportes")
def api_reportes():
    return jsonify(engine.get_reportes())


def _query_metricas_filters():
    from_dt = engine._parse_datetime_filter(request.args.get("from"))
    to_dt = engine._parse_datetime_filter(request.args.get("to"))
    metrica = (request.args.get("metrica") or "").strip() or None
    try:
        limit = int(request.args.get("limit", "1000"))
    except ValueError:
        limit = 1000
    return from_dt, to_dt, metrica, max(1, min(limit, 10000))


def _rows_to_csv_response(rows, filename):
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        writer = csv.writer(output)
        writer.writerow(["sin_datos"])
    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/metricas/raw")
def api_metricas_raw():
    from_dt, to_dt, metrica, limit = _query_metricas_filters()
    return jsonify(engine.get_metricas_raw(from_dt=from_dt, to_dt=to_dt, metrica=metrica, limit=limit))


@app.get("/api/metricas/raw.csv")
def api_metricas_raw_csv():
    from_dt, to_dt, metrica, limit = _query_metricas_filters()
    data = engine.get_metricas_raw(from_dt=from_dt, to_dt=to_dt, metrica=metrica, limit=limit)
    return _rows_to_csv_response(data.get("items", []), "metricas_raw.csv")


@app.get("/api/metricas/clean")
def api_metricas_clean():
    from_dt, to_dt, metrica, limit = _query_metricas_filters()
    return jsonify(engine.get_metricas_clean(from_dt=from_dt, to_dt=to_dt, metrica=metrica, limit=limit))


@app.get("/api/metricas/clean.csv")
def api_metricas_clean_csv():
    from_dt, to_dt, metrica, limit = _query_metricas_filters()
    data = engine.get_metricas_clean(from_dt=from_dt, to_dt=to_dt, metrica=metrica, limit=limit)
    return _rows_to_csv_response(data.get("items", []), "metricas_clean.csv")


@app.get("/api/metricas/resumen")
def api_metricas_resumen():
    return jsonify(engine.get_metricas_resumen())


@app.get("/api/2fa/setup")
def api_2fa_setup():
    username = (request.args.get("username") or "").strip() or None
    data = engine.get_two_fa_setup(username=username)
    token = _admin_token_from_request()
    if engine._admin_token_valid(token):
        if username:
            user_sec = engine._get_user_security(username)
            if user_sec and user_sec.get("totp_secret"):
                data["otpauth_uri"] = engine._totp_otpauth_uri_for(username, user_sec.get("totp_secret"))
                data["qr_endpoint"] = (
                    f"/api/2fa/qr?token={urllib.parse.quote(token)}&username={urllib.parse.quote(username)}"
                )
        else:
            data["otpauth_uri"] = engine._totp_otpauth_uri()
            data["qr_endpoint"] = f"/api/2fa/qr?token={urllib.parse.quote(token)}"
        data["admin_access"] = True
    else:
        data["admin_access"] = False
    return jsonify(data)


@app.get("/api/2fa/qr")
def api_2fa_qr():
    token = _admin_token_from_request()
    if not engine._admin_token_valid(token):
        return jsonify({"ok": False, "error": "Admin token requerido"}), 403
    username = (request.args.get("username") or "").strip() or None
    if username:
        user_sec = engine._get_user_security(username)
        if not user_sec or not user_sec.get("totp_secret"):
            return jsonify({"ok": False, "error": "Usuario sin 2FA enrolado"}), 404
        uri = engine._totp_otpauth_uri_for(username, user_sec.get("totp_secret"))
    else:
        uri = engine._totp_otpauth_uri()
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype="image/png")


@app.post("/api/2fa/verify")
def api_2fa_verify():
    payload = request.get_json(silent=True) or {}
    code = payload.get("code", "")
    ok, message = engine.verify_second_factor(code)
    status = 200 if ok else 400
    return jsonify({"ok": ok, "message": message, "status": engine.get_status()}), status


@app.get("/api/security/panel")
def api_security_panel():
    return jsonify(engine.get_security_panel())


@app.get("/api/admin/users_security")
def api_admin_users_security():
    _, error = _require_admin()
    if error:
        return error
    return jsonify({"ok": True, "items": engine.list_user_security()})


@app.post("/api/admin/users_security/enroll")
def api_admin_enroll_user():
    _, error = _require_admin()
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    role = payload.get("role", "empleado")
    requires_2fa = bool(payload.get("requires_2fa", True))
    ok, msg, data = engine.enroll_user_2fa(username, role=role, requires_2fa=requires_2fa)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "item": data})


@app.post("/api/admin/users_security/<username>/active")
def api_admin_set_user_active(username):
    _, error = _require_admin()
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    active = bool(payload.get("active", True))
    ok, msg = engine.set_user_active(username, active=active)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "username": username, "active": active})


@app.post("/api/admin/users_security/<username>/role")
def api_admin_set_user_role(username):
    _, error = _require_admin()
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    role = str(payload.get("role", "empleado"))
    ok, msg = engine.set_user_role(username, role=role)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "username": username, "role": role})


@app.post("/api/admin/users_security/<username>/rotate_2fa")
def api_admin_rotate_user_2fa(username):
    token, error = _require_admin()
    if error:
        return error
    ok, msg, data = engine.rotate_user_2fa(username)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    data["qr_endpoint"] = (
        f"/api/2fa/qr?token={urllib.parse.quote(token)}&username={urllib.parse.quote(username)}"
    )
    return jsonify({"ok": True, "item": data})


@app.post("/api/mesh")
def api_mesh():
    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get("enabled", True))
    engine.set_mesh_enabled(enabled)
    return jsonify({"ok": True, "mesh_enabled": enabled})


@app.post("/api/performance")
def api_performance():
    payload = request.get_json(silent=True) or {}
    if "auto" in payload:
        engine.set_auto_performance(bool(payload.get("auto")))
    if "mode" in payload:
        mode = str(payload.get("mode", "normal")).strip().lower()
        if mode not in {"normal", "ahorro"}:
            return jsonify({"ok": False, "error": "mode invalido"}), 400
        engine.set_performance_mode(mode)
    return jsonify({"ok": True, "status": engine.get_status()})


@app.post("/api/reload_faces")
def api_reload_faces():
    if not LIVE_RELOAD_FACE_DB:
        return jsonify(
            {
                "ok": True,
                "requires_restart": True,
                "message": (
                    "Para estabilidad en este entorno, la recarga biometrica es por reinicio. "
                    "Ejecuta: docker compose restart face-service"
                ),
            }
        )

    result = engine.request_reload_faces(timeout_seconds=20.0)
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)
    finally:
        engine.shutdown()
