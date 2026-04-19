import os
import threading
import time
from pathlib import Path

import cv2
import face_recognition
import numpy as np
from flask import Flask, Response, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
KNOWN_FACES_DIR = DATA_DIR / "known_faces"
FOTO_REFERENCIA_PATH = Path(os.getenv("FOTO_REFERENCIA_PATH", str(DATA_DIR / "foto_referencia.png")))
CAMERA_INDEX = int(os.getenv("CAMERA_INDEX", "0"))
FRAME_SCALE = float(os.getenv("FRAME_SCALE", "0.25"))
PROCESS_EVERY_N_FRAMES = int(os.getenv("PROCESS_EVERY_N_FRAMES", "2"))
MATCH_THRESHOLD = float(os.getenv("MATCH_THRESHOLD", "0.5"))
FRAMES_CONSECUTIVOS_REQUERIDOS = int(os.getenv("FRAMES_CONSECUTIVOS_REQUERIDOS", "10"))
CAMERA_WIDTH = int(os.getenv("CAMERA_WIDTH", "960"))
CAMERA_HEIGHT = int(os.getenv("CAMERA_HEIGHT", "540"))
JPEG_QUALITY = int(os.getenv("JPEG_QUALITY", "75"))


class RecognitionEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.running = True
        self.camera_enabled = True
        self.scan_active = False
        self.state = "idle"
        self.progress = 0
        self.confidence = None
        self.current_candidate = None
        self.mesh_enabled = False
        self.resolution = f"{CAMERA_WIDTH}x{CAMERA_HEIGHT}"
        self.fps = 0
        self.last_process = 0.0

        self.frame_count = 0
        self.frames_consecutivos = 0
        self.unknown_start = None
        self.unknown_seconds = 0.0
        self.last_unknown_frame = None
        self.last_frame = np.zeros((CAMERA_HEIGHT, CAMERA_WIDTH, 3), dtype=np.uint8)

        self.users = []
        self.known_encodings = []
        self.known_names = []
        self.reload_faces()

        self.cap = cv2.VideoCapture(CAMERA_INDEX)
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAMERA_WIDTH)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAMERA_HEIGHT)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _load_single_image(self, path: Path, username: str):
        try:
            img = face_recognition.load_image_file(str(path))
            encs = face_recognition.face_encodings(img)
            if encs:
                self.known_encodings.append(encs[0])
                self.known_names.append(username)
                return True
        except Exception:
            return False
        return False

    def reload_faces(self):
        with self.lock:
            self.known_encodings = []
            self.known_names = []
            loaded = 0
            identities = set()

            if FOTO_REFERENCIA_PATH.exists() and FOTO_REFERENCIA_PATH.is_file():
                if self._load_single_image(FOTO_REFERENCIA_PATH, "Andersson"):
                    loaded += 1
                    identities.add("Andersson")

            if KNOWN_FACES_DIR.exists():
                for user_dir in sorted(KNOWN_FACES_DIR.iterdir()):
                    if not user_dir.is_dir():
                        continue
                    username = user_dir.name
                    for img in sorted(user_dir.glob("*")):
                        if img.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp"}:
                            continue
                        if self._load_single_image(img, username):
                            loaded += 1
                            identities.add(username)

            self.users = sorted(identities)
            return {"ok": True, "encodings": loaded, "identidades": len(self.users)}

    def add_user(self, username: str):
        username = (username or "").strip()
        if not username:
            return False, "Nombre vacio"
        user_dir = KNOWN_FACES_DIR / username
        user_dir.mkdir(parents=True, exist_ok=True)
        with self.lock:
            if username not in self.users:
                self.users.append(username)
                self.users.sort()
        return True, f"Usuario {username} listo. Agrega fotos en {user_dir}"

    def remove_user(self, username: str):
        username = (username or "").strip()
        if not username:
            return False, "Nombre vacio"
        with self.lock:
            old_len = len(self.known_names)
            keep_idx = [i for i, n in enumerate(self.known_names) if n != username]
            self.known_names = [self.known_names[i] for i in keep_idx]
            self.known_encodings = [self.known_encodings[i] for i in keep_idx]
            if username in self.users:
                self.users.remove(username)
            removed = old_len - len(self.known_names)
        return True, f"Usuario {username} eliminado de memoria ({removed} encodings removidos)"

    def user_photo_path(self, username: str):
        username = (username or "").strip()
        if not username:
            return None
        user_dir = KNOWN_FACES_DIR / username
        if not user_dir.exists() or not user_dir.is_dir():
            return None
        for ext in ("*.jpg", "*.jpeg", "*.png", "*.webp"):
            files = sorted(user_dir.glob(ext))
            if files:
                return files[0]
        return None

    def start_scan(self):
        with self.lock:
            self.camera_enabled = True
            self.scan_active = True
            self.state = "scanning"
            self.progress = 0
            self.confidence = None
            self.current_candidate = None
            self.frames_consecutivos = 0
            self.unknown_start = None
            self.unknown_seconds = 0.0
        if not self.cap.isOpened():
            self.cap.open(CAMERA_INDEX)
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAMERA_WIDTH)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAMERA_HEIGHT)

    def reset(self):
        with self.lock:
            self.scan_active = False
            self.state = "idle"
            self.progress = 0
            self.confidence = None
            self.current_candidate = None
            self.frames_consecutivos = 0
            self.unknown_start = None
            self.unknown_seconds = 0.0

    def set_camera_enabled(self, enabled: bool):
        enabled = bool(enabled)
        with self.lock:
            self.camera_enabled = enabled
            if not enabled:
                self.scan_active = False
                self.state = "idle"
                self.progress = 0
                self.confidence = None
                self.current_candidate = None
                self.frames_consecutivos = 0
                self.unknown_start = None
                self.unknown_seconds = 0.0
        if enabled:
            if not self.cap.isOpened():
                self.cap.open(CAMERA_INDEX)
                self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAMERA_WIDTH)
                self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAMERA_HEIGHT)
        else:
            if self.cap.isOpened():
                self.cap.release()

    def set_mesh(self, enabled: bool):
        with self.lock:
            self.mesh_enabled = bool(enabled)

    def _update_fps(self):
        now = time.time()
        if self.last_process:
            dt = now - self.last_process
            if dt > 0:
                self.fps = int(1.0 / dt)
        self.last_process = now

    def _draw_label(self, frame, left, top, right, bottom, name, ok):
        color = (0, 255, 0) if ok else (0, 0, 255)
        cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
        cv2.rectangle(frame, (left, bottom - 30), (right, bottom), color, cv2.FILLED)
        cv2.putText(frame, name, (left + 6, bottom - 8), cv2.FONT_HERSHEY_DUPLEX, 0.6, (0, 0, 0), 1)

    def _process_frame(self, frame):
        if not self.scan_active:
            return frame

        self.frame_count += 1
        if self.frame_count % max(1, PROCESS_EVERY_N_FRAMES) != 0:
            return frame

        small = cv2.resize(frame, (0, 0), fx=FRAME_SCALE, fy=FRAME_SCALE)
        rgb_small = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
        locations = face_recognition.face_locations(rgb_small)
        encodings = face_recognition.face_encodings(rgb_small, locations)

        best_name = None
        best_dist = None
        unknown_detected = False

        for (top, right, bottom, left), face_encoding in zip(locations, encodings):
            name = "Desconocido"
            ok = False
            if self.known_encodings:
                dists = face_recognition.face_distance(self.known_encodings, face_encoding)
                idx = int(np.argmin(dists))
                d = float(dists[idx])
                if d <= MATCH_THRESHOLD:
                    name = self.known_names[idx]
                    ok = True
                    if best_dist is None or d < best_dist:
                        best_dist = d
                        best_name = name
                else:
                    unknown_detected = True
            else:
                unknown_detected = True

            s = int(1.0 / FRAME_SCALE)
            self._draw_label(frame, left * s, top * s, right * s, bottom * s, name, ok)

        if best_name is not None and best_dist is not None:
            self.frames_consecutivos = min(self.frames_consecutivos + 1, FRAMES_CONSECUTIVOS_REQUERIDOS)
            self.current_candidate = best_name
            self.confidence = max(0.0, min(100.0, (1.0 - best_dist) * 100.0))
            self.progress = int((self.frames_consecutivos / FRAMES_CONSECUTIVOS_REQUERIDOS) * 100)
            self.state = "detected" if self.frames_consecutivos >= FRAMES_CONSECUTIVOS_REQUERIDOS else "scanning"
            self.unknown_start = None
            self.unknown_seconds = 0.0
        elif unknown_detected:
            self.frames_consecutivos = 0
            self.progress = 0
            self.current_candidate = None
            self.confidence = None
            self.state = "denied"
            now = time.time()
            if self.unknown_start is None:
                self.unknown_start = now
            self.unknown_seconds = now - self.unknown_start
            self.last_unknown_frame = frame.copy()
        else:
            self.frames_consecutivos = 0
            self.progress = 0
            self.current_candidate = None
            self.confidence = None
            self.state = "scanning"
            self.unknown_start = None
            self.unknown_seconds = 0.0

        return frame

    def _loop(self):
        while self.running:
            if not self.camera_enabled:
                blank = np.zeros((CAMERA_HEIGHT, CAMERA_WIDTH, 3), dtype=np.uint8)
                cv2.putText(blank, "Camara apagada", (40, 70), cv2.FONT_HERSHEY_DUPLEX, 1.0, (180, 180, 180), 2)
                with self.lock:
                    self.fps = 0
                    self.last_frame = blank
                time.sleep(0.15)
                continue

            if not self.cap.isOpened():
                self.cap.open(CAMERA_INDEX)
                time.sleep(0.2)
                continue

            ok, frame = self.cap.read()
            if not ok:
                time.sleep(0.05)
                continue

            frame = cv2.resize(frame, (CAMERA_WIDTH, CAMERA_HEIGHT))
            with self.lock:
                self._update_fps()
                processed = self._process_frame(frame)
                self.last_frame = processed

    def get_status(self):
        with self.lock:
            return {
                "camera_enabled": self.camera_enabled,
                "camera_opened": bool(self.cap.isOpened()) if self.cap is not None else False,
                "scan_active": self.scan_active,
                "state": self.state,
                "progress": self.progress,
                "confidence": self.confidence,
                "current_candidate": self.current_candidate,
                "unknown_seconds": round(self.unknown_seconds, 2),
                "mesh_enabled": self.mesh_enabled,
                "fps": self.fps,
                "resolution": self.resolution,
                "users": self.users,
            }

    def get_snapshot(self, unknown_only=False):
        with self.lock:
            frame = self.last_unknown_frame if unknown_only and self.last_unknown_frame is not None else self.last_frame
            ok, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY])
            return buffer.tobytes() if ok else b""

    def stream(self):
        while True:
            jpg = self.get_snapshot(unknown_only=False)
            if not jpg:
                time.sleep(0.05)
                continue
            yield (b"--frame\r\n"
                   b"Content-Type: image/jpeg\r\n\r\n" + jpg + b"\r\n")
            time.sleep(0.03)


app = Flask(__name__)
engine = RecognitionEngine()


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/video_feed")
def video_feed():
    return Response(engine.stream(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.get("/internal/status")
def status():
    return jsonify(engine.get_status())


@app.get("/internal/users")
def users():
    data = engine.get_status()
    return jsonify({"users": data.get("users", []), "count": len(data.get("users", []))})


@app.get("/internal/user_photo/<username>")
def user_photo(username):
    path = engine.user_photo_path(username)
    if path is None:
        return jsonify({"ok": False, "error": "Foto no encontrada"}), 404
    data = path.read_bytes()
    suffix = path.suffix.lower()
    mime = "image/jpeg"
    if suffix == ".png":
        mime = "image/png"
    elif suffix == ".webp":
        mime = "image/webp"
    return Response(data, mimetype=mime)


@app.post("/internal/users")
def add_user():
    payload = request.get_json(silent=True) or {}
    ok, msg = engine.add_user(str(payload.get("name", "")))
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "message": msg})


@app.delete("/internal/users/<name>")
def delete_user(name):
    ok, msg = engine.remove_user(name)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "message": msg})


@app.post("/internal/start_scan")
def start_scan():
    engine.start_scan()
    return jsonify({"ok": True})


@app.post("/internal/reset")
def reset():
    engine.reset()
    return jsonify({"ok": True})


@app.post("/internal/mesh")
def mesh():
    payload = request.get_json(silent=True) or {}
    engine.set_mesh(bool(payload.get("enabled", False)))
    return jsonify({"ok": True})


@app.post("/internal/camera")
def camera():
    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get("enabled", False))
    engine.set_camera_enabled(enabled)
    return jsonify({"ok": True, "camera_enabled": enabled})


@app.post("/internal/reload_faces")
def reload_faces():
    return jsonify(engine.reload_faces())


@app.get("/internal/snapshot.jpg")
def snapshot():
    unknown_only = str(request.args.get("unknown_only", "0")) in {"1", "true", "True"}
    data = engine.get_snapshot(unknown_only=unknown_only)
    return Response(data, mimetype="image/jpeg")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8101, debug=False)
