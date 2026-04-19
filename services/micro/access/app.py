import csv
import io
import json
import os
import threading
import time
from time import perf_counter
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import psycopg2
import requests
from psycopg2.extras import Json
from flask import Flask, Response, jsonify, request, send_file, g
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

RECOGNITION_URL = os.getenv("RECOGNITION_URL", "http://recognition-service:8101")
AUTH_URL = os.getenv("AUTH_URL", "http://auth-service:8102")
DEVICE_SERVICE_URL = os.getenv("DEVICE_SERVICE_URL", "http://device-service:8001")
DB_URL = os.getenv("DB_URL", "postgresql://faceaccess:faceaccess@postgres-service:5432/faceaccess")
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "").strip()
PLEX_URL = os.getenv("PLEX_URL", "http://host.docker.internal:8097/web/index.html#/dashboard")
INTRUSOS_DIR = Path(os.getenv("INTRUSOS_DIR", "/app/intrusos"))
RUTA_LOG = Path(os.getenv("RUTA_LOG", "/app/registro_accesos.csv"))

TWO_FA_GRACE_SECONDS = int(os.getenv("TWO_FA_GRACE_SECONDS", "60"))
TWO_FA_TRUST_SECONDS = int(os.getenv("TWO_FA_TRUST_SECONDS", "120"))
INTRUSO_SECONDS = float(os.getenv("SEGUNDOS_INTRUSO", "3.0"))
INTRUSO_COOLDOWN = float(os.getenv("COOLDOWN_CAPTURA_INTRUSO", "5.0"))
METRIC_SNAPSHOT_INTERVAL = float(os.getenv("METRIC_SNAPSHOT_INTERVAL", "30"))

HTTP_REQUESTS_TOTAL = Counter(
    "pdp_http_requests_total",
    "Total requests HTTP por endpoint/method/status",
    ["endpoint", "method", "status"],
)
HTTP_REQUEST_LATENCY_SECONDS = Histogram(
    "pdp_http_request_latency_seconds",
    "Latencia de requests HTTP por endpoint",
    ["endpoint", "method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
PDP_ACCESS_EVENTS_TOTAL = Counter(
    "pdp_access_events_total",
    "Conteo de eventos de acceso",
    ["evento"],
)
PDP_TWOFA_EVENTS_TOTAL = Counter(
    "pdp_twofa_events_total",
    "Conteo de eventos 2FA por resultado",
    ["resultado"],
)
PDP_INTRUSOS_TOTAL = Counter(
    "pdp_intrusos_total",
    "Capturas de intrusos detectados",
)
PDP_KPI_PCT_CONCEDIDOS = Gauge("pdp_kpi_pct_concedidos", "Porcentaje accesos concedidos")
PDP_KPI_PCT_DENEGADOS = Gauge("pdp_kpi_pct_denegados", "Porcentaje accesos denegados")
PDP_KPI_PCT_2FA_FAIL = Gauge("pdp_kpi_pct_2fa_fail", "Porcentaje fallos de 2FA")
PDP_KPI_TOTAL_EVENTOS = Gauge("pdp_kpi_total_eventos", "Total eventos acceso")
PDP_NETWORK_LATENCY_MS = Gauge("pdp_network_latency_ms", "Latencia de red promedio por servicio (ms)", ["servicio"])
PDP_NETWORK_ERROR_PCT = Gauge("pdp_network_error_pct", "Porcentaje de error por servicio", ["servicio"])
PDP_NETWORK_AVAILABILITY_PCT = Gauge("pdp_network_availability_pct", "Disponibilidad por servicio", ["servicio"])
PDP_CAMERA_RECOGNITION_PCT = Gauge("pdp_camera_recognition_pct", "Tasa reconocimiento por perfil de camara", ["perfil"])
PDP_CAMERA_EVENTS_TOTAL = Gauge("pdp_camera_events_total", "Eventos por perfil de camara", ["perfil"])


class AccessEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.logs = deque(maxlen=500)
        self.system_open = False
        self.current_user = None
        self.current_role = None
        self.current_confidence = None
        self.pending_2fa_user = None
        self.pending_2fa_expires_at = 0.0
        self.two_fa_trusted_until = {}
        self.security_lock_until = 0.0
        self.last_intruso_capture = 0.0
        self.last_denied_emit = 0.0
        self.net_stats = {}
        self.last_metrics_snapshot_at = 0.0
        self.twofa_ok_count = 0
        self.twofa_fail_count = 0
        self.camera_profile_stats = {
            "pobre": {"ok": 0, "den": 0, "total": 0},
            "buena": {"ok": 0, "den": 0, "total": 0},
            "desconocida": {"ok": 0, "den": 0, "total": 0},
        }
        self.last_rec_snapshot = {}
        self.live_cache = {
            "generated_at": None,
            "kpis": {},
            "network": [],
            "camera": [],
        }
        self.live_history = {
            "times": deque(maxlen=60),
            "pct_concedidos": deque(maxlen=60),
            "pct_denegados": deque(maxlen=60),
            "pct_2fa_fail": deque(maxlen=60),
        }

        INTRUSOS_DIR.mkdir(parents=True, exist_ok=True)
        self._init_csv()
        self._init_db()
        self._table_columns_cache = {}

    def _http(self, method, url, **kwargs):
        timeout = kwargs.pop("timeout", 3)
        svc = self._service_from_url(url)
        t0 = perf_counter()
        try:
            resp = requests.request(method, url, timeout=timeout, **kwargs)
            elapsed_ms = (perf_counter() - t0) * 1000.0
            self._record_network_stat(svc, elapsed_ms, ok=(200 <= resp.status_code < 400))
            return resp
        except Exception:
            elapsed_ms = (perf_counter() - t0) * 1000.0
            self._record_network_stat(svc, elapsed_ms, ok=False)
            raise

    def _service_from_url(self, url: str):
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if "recognition" in host:
            return "recognition"
        if "auth" in host:
            return "auth"
        if "device" in host:
            return "device"
        if "n8n" in host:
            return "n8n"
        return host or "desconocido"

    def _record_network_stat(self, service: str, latency_ms: float, ok: bool):
        with self.lock:
            s = self.net_stats.setdefault(service, {"count": 0, "ok": 0, "err": 0, "lat_sum_ms": 0.0})
            s["count"] += 1
            s["lat_sum_ms"] += float(latency_ms or 0.0)
            if ok:
                s["ok"] += 1
            else:
                s["err"] += 1

    def _parse_resolution(self, resolution):
        if not resolution or "x" not in str(resolution):
            return 0, 0
        try:
            w, h = str(resolution).lower().split("x", 1)
            return int(w.strip()), int(h.strip())
        except Exception:
            return 0, 0

    def _camera_profile(self, rec):
        fps = float(rec.get("fps") or 0.0)
        w, h = self._parse_resolution(rec.get("resolution"))
        if w >= 1280 and h >= 720 and fps >= 24:
            return "buena"
        if w > 0 and h > 0:
            return "pobre"
        return "desconocida"

    def _register_camera_event_metrics(self, rec, evento, persona):
        perfil = self._camera_profile(rec or {})
        fps = rec.get("fps")
        resolution = rec.get("resolution")
        et = {"perfil": perfil, "evento": evento, "persona": persona or "-", "resolution": resolution or "-"}
        self._register_metric("camara_evento", 1.0, "conteo", et)
        if fps is not None:
            try:
                self._register_metric("camara_fps", float(fps), "fps", et)
            except Exception:
                pass
        with self.lock:
            p = self.camera_profile_stats.setdefault(perfil, {"ok": 0, "den": 0, "total": 0})
            p["total"] += 1
            if evento == "ACCESO_CONCEDIDO":
                p["ok"] += 1
            if evento == "ACCESO_DENEGADO":
                p["den"] += 1

    def _emit_snapshot_metrics(self, force=False):
        now = time.time()
        if (not force) and (now - self.last_metrics_snapshot_at < METRIC_SNAPSHOT_INTERVAL):
            return
        self.last_metrics_snapshot_at = now

        with self.lock:
            net_copy = dict(self.net_stats)
            cam_copy = json.loads(json.dumps(self.camera_profile_stats))
            twofa_ok = int(self.twofa_ok_count)
            twofa_fail = int(self.twofa_fail_count)

        network_rows = []
        for service, s in net_copy.items():
            count = int(s.get("count", 0) or 0)
            if count <= 0:
                continue
            lat_avg = float(s.get("lat_sum_ms", 0.0)) / count
            err = int(s.get("err", 0) or 0)
            ok = int(s.get("ok", 0) or 0)
            err_pct = (err / count) * 100.0
            avail_pct = (ok / count) * 100.0
            et = {"servicio": service}
            self._register_metric("red_latencia_promedio", lat_avg, "ms", et)
            self._register_metric("red_tasa_error", err_pct, "porcentaje", et)
            self._register_metric("red_disponibilidad", avail_pct, "porcentaje", et)
            PDP_NETWORK_LATENCY_MS.labels(servicio=service).set(lat_avg)
            PDP_NETWORK_ERROR_PCT.labels(servicio=service).set(err_pct)
            PDP_NETWORK_AVAILABILITY_PCT.labels(servicio=service).set(avail_pct)
            network_rows.append(
                {
                    "servicio": service,
                    "lat_ms": round(lat_avg, 2),
                    "error_pct": round(err_pct, 2),
                    "disponibilidad_pct": round(avail_pct, 2),
                    "count": count,
                }
            )

        rep = self.get_reportes()
        total = float(rep.get("total", 0) or 0)
        concedidos = float(rep.get("concedidos", 0) or 0)
        denegados = float(rep.get("denegados", 0) or 0)
        pct_con = (concedidos / total) * 100.0 if total > 0 else 0.0
        pct_den = (denegados / total) * 100.0 if total > 0 else 0.0
        self._register_metric("porcentaje_accesos_concedidos", pct_con, "porcentaje", {"scope": "global"})
        self._register_metric("porcentaje_accesos_denegados", pct_den, "porcentaje", {"scope": "global"})
        PDP_KPI_PCT_CONCEDIDOS.set(pct_con)
        PDP_KPI_PCT_DENEGADOS.set(pct_den)
        PDP_KPI_TOTAL_EVENTOS.set(total)

        twofa_total = float(twofa_ok + twofa_fail)
        pct_2fa_fail = (twofa_fail / twofa_total) * 100.0 if twofa_total > 0 else 0.0
        self._register_metric("porcentaje_2fa_fallido", pct_2fa_fail, "porcentaje", {"scope": "global"})
        PDP_KPI_PCT_2FA_FAIL.set(pct_2fa_fail)

        camera_rows = []
        for perfil, c in cam_copy.items():
            t = float(c.get("total", 0) or 0)
            ok = float(c.get("ok", 0) or 0)
            den = float(c.get("den", 0) or 0)
            rate = (ok / t) * 100.0 if t > 0 else 0.0
            self._register_metric("camara_tasa_reconocimiento", rate, "porcentaje", {"perfil": perfil})
            PDP_CAMERA_RECOGNITION_PCT.labels(perfil=perfil).set(rate)
            PDP_CAMERA_EVENTS_TOTAL.labels(perfil=perfil).set(t)
            camera_rows.append(
                {
                    "perfil": perfil,
                    "total": int(t),
                    "ok": int(ok),
                    "den": int(den),
                    "tasa_reconocimiento_pct": round(rate, 2),
                }
            )

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.live_cache = {
                "generated_at": ts,
                "kpis": {
                    "total_eventos": int(total),
                    "concedidos": int(concedidos),
                    "denegados": int(denegados),
                    "pct_concedidos": round(pct_con, 2),
                    "pct_denegados": round(pct_den, 2),
                    "pct_2fa_fail": round(pct_2fa_fail, 2),
                    "twofa_ok": twofa_ok,
                    "twofa_fail": twofa_fail,
                },
                "network": sorted(network_rows, key=lambda x: x["servicio"]),
                "camera": sorted(camera_rows, key=lambda x: x["perfil"]),
            }
            self.live_history["times"].append(ts[-8:])
            self.live_history["pct_concedidos"].append(round(pct_con, 2))
            self.live_history["pct_denegados"].append(round(pct_den, 2))
            self.live_history["pct_2fa_fail"].append(round(pct_2fa_fail, 2))

    def _is_admin_token_valid(self, token: str):
        token = (token or "").strip()
        if not token:
            return False
        try:
            r = self._http(
                "GET",
                f"{AUTH_URL}/api/admin/users_security",
                headers={"X-Admin-Token": token},
                timeout=4,
            )
            return 200 <= r.status_code < 300
        except Exception:
            return False

    def _init_csv(self):
        if not RUTA_LOG.exists():
            with RUTA_LOG.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["fecha_hora", "evento", "persona", "distancia"])

    def _init_db(self):
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
                        ts TIMESTAMP NOT NULL DEFAULT NOW(),
                        metrica VARCHAR(128) NOT NULL,
                        valor DOUBLE PRECISION,
                        unidad VARCHAR(32),
                        etiquetas JSONB,
                        origen VARCHAR(64) NOT NULL DEFAULT 'access-service'
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS metricas_clean (
                        id BIGSERIAL PRIMARY KEY,
                        ts TIMESTAMP NOT NULL DEFAULT NOW(),
                        metrica VARCHAR(128) NOT NULL,
                        valor DOUBLE PRECISION,
                        unidad VARCHAR(32),
                        etiquetas JSONB,
                        origen VARCHAR(64) NOT NULL DEFAULT 'access-service'
                    )
                    """
                )
            conn.commit()

    def _log(self, msg, t="info"):
        self.logs.appendleft({"time": datetime.now().strftime("%H:%M:%S"), "msg": msg, "type": t})

    def _notify_n8n(self, event_type, payload):
        if not N8N_WEBHOOK_URL:
            return
        try:
            self._http("POST", N8N_WEBHOOK_URL, json={"event_type": event_type, "source": "access-service", "payload": payload}, timeout=2)
        except Exception:
            pass

    def _notify_device(self, text, led_on=False):
        try:
            self._http("POST", f"{DEVICE_SERVICE_URL}/notify", json={"text": text, "led_on": bool(led_on)}, timeout=2)
        except Exception:
            pass

    def _register_event(self, evento, persona, distancia=None):
        with RUTA_LOG.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                evento,
                persona,
                "-" if distancia is None else f"{float(distancia):.4f}",
            ])

        with psycopg2.connect(DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO access_logs(evento, persona, distancia) VALUES(%s,%s,%s)", (evento, persona, distancia))
            conn.commit()
        PDP_ACCESS_EVENTS_TOTAL.labels(evento=evento).inc()

    def _metric_clean_name(self, m):
        mapping = {
            "intento_acceso_total": ("acceso_intento", "conteo"),
            "acceso_concedido": ("acceso_concedido", "conteo"),
            "acceso_denegado": ("acceso_denegado", "conteo"),
            "confianza_biometrica": ("biometria_confianza", "porcentaje"),
        }
        return mapping.get(m, (m, "sin_unidad"))

    def _register_metric(self, metrica, valor=None, unidad=None, etiquetas=None):
        etiquetas = etiquetas or {}
        with psycopg2.connect(DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO metricas_raw(metrica, valor, unidad, etiquetas, origen) VALUES(%s,%s,%s,%s,%s)",
                    (metrica, valor, unidad, Json(etiquetas), "access-service"),
                )
                clean_m, clean_u = self._metric_clean_name(metrica)
                clean_v = 1.0 if clean_u == "conteo" else (float(valor) if valor is not None else None)
                clean_et = {"metrica_origen": metrica, **etiquetas}
                cols_clean = self._table_columns("metricas_clean", conn=conn)
                if {"etiquetas", "origen"}.issubset(cols_clean):
                    cur.execute(
                        "INSERT INTO metricas_clean(metrica, valor, unidad, etiquetas, origen) VALUES(%s,%s,%s,%s,%s)",
                        (clean_m, clean_v, clean_u, Json(clean_et), "access-service"),
                    )
                else:
                    ts_col = "ts" if "ts" in cols_clean else "fecha_hora"
                    d1 = str(etiquetas.get("evento", ""))
                    d2 = str(etiquetas.get("persona", ""))
                    notas = json.dumps(clean_et, ensure_ascii=False)
                    cur.execute(
                        f"INSERT INTO metricas_clean({ts_col}, metrica, valor, unidad, dimension_1, dimension_2, notas) "
                        "VALUES(NOW(),%s,%s,%s,%s,%s,%s)",
                        (clean_m, clean_v, clean_u, d1, d2, notas),
                    )
            conn.commit()

    def _capture_intruso(self):
        try:
            r = self._http("GET", f"{RECOGNITION_URL}/internal/snapshot.jpg", params={"unknown_only": "1"}, timeout=3)
            if r.status_code != 200:
                return None
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = INTRUSOS_DIR / f"intruso_{ts}.jpg"
            out.write_bytes(r.content)
            return out
        except Exception:
            return None

    def _get_rec_status(self):
        r = self._http("GET", f"{RECOGNITION_URL}/internal/status")
        r.raise_for_status()
        return r.json()

    def _get_user_policy(self, username):
        r = self._http("GET", f"{AUTH_URL}/internal/user/{username}")
        r.raise_for_status()
        return (r.json() or {}).get("user", {})

    def start_scan(self):
        with self.lock:
            self.system_open = False
            self.current_user = None
            self.current_role = None
            self.current_confidence = None
            self.pending_2fa_user = None
            self.pending_2fa_expires_at = 0.0
        self._http("POST", f"{RECOGNITION_URL}/internal/start_scan")
        self._notify_device("Esperando...", led_on=False)
        self._log("Escaneo iniciado", "info")

    def reset(self):
        with self.lock:
            self.system_open = False
            self.current_user = None
            self.current_role = None
            self.current_confidence = None
            self.pending_2fa_user = None
            self.pending_2fa_expires_at = 0.0
            self.security_lock_until = 0.0
        self._http("POST", f"{RECOGNITION_URL}/internal/reset")
        self._notify_device("Esperando...", led_on=False)
        self._log("Sistema reiniciado", "warn")

    def verify_2fa(self, code):
        with self.lock:
            user = self.pending_2fa_user
            if not user:
                return False, "No hay verificacion 2FA pendiente"
            if time.time() > self.pending_2fa_expires_at:
                self.pending_2fa_user = None
                return False, "Codigo expirado"

        r = self._http("POST", f"{AUTH_URL}/internal/verify_2fa", json={"username": user, "code": code})
        data = r.json() if r.content else {}
        if r.status_code >= 300 or not data.get("ok"):
            self._register_metric("intento_2fa_fallido", 1.0, "conteo", {"evento": "2FA_FALLIDO", "persona": user})
            with self.lock:
                self.twofa_fail_count += 1
            PDP_TWOFA_EVENTS_TOTAL.labels(resultado="fallido").inc()
            self._notify_n8n("2fa_fallido", {"persona": user})
            return False, data.get("message", "Codigo invalido")

        with self.lock:
            self.pending_2fa_user = None
            self.two_fa_trusted_until[user] = time.time() + TWO_FA_TRUST_SECONDS
            self.system_open = True
            self.current_user = user
            current_confidence = self.current_confidence
            rec_snapshot = dict(self.last_rec_snapshot or {})
            self.twofa_ok_count += 1
        self._notify_device(f"Bienvenido, {user}!", led_on=True)
        self._register_event("ACCESO_CONCEDIDO", user, None if current_confidence is None else float(current_confidence))
        self._register_metric("intento_acceso_total", 1.0, "conteo", {"evento": "ACCESO_CONCEDIDO", "persona": user})
        self._register_metric("acceso_concedido", 1.0, "conteo", {"evento": "ACCESO_CONCEDIDO", "persona": user})
        if current_confidence is not None:
            self._register_metric("confianza_biometrica", float(current_confidence), "porcentaje", {"evento": "ACCESO_CONCEDIDO", "persona": user})
        self._register_camera_event_metrics(rec_snapshot, "ACCESO_CONCEDIDO", user)
        self._notify_n8n("2fa_exitoso", {"persona": user})
        self._log(f"2FA valido para {user}", "ok")
        PDP_TWOFA_EVENTS_TOTAL.labels(resultado="exitoso").inc()
        return True, "2FA verificado"

    def status(self):
        now = time.time()
        rec = self._get_rec_status()
        with self.lock:
            self.last_rec_snapshot = dict(rec or {})
        self._emit_snapshot_metrics()

        with self.lock:
            if now < self.security_lock_until:
                return {
                    **rec,
                    "state": "denied",
                    "scan_active": rec.get("scan_active", False),
                    "system_open": False,
                    "current_user": None,
                    "current_role": None,
                    "arduino_text": "Bloqueo temporal activo",
                    "led_on": True,
                    "security_locked": True,
                    "security_lock_remaining": int(self.security_lock_until - now),
                    "plex_url": PLEX_URL,
                }

            if self.pending_2fa_user and now > self.pending_2fa_expires_at:
                self.pending_2fa_user = None

            state = rec.get("state", "idle")
            candidate = rec.get("current_candidate")
            confidence = rec.get("confidence")
            unknown_seconds = float(rec.get("unknown_seconds", 0.0) or 0.0)

            if rec.get("scan_active") and state == "detected" and candidate and not self.system_open:
                policy = self._get_user_policy(candidate)
                if not policy.get("active", True):
                    state = "denied"
                    self._notify_device("Usuario inactivo", led_on=True)
                    self._log(f"Intento bloqueado: usuario inactivo ({candidate})", "err")
                elif policy.get("requires_2fa", True) and now > self.two_fa_trusted_until.get(candidate, 0.0):
                    self.pending_2fa_user = candidate
                    self.pending_2fa_expires_at = now + TWO_FA_GRACE_SECONDS
                    state = "awaiting_2fa"
                    self.current_user = candidate
                    self.current_role = policy.get("role", "empleado")
                    self.current_confidence = confidence
                    self._notify_device("Confirma 2FA en celular", led_on=True)
                else:
                    self.system_open = True
                    self.current_user = candidate
                    self.current_role = policy.get("role", "empleado")
                    self.current_confidence = confidence
                    self._notify_device(f"Bienvenido, {candidate}!", led_on=True)
                    self._register_event("ACCESO_CONCEDIDO", candidate, None)
                    self._register_metric("intento_acceso_total", 1.0, "conteo", {"evento": "ACCESO_CONCEDIDO", "persona": candidate})
                    self._register_metric("acceso_concedido", 1.0, "conteo", {"evento": "ACCESO_CONCEDIDO", "persona": candidate})
                    if confidence is not None:
                        self._register_metric("confianza_biometrica", float(confidence), "porcentaje", {"evento": "ACCESO_CONCEDIDO", "persona": candidate})
                    self._register_camera_event_metrics(rec, "ACCESO_CONCEDIDO", candidate)
                    self._notify_n8n("acceso_concedido", {"persona": candidate, "confidence": confidence})
                    self._log(f"Acceso concedido: {candidate}", "ok")
                    state = "detected"

            if rec.get("scan_active") and state == "denied" and unknown_seconds >= INTRUSO_SECONDS:
                if now - self.last_intruso_capture >= INTRUSO_COOLDOWN:
                    snap = self._capture_intruso()
                    self._register_event("ACCESO_DENEGADO", "Desconocido", None)
                    self._register_metric("intento_acceso_total", 1.0, "conteo", {"evento": "ACCESO_DENEGADO", "persona": "Desconocido"})
                    self._register_metric("acceso_denegado", 1.0, "conteo", {"evento": "ACCESO_DENEGADO", "persona": "Desconocido"})
                    self._register_camera_event_metrics(rec, "ACCESO_DENEGADO", "Desconocido")
                    payload = {"archivo": snap.name if snap else None, "unknown_seconds": unknown_seconds}
                    self._notify_n8n("intruso_detectado", payload)
                    self._log(f"Intruso detectado {payload['archivo'] or ''}".strip(), "err")
                    self.last_intruso_capture = now
                    PDP_INTRUSOS_TOTAL.inc()

            if not rec.get("scan_active"):
                self.system_open = False
                self.current_user = None
                self.current_role = None
                self.current_confidence = None

            if self.pending_2fa_user:
                state = "awaiting_2fa"
                display_user = self.pending_2fa_user
                display_conf = self.current_confidence
            else:
                display_user = self.current_user if self.system_open else candidate
                display_conf = self.current_confidence if self.system_open else confidence

            return {
                **rec,
                "state": state,
                "system_open": bool(self.system_open),
                "current_user": display_user,
                "current_role": self.current_role,
                "confidence": display_conf,
                "two_fa_user": self.pending_2fa_user,
                "two_fa_expires_in": max(0, int(self.pending_2fa_expires_at - now)) if self.pending_2fa_user else 0,
                "security_locked": False,
                "security_lock_remaining": 0,
                "plex_url": PLEX_URL,
                "arduino_text": f"Bienvenido, {self.current_user}!" if self.system_open and self.current_user else ("Confirma 2FA en celular" if self.pending_2fa_user else "Esperando..."),
                "led_on": bool(self.system_open or self.pending_2fa_user),
                "arduino_connected": True,
            }

    def get_logs(self, limit=120):
        return list(self.logs)[:limit]

    def get_reportes(self):
        out = {"total": 0, "concedidos": 0, "denegados": 0, "hoy_concedidos": 0, "hoy_denegados": 0, "ultimas_24h": 0}
        with psycopg2.connect(DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM access_logs")
                out["total"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE evento='ACCESO_CONCEDIDO'")
                out["concedidos"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE evento='ACCESO_DENEGADO'")
                out["denegados"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE evento='ACCESO_CONCEDIDO' AND fecha_hora::date = CURRENT_DATE")
                out["hoy_concedidos"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE evento='ACCESO_DENEGADO' AND fecha_hora::date = CURRENT_DATE")
                out["hoy_denegados"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE fecha_hora >= NOW() - INTERVAL '24 hours'")
                out["ultimas_24h"] = int(cur.fetchone()[0] or 0)
        return out

    def get_user_activity(self, username: str, limit=30):
        uname = (username or "").strip()
        if not uname:
            return {"ok": False, "error": "username requerido"}

        profile = {"username": uname, "role": "empleado", "active": True, "requires_2fa": True}
        try:
            r = self._http("GET", f"{AUTH_URL}/internal/user/{uname}", timeout=4)
            if r.status_code < 300:
                profile = (r.json() or {}).get("user", profile)
        except Exception:
            pass

        stats = {
            "total_eventos": 0,
            "concedidos": 0,
            "denegados": 0,
            "hoy_concedidos": 0,
            "hoy_denegados": 0,
            "ultimo_evento": None,
        }
        recent = []
        with psycopg2.connect(DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE persona = %s", (uname,))
                stats["total_eventos"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE persona = %s AND evento = 'ACCESO_CONCEDIDO'", (uname,))
                stats["concedidos"] = int(cur.fetchone()[0] or 0)
                cur.execute("SELECT COUNT(*) FROM access_logs WHERE persona = %s AND evento = 'ACCESO_DENEGADO'", (uname,))
                stats["denegados"] = int(cur.fetchone()[0] or 0)
                cur.execute(
                    "SELECT COUNT(*) FROM access_logs WHERE persona = %s AND evento = 'ACCESO_CONCEDIDO' AND fecha_hora::date = CURRENT_DATE",
                    (uname,),
                )
                stats["hoy_concedidos"] = int(cur.fetchone()[0] or 0)
                cur.execute(
                    "SELECT COUNT(*) FROM access_logs WHERE persona = %s AND evento = 'ACCESO_DENEGADO' AND fecha_hora::date = CURRENT_DATE",
                    (uname,),
                )
                stats["hoy_denegados"] = int(cur.fetchone()[0] or 0)
                cur.execute(
                    "SELECT fecha_hora, evento, distancia FROM access_logs WHERE persona = %s ORDER BY fecha_hora DESC LIMIT %s",
                    (uname, max(1, min(int(limit), 200))),
                )
                rows = cur.fetchall()
                for dt, evento, distancia in rows:
                    if stats["ultimo_evento"] is None:
                        stats["ultimo_evento"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                    recent.append(
                        {
                            "fecha_hora": dt.strftime("%Y-%m-%d %H:%M:%S"),
                            "evento": evento,
                            "distancia": None if distancia is None else float(distancia),
                        }
                    )

        return {
            "ok": True,
            "profile": profile,
            "stats": stats,
            "recent_logs": recent,
            "photo_url": f"/api/users/{uname}/photo",
        }

    def list_intrusos(self):
        return [p.name for p in sorted(INTRUSOS_DIR.glob("intruso_*.jpg"), reverse=True)]

    def _table_columns(self, table, conn=None):
        if table in self._table_columns_cache:
            return self._table_columns_cache[table]

        def _read_cols(c):
            with c.cursor() as cur:
                cur.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema='public' AND table_name=%s
                    """,
                    (table,),
                )
                return {r[0] for r in cur.fetchall()}

        if conn is not None:
            cols = _read_cols(conn)
        else:
            with psycopg2.connect(DB_URL) as c:
                cols = _read_cols(c)
        self._table_columns_cache[table] = cols
        return cols

    def _fetch_metric_rows(self, table, from_dt=None, to_dt=None, metrica=None, limit=1000):
        cols = self._table_columns(table)
        ts_col = "ts" if "ts" in cols else "fecha_hora"
        select_cols = []
        if "id" in cols:
            select_cols.append("id")
        select_cols.append(f"{ts_col} AS ts")
        if "metrica" in cols:
            select_cols.append("metrica")
        if "valor" in cols:
            select_cols.append("valor")
        if "unidad" in cols:
            select_cols.append("unidad")
        if "etiquetas" in cols:
            select_cols.append("etiquetas")
        if "origen" in cols:
            select_cols.append("origen")
        if "dimension_1" in cols:
            select_cols.append("dimension_1")
        if "dimension_2" in cols:
            select_cols.append("dimension_2")
        if "notas" in cols:
            select_cols.append("notas")

        where = ["TRUE"]
        params = []
        if from_dt:
            where.append(f"{ts_col} >= %s")
            params.append(from_dt)
        if to_dt:
            where.append(f"{ts_col} <= %s")
            params.append(to_dt)
        if metrica:
            where.append("metrica = %s")
            params.append(metrica)
        params.append(limit)
        q = f"SELECT {', '.join(select_cols)} FROM {table} WHERE {' AND '.join(where)} ORDER BY {ts_col} DESC LIMIT %s"
        rows = []
        with psycopg2.connect(DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(q, tuple(params))
                cols = [d[0] for d in cur.description]
                for r in cur.fetchall():
                    item = dict(zip(cols, r))
                    if isinstance(item.get("ts"), datetime):
                        item["ts"] = item["ts"].strftime("%Y-%m-%d %H:%M:%S")
                    rows.append(item)
        return rows

    def metricas(self, clean=False, from_dt=None, to_dt=None, metrica=None, limit=1000):
        table = "metricas_clean" if clean else "metricas_raw"
        rows = self._fetch_metric_rows(table, from_dt, to_dt, metrica, limit)
        return {"count": len(rows), "items": rows}

    def metricas_live(self):
        with self.lock:
            cache = json.loads(json.dumps(self.live_cache))
            hist = {
                "times": list(self.live_history["times"]),
                "pct_concedidos": list(self.live_history["pct_concedidos"]),
                "pct_denegados": list(self.live_history["pct_denegados"]),
                "pct_2fa_fail": list(self.live_history["pct_2fa_fail"]),
            }
        return {"ok": True, "cache": cache, "history": hist}


app = Flask(__name__)
engine = AccessEngine()


@app.before_request
def _metrics_before_request():
    g._req_start = perf_counter()


@app.after_request
def _metrics_after_request(response):
    try:
        endpoint = (request.url_rule.rule if request.url_rule is not None else request.path) or "unknown"
        method = request.method or "GET"
        status = str(response.status_code)
        HTTP_REQUESTS_TOTAL.labels(endpoint=endpoint, method=method, status=status).inc()
        started = getattr(g, "_req_start", None)
        if started is not None:
            elapsed = max(0.0, perf_counter() - started)
            HTTP_REQUEST_LATENCY_SECONDS.labels(endpoint=endpoint, method=method).observe(elapsed)
    except Exception:
        pass
    return response


def _metric_filters():
    from_dt = request.args.get("from") or None
    to_dt = request.args.get("to") or None
    metrica = (request.args.get("metrica") or "").strip() or None
    try:
        limit = int(request.args.get("limit", "1000"))
    except ValueError:
        limit = 1000
    return from_dt, to_dt, metrica, max(1, min(limit, 10000))


def _csv_response(rows, filename):
    out = io.StringIO()
    if rows:
        writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        writer = csv.writer(out)
        writer.writerow(["sin_datos"])
    return Response(out.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/metrics")
def metrics():
    engine._emit_snapshot_metrics()
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


@app.get("/api/status")
def api_status():
    return jsonify(engine.status())


@app.get("/api/logs")
def api_logs():
    try:
        limit = int(request.args.get("limit", "120"))
    except ValueError:
        limit = 120
    return jsonify({"logs": engine.get_logs(limit=max(1, min(500, limit)))})


@app.get("/api/users")
def api_users():
    r = requests.get(f"{RECOGNITION_URL}/internal/users", timeout=3)
    return jsonify(r.json())


@app.post("/api/users")
def api_add_user():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{RECOGNITION_URL}/internal/users", json=payload, timeout=5)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.delete("/api/users/<name>")
def api_delete_user(name):
    r = requests.delete(f"{RECOGNITION_URL}/internal/users/{name}", timeout=5)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.post("/api/start_scan")
def api_start_scan():
    engine.start_scan()
    return jsonify({"ok": True})


@app.post("/api/reset")
def api_reset():
    engine.reset()
    return jsonify({"ok": True})


@app.post("/api/mesh")
def api_mesh():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{RECOGNITION_URL}/internal/mesh", json=payload, timeout=3)
    return jsonify(r.json())


@app.post("/api/camera")
def api_camera():
    payload = request.get_json(silent=True) or {}
    r = requests.post(f"{RECOGNITION_URL}/internal/camera", json={"enabled": bool(payload.get("enabled", False))}, timeout=3)
    return jsonify(r.json())


@app.post("/api/reload_faces")
def api_reload_faces():
    r = requests.post(f"{RECOGNITION_URL}/internal/reload_faces", timeout=20)
    return jsonify(r.json())


@app.get("/api/intrusos")
def api_intrusos():
    return jsonify({"files": engine.list_intrusos()})


@app.get("/api/intrusos/<path:filename>")
def api_intruso_file(filename):
    safe_name = Path(filename).name
    if not safe_name.startswith("intruso_") or not safe_name.lower().endswith(".jpg"):
        return jsonify({"ok": False, "error": "Archivo invalido"}), 400
    target = (INTRUSOS_DIR / safe_name).resolve()
    try:
        target.relative_to(INTRUSOS_DIR.resolve())
    except Exception:
        return jsonify({"ok": False, "error": "Ruta invalida"}), 400
    if not target.exists() or not target.is_file():
        return jsonify({"ok": False, "error": "Archivo no encontrado"}), 404
    return send_file(target, mimetype="image/jpeg")


@app.get("/api/reportes")
def api_reportes():
    engine._emit_snapshot_metrics()
    return jsonify(engine.get_reportes())


@app.get("/api/metricas/raw")
def api_metricas_raw():
    engine._emit_snapshot_metrics()
    f, t, m, l = _metric_filters()
    return jsonify(engine.metricas(clean=False, from_dt=f, to_dt=t, metrica=m, limit=l))


@app.get("/api/metricas/raw.csv")
def api_metricas_raw_csv():
    engine._emit_snapshot_metrics()
    f, t, m, l = _metric_filters()
    data = engine.metricas(clean=False, from_dt=f, to_dt=t, metrica=m, limit=l)
    return _csv_response(data.get("items", []), "metricas_raw.csv")


@app.get("/api/metricas/clean")
def api_metricas_clean():
    engine._emit_snapshot_metrics()
    f, t, m, l = _metric_filters()
    return jsonify(engine.metricas(clean=True, from_dt=f, to_dt=t, metrica=m, limit=l))


@app.get("/api/metricas/clean.csv")
def api_metricas_clean_csv():
    engine._emit_snapshot_metrics()
    f, t, m, l = _metric_filters()
    data = engine.metricas(clean=True, from_dt=f, to_dt=t, metrica=m, limit=l)
    return _csv_response(data.get("items", []), "metricas_clean.csv")


@app.get("/api/metricas/resumen")
def api_metricas_resumen():
    engine._emit_snapshot_metrics()
    with psycopg2.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM metricas_raw")
            raw_total = int(cur.fetchone()[0] or 0)
            cur.execute("SELECT COUNT(*) FROM metricas_clean")
            clean_total = int(cur.fetchone()[0] or 0)
    return jsonify({"raw_total": raw_total, "clean_total": clean_total})


@app.get("/api/metricas/live")
def api_metricas_live():
    engine._emit_snapshot_metrics()
    return jsonify(engine.metricas_live())


@app.post("/api/2fa/verify")
def api_verify_2fa():
    payload = request.get_json(silent=True) or {}
    ok, msg = engine.verify_2fa(str(payload.get("code", "")))
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.get("/api/security/panel")
def api_security_panel():
    now = time.time()
    return jsonify({
        "security_locked": now < engine.security_lock_until,
        "security_lock_remaining": max(0, int(engine.security_lock_until - now)),
        "critical_alerts": 0,
        "incidents_24h": 0,
    })


# Proxy auth endpoints used by UI/admin
@app.get("/api/2fa/setup")
def api_2fa_setup():
    r = requests.get(f"{AUTH_URL}/api/2fa/setup", params=request.args, timeout=5)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.get("/api/2fa/qr")
def api_2fa_qr():
    r = requests.get(f"{AUTH_URL}/api/2fa/qr", params=request.args, timeout=10)
    ctype = r.headers.get("Content-Type", "image/png")
    return Response(r.content, status=r.status_code, mimetype=ctype)


@app.get("/api/admin/users_security")
def api_admin_list():
    headers = {"X-Admin-Token": request.headers.get("X-Admin-Token", "")}
    r = requests.get(f"{AUTH_URL}/api/admin/users_security", params=request.args, headers=headers, timeout=8)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.post("/api/admin/users_security/enroll")
def api_admin_enroll():
    headers = {"X-Admin-Token": request.headers.get("X-Admin-Token", "")}
    r = requests.post(f"{AUTH_URL}/api/admin/users_security/enroll", json=request.get_json(silent=True) or {}, params=request.args, headers=headers, timeout=8)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.post("/api/admin/users_security/<username>/active")
def api_admin_active(username):
    headers = {"X-Admin-Token": request.headers.get("X-Admin-Token", "")}
    r = requests.post(f"{AUTH_URL}/api/admin/users_security/{username}/active", json=request.get_json(silent=True) or {}, params=request.args, headers=headers, timeout=8)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.post("/api/admin/users_security/<username>/role")
def api_admin_role(username):
    headers = {"X-Admin-Token": request.headers.get("X-Admin-Token", "")}
    r = requests.post(f"{AUTH_URL}/api/admin/users_security/{username}/role", json=request.get_json(silent=True) or {}, params=request.args, headers=headers, timeout=8)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.post("/api/admin/users_security/<username>/rotate_2fa")
def api_admin_rotate(username):
    headers = {"X-Admin-Token": request.headers.get("X-Admin-Token", "")}
    r = requests.post(f"{AUTH_URL}/api/admin/users_security/{username}/rotate_2fa", json=request.get_json(silent=True) or {}, params=request.args, headers=headers, timeout=8)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.delete("/api/admin/users_security/<username>")
def api_admin_delete(username):
    headers = {"X-Admin-Token": request.headers.get("X-Admin-Token", "")}
    r = requests.delete(f"{AUTH_URL}/api/admin/users_security/{username}", params=request.args, headers=headers, timeout=8)
    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.get("/api/admin/users_security/<username>/activity")
def api_admin_user_activity(username):
    token = request.headers.get("X-Admin-Token", "")
    if not engine._is_admin_token_valid(token):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    try:
        limit = int(request.args.get("limit", "30"))
    except ValueError:
        limit = 30
    return jsonify(engine.get_user_activity(username, limit=limit))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8103, debug=False)
