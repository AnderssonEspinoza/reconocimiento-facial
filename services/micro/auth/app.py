import base64
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
import urllib.parse

import psycopg2
import qrcode
from flask import Flask, Response, jsonify, request

DB_URL = os.getenv("DB_URL", "postgresql://faceaccess:faceaccess@postgres-service:5432/faceaccess")
ADMIN_TOKEN = os.getenv("TWO_FA_ADMIN_TOKEN", "CAMBIA_ESTE_TOKEN_ADMIN")
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "PROYECTO_PDP")
TOTP_DIGITS = int(os.getenv("TOTP_DIGITS", "6"))
TOTP_PERIOD = int(os.getenv("TOTP_PERIOD", "30"))

app = Flask(__name__)


def db_exec(query, params=(), fetch=False, many=False):
    with psycopg2.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            if many:
                cur.executemany(query, params)
            else:
                cur.execute(query, params)
            if fetch:
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, r)) for r in cur.fetchall()]
        conn.commit()
    return []


def ensure_schema():
    db_exec(
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


def is_admin(req):
    token = req.headers.get("X-Admin-Token") or req.args.get("token") or ""
    return bool(token) and token == ADMIN_TOKEN


def norm_user(name: str):
    return (name or "").strip()


def mask_secret(secret: str):
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret)-8)}{secret[-4:]}"


def random_totp_secret():
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii").replace("=", "")


def totp_code(secret: str, for_time: int):
    counter = int(for_time // TOTP_PERIOD)
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7FFFFFFF) % (10**TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str):
    code = (code or "").strip()
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    now = int(time.time())
    for drift in (-1, 0, 1):
        if totp_code(secret, now + drift * TOTP_PERIOD) == code:
            return True
    return False


def otpauth_uri(username: str, secret: str):
    label = urllib.parse.quote(f"{TOTP_ISSUER}:{username}")
    issuer = urllib.parse.quote(TOTP_ISSUER)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/internal/user/<username>")
def internal_user(username):
    uname = norm_user(username)
    rows = db_exec("SELECT username, role, active, requires_2fa, totp_secret FROM users_security WHERE username=%s", (uname,), fetch=True)
    if not rows:
        return jsonify({"ok": True, "user": {"username": uname, "role": "empleado", "active": True, "requires_2fa": True, "exists": False}})
    u = rows[0]
    u["exists"] = True
    u["totp_secret_masked"] = mask_secret(u.get("totp_secret") or "")
    u.pop("totp_secret", None)
    return jsonify({"ok": True, "user": u})


@app.post("/internal/verify_2fa")
def internal_verify_2fa():
    payload = request.get_json(silent=True) or {}
    username = norm_user(payload.get("username", ""))
    code = str(payload.get("code", "")).strip()
    rows = db_exec("SELECT username, active, requires_2fa, totp_secret FROM users_security WHERE username=%s", (username,), fetch=True)
    if not rows:
        return jsonify({"ok": False, "message": "Usuario no encontrado"}), 404
    user = rows[0]
    if not user.get("active", True):
        return jsonify({"ok": False, "message": "Usuario inactivo"}), 403
    if not user.get("requires_2fa", True):
        return jsonify({"ok": True, "message": "2FA no requerido"})
    secret = user.get("totp_secret")
    if not secret:
        return jsonify({"ok": False, "message": "Usuario sin secreto 2FA"}), 400
    if not verify_totp(secret, code):
        return jsonify({"ok": False, "message": "Codigo 2FA invalido"}), 401
    return jsonify({"ok": True, "message": "2FA valido"})


@app.get("/api/2fa/setup")
def api_2fa_setup():
    username = norm_user(request.args.get("username", "")) or None
    token_ok = is_admin(request)
    data = {
        "enabled": True,
        "issuer": TOTP_ISSUER,
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD,
        "username": username,
        "admin_access": token_ok,
        "qr_endpoint": None,
    }
    if token_ok and username:
        data["qr_endpoint"] = f"/api/2fa/qr?token={urllib.parse.quote(ADMIN_TOKEN)}&username={urllib.parse.quote(username)}"
    return jsonify(data)


@app.get("/api/2fa/qr")
def api_2fa_qr():
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token requerido"}), 403
    username = norm_user(request.args.get("username", ""))
    if not username:
        return jsonify({"ok": False, "error": "username requerido"}), 400

    rows = db_exec("SELECT username, totp_secret FROM users_security WHERE username=%s", (username,), fetch=True)
    if not rows:
        return jsonify({"ok": False, "error": "Usuario no encontrado"}), 404

    secret = rows[0].get("totp_secret")
    if not secret:
        secret = random_totp_secret()
        db_exec("UPDATE users_security SET totp_secret=%s, updated_at=NOW() WHERE username=%s", (secret, username))

    uri = otpauth_uri(username, secret)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(buf.getvalue(), mimetype="image/png")


@app.get("/api/admin/users_security")
def api_admin_list():
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    rows = db_exec("SELECT username, role, active, requires_2fa, totp_secret, created_at, updated_at FROM users_security ORDER BY username", fetch=True)
    for r in rows:
        r["totp_secret_masked"] = mask_secret(r.get("totp_secret") or "")
        r.pop("totp_secret", None)
    return jsonify({"ok": True, "items": rows})


@app.post("/api/admin/users_security/enroll")
def api_admin_enroll():
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    p = request.get_json(silent=True) or {}
    username = norm_user(p.get("username", ""))
    if not username:
        return jsonify({"ok": False, "error": "username requerido"}), 400
    role = str(p.get("role", "empleado")).strip().lower() or "empleado"
    if role not in {"admin", "seguridad", "empleado", "visita"}:
        role = "empleado"
    requires_2fa = bool(p.get("requires_2fa", True))
    active = bool(p.get("active", True))
    secret = random_totp_secret() if requires_2fa else None

    db_exec(
        """
        INSERT INTO users_security(username, role, active, requires_2fa, totp_secret, created_at, updated_at)
        VALUES(%s,%s,%s,%s,%s,NOW(),NOW())
        ON CONFLICT (username)
        DO UPDATE SET role=EXCLUDED.role, active=EXCLUDED.active, requires_2fa=EXCLUDED.requires_2fa,
                      totp_secret=EXCLUDED.totp_secret, updated_at=NOW()
        """,
        (username, role, active, requires_2fa, secret),
    )
    return jsonify({"ok": True, "username": username, "role": role, "requires_2fa": requires_2fa, "active": active})


@app.post("/api/admin/users_security/<username>/active")
def api_admin_active(username):
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    p = request.get_json(silent=True) or {}
    active = bool(p.get("active", True))
    db_exec("UPDATE users_security SET active=%s, updated_at=NOW() WHERE username=%s", (active, norm_user(username)))
    return jsonify({"ok": True})


@app.post("/api/admin/users_security/<username>/role")
def api_admin_role(username):
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    p = request.get_json(silent=True) or {}
    role = str(p.get("role", "empleado")).strip().lower() or "empleado"
    if role not in {"admin", "seguridad", "empleado", "visita"}:
        role = "empleado"
    db_exec("UPDATE users_security SET role=%s, updated_at=NOW() WHERE username=%s", (role, norm_user(username)))
    return jsonify({"ok": True})


@app.post("/api/admin/users_security/<username>/rotate_2fa")
def api_admin_rotate(username):
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    uname = norm_user(username)
    secret = random_totp_secret()
    db_exec("UPDATE users_security SET totp_secret=%s, requires_2fa=TRUE, updated_at=NOW() WHERE username=%s", (secret, uname))
    qr_endpoint = f"/api/2fa/qr?token={urllib.parse.quote(ADMIN_TOKEN)}&username={urllib.parse.quote(uname)}"
    return jsonify({"ok": True, "username": uname, "qr_endpoint": qr_endpoint})


@app.delete("/api/admin/users_security/<username>")
def api_admin_delete(username):
    if not is_admin(request):
        return jsonify({"ok": False, "error": "Admin token invalido"}), 403
    uname = norm_user(username)
    db_exec("DELETE FROM users_security WHERE username=%s", (uname,))
    return jsonify({"ok": True, "username": uname})


if __name__ == "__main__":
    ensure_schema()
    app.run(host="0.0.0.0", port=8102, debug=False)
