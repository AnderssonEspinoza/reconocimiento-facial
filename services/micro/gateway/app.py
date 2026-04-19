import os

import requests
from flask import Flask, Response, request, send_file

ACCESS_URL = os.getenv("ACCESS_URL", "http://access-service:8103")
RECOGNITION_URL = os.getenv("RECOGNITION_URL", "http://recognition-service:8101")
ANALYTICS_URL = os.getenv("ANALYTICS_URL", "http://analytics-service:8104")
UI_FILE = os.getenv("UI_FILE", "/app/faceaccess.html")
ADMIN_UI_FILE = os.getenv("ADMIN_UI_FILE", "/app/admin.html")

app = Flask(__name__)


def proxy(method, base_url, path="", timeout=15, stream=False):
    url = f"{base_url}{path}"
    headers = {k: v for k, v in request.headers if k.lower() != "host"}
    kwargs = {
        "params": request.args,
        "headers": headers,
        "timeout": timeout,
        "stream": stream,
    }
    if request.method in {"POST", "PUT", "PATCH"}:
        if request.is_json:
            kwargs["json"] = request.get_json(silent=True)
        else:
            kwargs["data"] = request.get_data()
    resp = requests.request(method, url, **kwargs)

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    out_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

    if stream:
        return Response(resp.iter_content(chunk_size=8192), status=resp.status_code, headers=out_headers)
    return Response(resp.content, status=resp.status_code, headers=out_headers)


@app.get("/")
def home():
    return send_file(UI_FILE)


@app.get("/admin")
def admin():
    return send_file(ADMIN_UI_FILE)


@app.get("/video_feed")
def video_feed():
    return proxy("GET", RECOGNITION_URL, "/video_feed", timeout=60, stream=True)


@app.get("/api/users/<username>/photo")
def user_photo(username):
    return proxy("GET", RECOGNITION_URL, f"/internal/user_photo/{username}", timeout=20, stream=True)


@app.route("/api/analytics", methods=["GET"])
def analytics_root():
    return proxy("GET", ANALYTICS_URL, "/", timeout=20)


@app.route("/api/analytics/<path:rest>", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
def analytics_api(rest):
    return proxy(request.method, ANALYTICS_URL, f"/{rest}", timeout=20)


@app.route("/api/<path:rest>", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
def api(rest):
    return proxy(request.method, ACCESS_URL, f"/api/{rest}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
