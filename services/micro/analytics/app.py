import os
from typing import Dict, List

import pandas as pd
import requests
from flask import Flask, jsonify, request

ACCESS_API_URL = os.getenv("ACCESS_API_URL", "http://access-service:8103/api").rstrip("/")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8"))
DEFAULT_LIMIT = int(os.getenv("ANALYTICS_DEFAULT_LIMIT", "2500"))
MAX_LIMIT = int(os.getenv("ANALYTICS_MAX_LIMIT", "10000"))

app = Flask(__name__)


def _safe_limit(value):
    try:
        n = int(value)
    except Exception:
        n = DEFAULT_LIMIT
    return max(1, min(n, MAX_LIMIT))


def _fetch_json(path: str, params: Dict = None):
    url = f"{ACCESS_API_URL}/{path.lstrip('/')}"
    r = requests.get(url, params=params or {}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _fetch_reportes():
    return _fetch_json("reportes")


def _fetch_metricas_raw(limit: int):
    data = _fetch_json("metricas/raw", params={"limit": _safe_limit(limit)})
    return data.get("items", []) if isinstance(data, dict) else []


def _raw_df(limit: int):
    items = _fetch_metricas_raw(limit)
    if not items:
        return pd.DataFrame(columns=["ts", "metrica", "valor", "unidad", "etiquetas"])
    df = pd.DataFrame(items)
    if "ts" in df:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    else:
        df["ts"] = pd.NaT
    df = df.dropna(subset=["ts"])
    if "metrica" not in df:
        df["metrica"] = ""
    if "valor" not in df:
        df["valor"] = None
    if "etiquetas" not in df:
        df["etiquetas"] = None
    return df


def _etag_value(etiquetas, key, default=None):
    if isinstance(etiquetas, dict):
        return etiquetas.get(key, default)
    return default


def _access_events_df(df: pd.DataFrame):
    if df.empty:
        return df
    mask = df["metrica"].isin(["acceso_concedido", "acceso_denegado", "intento_acceso_total"])
    return df[mask].copy()


@app.get("/")
def root():
    return jsonify({"ok": True, "service": "analytics-service"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/dashboard/resumen")
def dashboard_resumen():
    limit = _safe_limit(request.args.get("limit", DEFAULT_LIMIT))
    rep = _fetch_reportes()
    df = _raw_df(limit)
    access_df = _access_events_df(df)

    per_hour = {}
    if not access_df.empty:
        per_hour = access_df.groupby(access_df["ts"].dt.hour).size().sort_values(ascending=False).head(6).astype(int).to_dict()
        per_hour = {str(k): int(v) for k, v in per_hour.items()}

    total = int(rep.get("total", 0) or 0)
    concedidos = int(rep.get("concedidos", 0) or 0)
    denegados = int(rep.get("denegados", 0) or 0)
    tasa_rec = (concedidos / total) if total > 0 else 0.0
    tasa_intr = (denegados / total) if total > 0 else 0.0

    return jsonify(
        {
            "ok": True,
            "total": total,
            "concedidos": concedidos,
            "denegados": denegados,
            "tasa_reconocimiento": float(tasa_rec),
            "tasa_intrusos": float(tasa_intr),
            "hoy_concedidos": int(rep.get("hoy_concedidos", 0) or 0),
            "hoy_denegados": int(rep.get("hoy_denegados", 0) or 0),
            "ultimas_24h": int(rep.get("ultimas_24h", 0) or 0),
            "horas_pico": per_hour,
            "fuente": {"access_api_url": ACCESS_API_URL, "limit_usado": limit},
        }
    )


@app.get("/kpi/resumen-general")
def kpi_resumen_general():
    rep = _fetch_reportes()
    total = int(rep.get("total", 0) or 0)
    concedidos = int(rep.get("concedidos", 0) or 0)
    denegados = int(rep.get("denegados", 0) or 0)
    return jsonify(
        {
            "total": total,
            "tasa_reconocimiento": float((concedidos / total) if total > 0 else 0.0),
            "tasa_intrusos": float((denegados / total) if total > 0 else 0.0),
        }
    )


@app.get("/kpi/tasa-reconocimiento")
def kpi_tasa_reconocimiento():
    rep = _fetch_reportes()
    total = int(rep.get("total", 0) or 0)
    concedidos = int(rep.get("concedidos", 0) or 0)
    return jsonify({"tasa": float((concedidos / total) if total > 0 else 0.0)})


@app.get("/kpi/tasa-intrusos")
def kpi_tasa_intrusos():
    rep = _fetch_reportes()
    total = int(rep.get("total", 0) or 0)
    denegados = int(rep.get("denegados", 0) or 0)
    return jsonify({"tasa": float((denegados / total) if total > 0 else 0.0)})


@app.get("/kpi/horas-pico")
def kpi_horas_pico():
    limit = _safe_limit(request.args.get("limit", DEFAULT_LIMIT))
    df = _access_events_df(_raw_df(limit))
    if df.empty:
        return jsonify({"horas": {}})
    series = df.groupby(df["ts"].dt.hour).size().sort_values(ascending=False).head(6)
    return jsonify({"horas": {str(k): int(v) for k, v in series.to_dict().items()}})


@app.get("/kpi/usuarios-top")
def kpi_usuarios_top():
    limit = _safe_limit(request.args.get("limit", DEFAULT_LIMIT))
    df = _raw_df(limit)
    if df.empty:
        return jsonify({"usuarios": {}})
    df = df[df["metrica"] == "acceso_concedido"].copy()
    if df.empty:
        return jsonify({"usuarios": {}})
    df["persona"] = df["etiquetas"].apply(lambda e: _etag_value(e, "persona", "Desconocido"))
    df = df[(df["persona"].notna()) & (df["persona"] != "Desconocido")]
    if df.empty:
        return jsonify({"usuarios": {}})
    top = df["persona"].value_counts().head(10)
    return jsonify({"usuarios": {str(k): int(v) for k, v in top.to_dict().items()}})


@app.get("/kpi/actividad-diaria")
def kpi_actividad_diaria():
    limit = _safe_limit(request.args.get("limit", DEFAULT_LIMIT))
    df = _access_events_df(_raw_df(limit))
    if df.empty:
        return jsonify({"dias": {}})
    by_day = df.groupby(df["ts"].dt.date).size().sort_index()
    return jsonify({"dias": {str(k): int(v) for k, v in by_day.to_dict().items()}})


@app.get("/kpi/trafico-red")
def kpi_trafico_red():
    limit = _safe_limit(request.args.get("limit", DEFAULT_LIMIT))
    df = _raw_df(limit)
    if df.empty:
        return jsonify({"servicios": [], "count": 0})
    red_df = df[df["metrica"].isin(["red_latencia_promedio", "red_tasa_error", "red_disponibilidad"])].copy()
    if red_df.empty:
        return jsonify({"servicios": [], "count": 0})

    red_df["servicio"] = red_df["etiquetas"].apply(lambda e: _etag_value(e, "servicio", "desconocido"))
    red_df["valor"] = pd.to_numeric(red_df["valor"], errors="coerce")
    red_df = red_df.dropna(subset=["valor"])
    red_df = red_df.sort_values("ts")

    services: List[Dict] = []
    for svc, grp in red_df.groupby("servicio"):
        lat = grp[grp["metrica"] == "red_latencia_promedio"]["valor"]
        err = grp[grp["metrica"] == "red_tasa_error"]["valor"]
        avail = grp[grp["metrica"] == "red_disponibilidad"]["valor"]
        services.append(
            {
                "servicio": str(svc),
                "latencia_ms": float(lat.iloc[-1]) if not lat.empty else None,
                "error_pct": float(err.iloc[-1]) if not err.empty else None,
                "disponibilidad_pct": float(avail.iloc[-1]) if not avail.empty else None,
            }
        )

    services = sorted(services, key=lambda x: x["servicio"])
    return jsonify({"servicios": services, "count": len(services)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8104, debug=False)
