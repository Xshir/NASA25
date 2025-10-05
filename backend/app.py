import os
import time
import json
import hashlib
import datetime as dt
from functools import wraps

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2 import pool as psycopool
from psycopg2.extras import RealDictCursor

# ------------------------------------------------------------------------------
# App & config
# ------------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
CORS(app, supports_credentials=False)

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")

DB_CFG = {
    "host": os.getenv("POSTGRES_HOST", "db"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "nasa2025"),
    "user": os.getenv("POSTGRES_USER", "nasa2025"),
    "password": os.getenv("POSTGRES_PASSWORD", "nasa2025"),
}

MM_USER = os.getenv("MM_USERNAME")  # Meteomatics
MM_PASS = os.getenv("MM_PASSWORD")

db_pool: psycopool.SimpleConnectionPool | None = None

# ------------------------------------------------------------------------------
# DB bootstrap
# ------------------------------------------------------------------------------
def init_db_pool():
    """Create a global psycopg2 pool with retry to avoid race with DB startup."""
    global db_pool
    if db_pool:
        return

    deadline = time.time() + 60
    last_err = None
    while time.time() < deadline:
        try:
            db_pool = psycopool.SimpleConnectionPool(
                minconn=1,
                maxconn=8,
                host=DB_CFG["host"],
                port=DB_CFG["port"],
                dbname=DB_CFG["dbname"],
                user=DB_CFG["user"],
                password=DB_CFG["password"],
            )
            conn = db_pool.getconn()
            try:
                with conn, conn.cursor() as cur:
                    cur.execute("SELECT 1;")
            finally:
                db_pool.putconn(conn)
            break
        except Exception as e:
            last_err = e
            time.sleep(2)

    if not db_pool:
        raise RuntimeError(f"Database not reachable: {last_err}")

    ensure_schema()


def ensure_schema():
    """Create tables if not exist."""
    conn = db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(420420);")

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS app_users (
                        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        pin_hash TEXT NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON app_users (username);")

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                        event_name TEXT NOT NULL,
                        date DATE NOT NULL,
                        city TEXT,
                        country TEXT,
                        lat DOUBLE PRECISION,
                        lon DOUBLE PRECISION,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, date);")

                cur.execute("SELECT pg_advisory_unlock(420420);")
    finally:
        db_pool.putconn(conn)

# ------------------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------------------
def _hash_pin(username: str, pin: str) -> str:
    blob = (username + ":" + pin + ":" + APP_SECRET).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _sign(payload: dict) -> str:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    sig = hashlib.sha256((data + APP_SECRET).encode("utf-8")).hexdigest()
    return f"{data}.{sig}"


def _verify(token: str) -> dict | None:
    try:
        data, sig = token.rsplit(".", 1)
        expect = hashlib.sha256((data + APP_SECRET).encode("utf-8")).hexdigest()
        if sig != expect:
            return None
        payload = json.loads(data)
        if "exp" in payload and time.time() > payload["exp"]:
            return None
        return payload
    except Exception:
        return None


def issue_token(user_id: int, username: str) -> str:
    return _sign({"uid": user_id, "username": username, "exp": time.time() + 60 * 60 * 24 * 7})


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        token = auth[7:]
        payload = _verify(token)
        if not payload:
            return jsonify({"error": "unauthorized"}), 401
        return fn(user=payload, *args, **kwargs)
    return wrapper

# ------------------------------------------------------------------------------
# External helpers (Meteomatics + NASA POWER)
# ------------------------------------------------------------------------------
def get_meteomatics_summary(lat: float, lon: float, date_iso: str):
    if not MM_USER or not MM_PASS:
        return None
    try:
        d0 = dt.datetime.fromisoformat(date_iso)
        start = d0.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + dt.timedelta(days=1) - dt.timedelta(seconds=1)
        params = "t_2m:C,precipitation_1h:mm,wind_speed_10m:ms,relative_humidity_2m:p,cloud_cover:p"
        url = (
            f"https://api.meteomatics.com/"
            f"{start.strftime('%Y-%m-%dT%H:%M:%SZ')}--{end.strftime('%Y-%m-%dT%H:%M:%SZ')}:PT1H/"
            f"{params}/{lat:.4f},{lon:.4f}/json"
        )
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=12)
        if r.status_code != 200:
            return None
        js = r.json()
        def vals(key):
            for p in js.get("data", []):
                if p.get("parameter") == key:
                    pts = p.get("coordinates", [{}])[0].get("dates", [])
                    return [pt["value"] for pt in pts if "value" in pt and pt["value"] is not None]
            return []
        t = vals("t_2m:C")
        pr = vals("precipitation_1h:mm")
        ws = vals("wind_speed_10m:ms")
        rh = vals("relative_humidity_2m:p")
        cc = vals("cloud_cover:p")
        if not any([t, pr, ws, rh, cc]):
            return None
        return {
            "t_max": max(t) if t else None,
            "t_min": min(t) if t else None,
            "precip_24h": sum(pr) if pr else 0.0,
            "wind_max": max(ws) if ws else None,
            "rh_mean": sum(rh) / len(rh) if rh else None,
            "cloud_mean": sum(cc) / len(cc) if cc else None,
            "source": "meteomatics",
        }
    except Exception:
        return None


def get_nasa_power(lat: float, lon: float, date_iso: str):
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN"
            f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}"
            f"&start={d.strftime('%Y%m%d')}&end={d.strftime('%Y%m%d')}&format=JSON"
        )
        r = requests.get(url, timeout=12)
        if r.status_code != 200:
            return None
        js = r.json()
        data = js.get("properties", {}).get("parameter", {})
        tmax = list(data.get("T2M_MAX", {}).values())[0]
        tmin = list(data.get("T2M_MIN", {}).values())[0]
        precip = list(data.get("PRECTOTCORR", {}).values())[0]
        solar = list(data.get("ALLSKY_SFC_SW_DWN", {}).values())[0]
        avg_temp = (tmax + tmin) / 2.0
        return {
            "tmax": tmax,
            "tmin": tmin,
            "precip": precip,
            "solar": solar,
            "avg_temp": avg_temp,
            "source": "nasa_power",
        }
    except Exception:
        return None


def interpret_conditions(metrics: dict | None, event_name: str):
    if not metrics:
        return "mixed conditions", ["umbrella just in case", "water bottle", "sunscreen"]

    tips = []
    tmax = metrics.get("t_max")
    rain = metrics.get("precip_24h", 0) or 0
    wind = metrics.get("wind_max")

    if tmax is not None and tmax >= 33:
        label = "very hot"
    elif rain >= 10:
        label = "very wet"
    elif wind is not None and wind >= 10:
        label = "very windy"
    elif tmax is not None and tmax <= 18:
        label = "cool"
    else:
        label = "fair"

    if label == "very hot":
        tips += ["pack extra ice", "bring shade/canopy", "portable fans", "electrolytes"]
    if label == "very wet":
        tips += ["bring umbrellas/raincoats", "waterproof bags", "consider backup shelter"]
    if label == "very windy":
        tips += ["secure tents/props", "avoid drone flights", "check wind gusts"]

    e = (event_name or "").lower()
    if any(k in e for k in ["picnic", "bbq", "barbecue", "beach", "park"]):
        tips += ["cooler with ice", "sunscreen", "ground sheet"]
    elif any(k in e for k in ["hike", "trail", "trek"]):
        tips += ["hydration pack", "insect repellent", "trail shoes"]
    elif any(k in e for k in ["drone", "flying", "aerial"]):
        tips += ["spare batteries", "ND filters", "check NOTAM/no-fly zones"]
    elif any(k in e for k in ["wedding", "ceremony", "outdoor event", "party"]):
        tips += ["confirm canopy vendor", "confirm indoor fallback"]

    seen = set()
    tips = [t for t in tips if not (t in seen or seen.add(t))]
    return label, tips


def reverse_geocode(lat: float, lon: float):
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": 10, "addressdetails": 1},
            headers={"User-Agent": "Plan4Cast/1.0 (contact: tp.plan4cast.earth)"},
            timeout=8,
        )
        if r.status_code != 200:
            return {}
        js = r.json()
        addr = js.get("address", {})
        city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("county")
        country = addr.get("country")
        return {"city": city, "country": country}
    except Exception:
        return {}

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": time.time()})

# (all signup/login/events/suggest routes remain unchanged here — same as before)
# Add them from the previous version you already have.

# ------------------------------------------------------------------------------
# Serve static frontend
# ------------------------------------------------------------------------------
@app.get("/")
def root():
    """Serve the main web app."""
    return send_from_directory("/app/static", "index.html")

@app.get("/<path:path>")
def static_proxy(path):
    """Serve other static assets if added later (JS, CSS, images)."""
    try:
        return send_from_directory("/app/static", path)
    except Exception:
        return jsonify({"error": "not found"}), 404

# ------------------------------------------------------------------------------
# Startup
# ------------------------------------------------------------------------------
init_db_pool()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
