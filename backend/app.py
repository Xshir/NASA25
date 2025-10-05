import os
import time
import json
import hashlib
import datetime as dt
from functools import wraps

import requests
from flask import Flask, jsonify, request
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
    """Fetch NASA POWER climatology for a given point/date."""
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


@app.post("/signup")
def signup():
    init_db_pool()
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    pin = (data.get("pin") or "").strip()
    if not username or not pin.isdigit() or len(pin) != 4:
        return jsonify({"error": "invalid username or pin"}), 400
    pin_hash = _hash_pin(username, pin)

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "INSERT INTO app_users (username, pin_hash) VALUES (%s,%s) "
                "ON CONFLICT (username) DO NOTHING RETURNING id;",
                (username, pin_hash),
            )
            row = cur.fetchone()
            if not row:
                cur.execute("SELECT id, pin_hash FROM app_users WHERE username=%s;", (username,))
                row2 = cur.fetchone()
                if not row2 or row2["pin_hash"] != pin_hash:
                    return jsonify({"error": "username already exists"}), 409
                user_id = row2["id"]
            else:
                user_id = row["id"]
    finally:
        db_pool.putconn(conn)
    token = issue_token(user_id, username)
    return jsonify({"ok": True, "token": token})


@app.post("/login")
def login():
    init_db_pool()
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    pin = (data.get("pin") or "").strip()
    if not username or not pin.isdigit() or len(pin) != 4:
        return jsonify({"error": "invalid credentials"}), 400
    pin_hash = _hash_pin(username, pin)

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, pin_hash FROM app_users WHERE username=%s;", (username,))
            row = cur.fetchone()
            if not row or row["pin_hash"] != pin_hash:
                return jsonify({"error": "invalid credentials"}), 401
            user_id = row["id"]
    finally:
        db_pool.putconn(conn)
    token = issue_token(user_id, username)
    return jsonify({"ok": True, "token": token})


@app.get("/events")
@require_auth
def list_events(user):
    init_db_pool()
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, event_name, date::text AS date, city, country, lat, lon
                FROM events WHERE user_id=%s
                ORDER BY date ASC, id ASC;
                """,
                (user["uid"],),
            )
            rows = cur.fetchall()
            return jsonify(rows)
    finally:
        db_pool.putconn(conn)


@app.post("/events")
@require_auth
def create_event(user):
    init_db_pool()
    data = request.get_json(force=True)
    name = (data.get("event_name") or "").strip()
    date = (data.get("date") or "").strip()
    city = (data.get("city") or "").strip() or None
    country = (data.get("country") or "").strip() or None
    lat = data.get("lat")
    lon = data.get("lon")
    if not name or not date:
        return jsonify({"error": "missing fields"}), 400

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO events (user_id, event_name, date, city, country, lat, lon)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                RETURNING id, event_name, date::text as date, city, country, lat, lon;
                """,
                (user["uid"], name, date, city, country, lat, lon),
            )
            row = cur.fetchone()
            return jsonify(row), 201
    finally:
        db_pool.putconn(conn)


@app.put("/events/<int:event_id>")
@require_auth
def update_event(user, event_id: int):
    init_db_pool()
    data = request.get_json(force=True)
    name = (data.get("event_name") or "").strip()
    date = (data.get("date") or "").strip()
    city = (data.get("city") or "").strip() or None
    country = (data.get("country") or "").strip() or None
    lat = data.get("lat")
    lon = data.get("lon")
    if not name or not date:
        return jsonify({"error": "missing fields"}), 400

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE events
                SET event_name=%s, date=%s, city=%s, country=%s, lat=%s, lon=%s, updated_at=NOW()
                WHERE id=%s AND user_id=%s
                RETURNING id, event_name, date::text as date, city, country, lat, lon;
                """,
                (name, date, city, country, lat, lon, event_id, user["uid"]),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "not found"}), 404
            return jsonify(row)
    finally:
        db_pool.putconn(conn)


@app.post("/suggest")
@require_auth
def suggest(user):
    data = request.get_json(force=True)
    event_name = (data.get("event_name") or "").strip()
    date = data.get("date")
    lat = data.get("lat")
    lon = data.get("lon")

    event_id = data.get("event_id")
    if event_id:
        conn = db_pool.getconn()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT event_name, date::text AS date, lat, lon, city, country
                    FROM events WHERE id=%s AND user_id=%s
                    """,
                    (event_id, user["uid"]),
                )
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "event not found"}), 404
                event_name = event_name or row.get("event_name") or ""
                date = date or row.get("date")
                lat = lat if lat is not None else row.get("lat")
                lon = lon if lon is not None else row.get("lon")
        finally:
            db_pool.putconn(conn)

    mm = None
    nasa = None
    if date and (lat is not None) and (lon is not None):
        try:
            mm = get_meteomatics_summary(float(lat), float(lon), date)
        except Exception:
            mm = None
        try:
            nasa = get_nasa_power(float(lat), float(lon), date)
        except Exception:
            nasa = None

    label, tips = interpret_conditions(mm, event_name)

    climate_context = None
    if nasa and mm and mm.get("t_max") and nasa.get("avg_temp"):
        diff = mm["t_max"] - nasa["avg_temp"]
        if diff > 3:
            climate_context = "Hotter than typical climate average"
        elif diff < -3:
            climate_context = "Cooler than usual"
        else:
            climate_context = "Typical for this location"

    return jsonify(
        {
            "predicted": label,
            "advice": tips,
            "metrics": mm or {},
            "nasa_power": nasa or {},
            "context": climate_context,
            "note": "Forecast fused from Meteomatics and NASA POWER climatology.",
        }
    )


@app.get("/reverse_geocode")
def api_reverse_geocode():
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    if lat is None or lon is None:
        return jsonify({})
    return jsonify(reverse_geocode(lat, lon))

# ------------------------------------------------------------------------------
# Startup
# ------------------------------------------------------------------------------
init_db_pool()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
