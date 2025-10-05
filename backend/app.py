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

MM_USER = os.getenv("MM_USERNAME")
MM_PASS = os.getenv("MM_PASSWORD")

db_pool: psycopool.SimpleConnectionPool | None = None

# ------------------------------------------------------------------------------
# DB setup
# ------------------------------------------------------------------------------
def init_db_pool():
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
                **DB_CFG
            )
            conn = db_pool.getconn()
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1;")
            db_pool.putconn(conn)
            break
        except Exception as e:
            last_err = e
            time.sleep(2)
    if not db_pool:
        raise RuntimeError(f"Database not reachable: {last_err}")
    ensure_schema()


def ensure_schema():
    conn = db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(420420);")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS app_users (
                        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        pin_hash TEXT NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                cur.execute("""
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
                """)
                cur.execute("SELECT pg_advisory_unlock(420420);")
    finally:
        db_pool.putconn(conn)

# ------------------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------------------
def _hash_pin(username, pin):
    return hashlib.sha256(f"{username}:{pin}:{APP_SECRET}".encode()).hexdigest()

def _sign(payload):
    data = json.dumps(payload, separators=(",", ":"))
    sig = hashlib.sha256((data + APP_SECRET).encode()).hexdigest()
    return f"{data}.{sig}"

def _verify(token):
    try:
        data, sig = token.rsplit(".", 1)
        expect = hashlib.sha256((data + APP_SECRET).encode()).hexdigest()
        if sig != expect:
            return None
        payload = json.loads(data)
        if "exp" in payload and time.time() > payload["exp"]:
            return None
        return payload
    except Exception:
        return None

def issue_token(uid, username):
    return _sign({"uid": uid, "username": username, "exp": time.time() + 60 * 60 * 24 * 7})

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
# External APIs
# ------------------------------------------------------------------------------
def get_meteomatics_summary(lat, lon, date_iso):
    """Fetch Meteomatics hourly data and compute summary."""
    if not MM_USER or not MM_PASS:
        print("[Meteomatics] Missing credentials")
        return None
    try:
        d0 = dt.datetime.fromisoformat(date_iso)
        start = d0.strftime("%Y-%m-%dT00:00:00Z")
        end = d0.strftime("%Y-%m-%dT23:59:59Z")
        params = "t_2m:C,precipitation_1h:mm,wind_speed_10m:ms"
        url = f"https://api.meteomatics.com/{start}--{end}:PT1H/{params}/{lat:.4f},{lon:.4f}/json"
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=15)
        print(f"[Meteomatics] URL={url} STATUS={r.status_code}")
        if r.status_code != 200:
            print("[Meteomatics error]", r.text[:200])
            return None
        js = r.json()
        # Try flexible parsing
        data = js.get("data", [])
        values = {p["parameter"]: [d["value"] for d in p["coordinates"][0]["dates"] if "value" in d]
                  for p in data if p.get("coordinates")}
        t = values.get("t_2m:C", [])
        pr = values.get("precipitation_1h:mm", [])
        ws = values.get("wind_speed_10m:ms", [])
        if not (t or pr or ws):
            print("[Meteomatics] No numeric data parsed.")
            return None
        return {
            "t_max": max(t) if t else None,
            "t_min": min(t) if t else None,
            "precip_24h": sum(pr) if pr else 0.0,
            "wind_max": max(ws) if ws else None,
            "source": "meteomatics"
        }
    except Exception as e:
        print("[Meteomatics Exception]", e)
        return None

def get_nasa_power(lat, lon, date_iso):
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR"
            f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}"
            f"&start={d.strftime('%Y%m%d')}&end={d.strftime('%Y%m%d')}&format=JSON"
        )
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            print("[NASA POWER error]", r.status_code, r.text[:100])
            return None
        data = r.json().get("properties", {}).get("parameter", {})
        tmax = list(data.get("T2M_MAX", {}).values())[0]
        tmin = list(data.get("T2M_MIN", {}).values())[0]
        precip = list(data.get("PRECTOTCORR", {}).values())[0]
        return {"tmax": tmax, "tmin": tmin, "precip": precip, "source": "nasa_power"}
    except Exception as e:
        print("[NASA POWER Exception]", e)
        return None

def interpret_conditions(metrics, event_name):
    if not metrics:
        return "mixed conditions", ["umbrella just in case", "water bottle", "sunscreen"]
    tmax = metrics.get("t_max")
    rain = metrics.get("precip_24h", 0)
    wind = metrics.get("wind_max")
    if tmax and tmax >= 33:
        label = "very hot"
    elif rain >= 10:
        label = "very wet"
    elif wind and wind >= 10:
        label = "very windy"
    elif tmax and tmax <= 18:
        label = "cool"
    else:
        label = "fair"
    tips = []
    if label == "very hot": tips += ["shade", "hydration"]
    if label == "very wet": tips += ["raincoat", "waterproof gear"]
    if label == "very windy": tips += ["secure tents"]
    if label == "cool": tips += ["light jacket"]
    return label, tips

def reverse_geocode(lat, lon):
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
                         params={"format": "jsonv2", "lat": lat, "lon": lon},
                         headers={"User-Agent": "Plan4Cast/1.0"}, timeout=8)
        if r.status_code != 200:
            return {}
        js = r.json().get("address", {})
        return {"city": js.get("city") or js.get("town") or js.get("village"), "country": js.get("country")}
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
                "INSERT INTO app_users (username, pin_hash) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING id;",
                (username, pin_hash),
            )
            row = cur.fetchone()
            if not row:
                cur.execute("SELECT id, pin_hash FROM app_users WHERE username=%s;", (username,))
                row2 = cur.fetchone()
                if not row2 or row2["pin_hash"] != pin_hash:
                    return jsonify({"error": "username already exists"}), 409
                uid = row2["id"]
            else:
                uid = row["id"]
    finally:
        db_pool.putconn(conn)
    return jsonify({"ok": True, "token": issue_token(uid, username)})

@app.post("/login")
def login():
    init_db_pool()
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    pin = (data.get("pin") or "").strip()
    pin_hash = _hash_pin(username, pin)
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, pin_hash FROM app_users WHERE username=%s;", (username,))
            row = cur.fetchone()
            if not row or row["pin_hash"] != pin_hash:
                return jsonify({"error": "invalid credentials"}), 401
            uid = row["id"]
    finally:
        db_pool.putconn(conn)
    return jsonify({"ok": True, "token": issue_token(uid, username)})

@app.post("/suggest")
@require_auth
def suggest(user):
    data = request.get_json(force=True)
    event_name = (data.get("event_name") or "").strip()
    date = data.get("date")
    lat = data.get("lat")
    lon = data.get("lon")
    print(f"\n=== Suggest for {event_name} ({date}) ===")
    print(f"Coordinates: {lat},{lon}")

    mm = get_meteomatics_summary(float(lat), float(lon), date) if (lat and lon and date) else None
    nasa = get_nasa_power(float(lat), float(lon), date) if (lat and lon and date) else None
    print("Meteomatics data:", mm)
    print("NASA POWER data:", nasa)

    label, tips = interpret_conditions(mm, event_name)
    return jsonify({
        "predicted": label,
        "advice": tips,
        "metrics": mm or {},
        "nasa_power": nasa or {},
        "note": "Forecast fused from Meteomatics and NASA POWER climatology."
    })

@app.get("/reverse_geocode")
def api_reverse_geocode():
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    return jsonify(reverse_geocode(lat, lon))

@app.get("/")
def root():
    return send_from_directory("/app/static", "index.html")

@app.get("/<path:path>")
def static_proxy(path):
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
