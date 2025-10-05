import os, time, json, hashlib, datetime as dt, logging, requests
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2 import pool as psycopool
from psycopg2.extras import RealDictCursor

# ------------------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
CORS(app, supports_credentials=False)
app.logger.setLevel(logging.INFO)

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
MM_USER = os.getenv("MM_USERNAME")
MM_PASS = os.getenv("MM_PASSWORD")

DB_CFG = dict(
    host=os.getenv("POSTGRES_HOST", "db"),
    port=int(os.getenv("POSTGRES_PORT", "5432")),
    dbname=os.getenv("POSTGRES_DB", "nasa2025"),
    user=os.getenv("POSTGRES_USER", "nasa2025"),
    password=os.getenv("POSTGRES_PASSWORD", "nasa2025"),
)

db_pool: psycopg2.pool.SimpleConnectionPool | None = None

# ------------------------------------------------------------------------------
# DB init
# ------------------------------------------------------------------------------
def init_db_pool():
    global db_pool
    if db_pool:
        return
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            db_pool = psycopg2.pool.SimpleConnectionPool(minconn=1, maxconn=8, **DB_CFG)
            conn = db_pool.getconn()
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1;")
            db_pool.putconn(conn)
            break
        except Exception as e:
            app.logger.warning(f"[DB wait] {e}")
            time.sleep(2)
    if not db_pool:
        raise RuntimeError("Database not reachable")
    ensure_schema()

def ensure_schema():
    conn = db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(420420);")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS app_users(
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    pin_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );""")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS events(
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
                );""")
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
        if hashlib.sha256((data + APP_SECRET).encode()).hexdigest() != sig:
            return None
        p = json.loads(data)
        if "exp" in p and time.time() > p["exp"]:
            return None
        return p
    except Exception:
        return None

def issue_token(uid, username):
    return _sign({"uid": uid, "username": username, "exp": time.time() + 604800})

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        p = _verify(auth[7:])
        if not p:
            return jsonify({"error": "unauthorized"}), 401
        return fn(user=p, *a, **kw)
    return wrapper

# ------------------------------------------------------------------------------
# External data
# ------------------------------------------------------------------------------
def get_meteomatics_summary(lat: float, lon: float, date_iso: str):
    if not (MM_USER and MM_PASS):
        app.logger.warning("[Meteomatics] Missing credentials")
        return None
    try:
        d = dt.datetime.fromisoformat(date_iso)
        start, end = f"{d:%Y-%m-%dT00:00:00Z}", f"{d:%Y-%m-%dT23:59:59Z}"
        params = "t_2m:C,precipitation_1h:mm,wind_speed_10m:ms"
        url = f"https://api.meteomatics.com/{start}--{end}:PT1H/{params}/{lat},{lon}/json"
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=15)
        app.logger.info(f"[Meteomatics] {r.status_code} {url}")
        if r.status_code != 200:
            app.logger.warning(f"[Meteomatics] Body {r.text[:200]}")
            return None
        js = r.json()
        vals = {}
        for p in js.get("data", []):
            key = p.get("parameter")
            coords = p.get("coordinates") or []
            if coords:
                pts = coords[0].get("dates", [])
                vals[key] = [x.get("value") for x in pts if isinstance(x, dict) and "value" in x]
        t = vals.get("t_2m:C", [])
        pr = vals.get("precipitation_1h:mm", [])
        ws = vals.get("wind_speed_10m:ms", [])
        if not (t or pr or ws):
            app.logger.warning("[Meteomatics] Parsed empty lists")
            return None
        out = {
            "t_max": max(t) if t else None,
            "t_min": min(t) if t else None,
            "precip_24h": sum(pr) if pr else 0,
            "wind_max": max(ws) if ws else None,
            "source": "meteomatics",
        }
        app.logger.info(f"[Meteomatics summary] {out}")
        return out
    except Exception as e:
        app.logger.error(f"[Meteomatics EXC] {e}")
        return None

def get_nasa_power(lat, lon, date_iso):
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR"
            f"&community=RE&longitude={lon}&latitude={lat}"
            f"&start={d:%Y%m%d}&end={d:%Y%m%d}&format=JSON"
        )
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            app.logger.warning(f"[NASA] {r.status_code}")
            return None
        data = r.json().get("properties", {}).get("parameter", {})
        tmax = list(data.get("T2M_MAX", {}).values())[0]
        tmin = list(data.get("T2M_MIN", {}).values())[0]
        precip = list(data.get("PRECTOTCORR", {}).values())[0]
        out = {"tmax": tmax, "tmin": tmin, "precip": precip, "avg_temp": (tmax + tmin) / 2, "source": "nasa_power"}
        app.logger.info(f"[NASA POWER] {out}")
        return out
    except Exception as e:
        app.logger.error(f"[NASA EXC] {e}")
        return None

def interpret_conditions(m, name):
    if not m:
        return "mixed conditions", ["umbrella", "water bottle", "sunscreen"]
    t, rain, w = m.get("t_max"), m.get("precip_24h", 0), m.get("wind_max")
    if t and t >= 33: label = "very hot"
    elif rain >= 10: label = "very wet"
    elif w and w >= 10: label = "very windy"
    elif t and t <= 18: label = "cool"
    else: label = "fair"
    return label, [f"Temp {t:.1f}°C" if t else "Check weather"]


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.post("/signup")
def signup():
    init_db_pool()
    d = request.get_json(force=True)
    u = (d.get("username") or "").strip().lower()
    p = (d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p) != 4:
        return jsonify({"error": "invalid"}), 400
    ph = _hash_pin(u, p)
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("INSERT INTO app_users(username,pin_hash) VALUES(%s,%s) ON CONFLICT(username) DO NOTHING RETURNING id;", (u, ph))
            row = c.fetchone()
            if not row:
                c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;", (u,))
                row2 = c.fetchone()
                if not row2 or row2["pin_hash"] != ph:
                    return jsonify({"error": "username exists"}), 409
                uid = row2["id"]
            else:
                uid = row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok": True, "token": issue_token(uid, u)})

@app.post("/login")
def login():
    init_db_pool()
    d = request.get_json(force=True)
    u = (d.get("username") or "").strip().lower()
    p = (d.get("pin") or "").strip()
    ph = _hash_pin(u, p)
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;", (u,))
            row = c.fetchone()
            if not row or row["pin_hash"] != ph:
                return jsonify({"error": "invalid"}), 401
            uid = row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok": True, "token": issue_token(uid, u)})

@app.post("/events")
@require_auth
def create_event(user):
    init_db_pool()
    d = request.get_json(force=True)
    name, date = (d.get("event_name") or "").strip(), (d.get("date") or "").strip()
    lat, lon = d.get("lat"), d.get("lon")
    if not name or not date:
        return jsonify({"error": "missing fields"}), 400
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""INSERT INTO events(user_id,event_name,date,lat,lon)
                         VALUES(%s,%s,%s,%s,%s)
                         RETURNING id,event_name,date::text,lat,lon;""",
                      (user["uid"], name, date, lat, lon))
            return jsonify(c.fetchone()), 201
    finally: db_pool.putconn(conn)

@app.post("/suggest")
@require_auth
def suggest(user):
    d = request.get_json(force=True)
    event, date, lat, lon = (d.get("event_name") or ""), d.get("date"), d.get("lat"), d.get("lon")
    app.logger.info(f"[/suggest] event={event} date={date} coords=({lat},{lon})")
    mm = nasa = None
    if date and lat and lon:
        mm = get_meteomatics_summary(float(lat), float(lon), date)
        nasa = get_nasa_power(float(lat), float(lon), date)
    app.logger.info(f"[/suggest] mm={mm} nasa={nasa}")
    label, tips = interpret_conditions(mm, event)
    note = "Using NASA POWER only" if (not mm and nasa) else "Forecast from Meteomatics + NASA"
    return jsonify({"predicted": label, "advice": tips, "metrics": mm or {}, "nasa_power": nasa or {}, "note": note})

@app.get("/")
def root(): return send_from_directory("/app/static","index.html")

@app.get("/<path:path>")
def static_proxy(path):
    try: return send_from_directory("/app/static",path)
    except Exception: return jsonify({"error":"not found"}),404

# ------------------------------------------------------------------------------
init_db_pool()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=8000,debug=True)
