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
    last_err = None
    while time.time() < deadline:
        try:
            db_pool = psycopg2.pool.SimpleConnectionPool(minconn=1, maxconn=8, **DB_CFG)
            conn = db_pool.getconn()
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1;")
            db_pool.putconn(conn)
            break
        except Exception as e:
            last_err = e
            app.logger.warning(f"[DB wait] {e}")
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
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON app_users(username);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, date);")
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
    return _sign({"uid": uid, "username": username, "exp": time.time() + 60*60*24*7})

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
# External data (Meteomatics + NASA POWER)
# ------------------------------------------------------------------------------
def get_meteomatics_summary(lat: float, lon: float, date_iso: str):
    """Fetch Meteomatics daily summary (free-tier safe)."""
    if not (MM_USER and MM_PASS):
        app.logger.warning("[Meteomatics] Missing credentials")
        return None
    try:
        d = dt.datetime.fromisoformat(date_iso)
        # Use daily aggregated params available to academic/free accounts
        params = "t_max_2m_24h:C,t_min_2m_24h:C,precip_24h:mm,wind_speed_10m_max_24h:ms"
        url = (
            f"https://api.meteomatics.com/{d:%Y-%m-%dT00:00:00Z}/{params}/{lat:.4f},{lon:.4f}/json"
        )
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=15)
        app.logger.info(f"[Meteomatics] {r.status_code} {url}")
        if r.status_code != 200:
            app.logger.warning(f"[Meteomatics body] {r.text[:200]}")
            return None

        js = r.json()
        data = {p["parameter"]: p["coordinates"][0]["dates"][0]["value"]
                for p in js.get("data", []) if p.get("coordinates")}
        out = {
            "t_max": data.get("t_max_2m_24h:C"),
            "t_min": data.get("t_min_2m_24h:C"),
            "precip_24h": data.get("precip_24h:mm", 0),
            "wind_max": data.get("wind_speed_10m_max_24h:ms"),
            "source": "meteomatics (daily aggregate)"
        }
        app.logger.info(f"[Meteomatics summary] {out}")
        return out
    except Exception as e:
        app.logger.error(f"[Meteomatics EXC] {e}")
        return None

def get_nasa_power(lat: float, lon: float, date_iso: str):
    """Fetch NASA POWER daily values for that day/point."""
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN"
            f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}"
            f"&start={d:%Y%m%d}&end={d:%Y%m%d}&format=JSON"
        )
        r = requests.get(url, timeout=12)
        if r.status_code == 400 or r.status_code == 500:
            app.logger.info("[NASA] Skipping — likely future date")
            return None
        if r.status_code != 200:
            app.logger.warning(f"[NASA] {r.status_code} body={r.text[:120]}")
            return None

        param = r.json().get("properties", {}).get("parameter", {})
        tmax = list(param.get("T2M_MAX", {}).values())[0]
        tmin = list(param.get("T2M_MIN", {}).values())[0]
        precip = list(param.get("PRECTOTCORR", {}).values())[0]
        solar = list(param.get("ALLSKY_SFC_SW_DWN", {}).values())[0]
        out = {"tmax": tmax, "tmin": tmin, "avg_temp": (tmax + tmin)/2.0, "precip": precip, "solar": solar, "source": "nasa_power"}
        app.logger.info(f"[NASA POWER] {out}")
        return out
    except Exception as e:
        app.logger.error(f"[NASA EXC] {e}")
        return None

def interpret_conditions(m, event_name: str):
    """Turn metrics into a label + tips (varies when Meteomatics parsed)."""
    if not m:
        return "mixed conditions", ["umbrella just in case", "water bottle", "sunscreen"]
    tmax = m.get("t_max")
    rain = m.get("precip_24h", 0) or 0
    wind = m.get("wind_max")
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
    tips = []
    if label == "very hot": tips += ["pack extra ice", "shade/canopy", "portable fans", "electrolytes"]
    if label == "very wet": tips += ["raincoats", "waterproof bags", "backup shelter"]
    if label == "very windy": tips += ["secure tents/props", "avoid drone flights"]
    return label, tips

def reverse_geocode(lat: float, lon: float):
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
                         params={"format":"jsonv2","lat":lat,"lon":lon,"zoom":10,"addressdetails":1},
                         headers={"User-Agent":"Plan4Cast/1.0"}, timeout=8)
        if r.status_code != 200: return {}
        addr = r.json().get("address", {})
        city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("county")
        return {"city": city, "country": addr.get("country")}
    except Exception:
        return {}

# ------------------------------------------------------------------------------
# Error handlers (JSON for XHR)
# ------------------------------------------------------------------------------
def _wants_json():
    a = request.headers.get("Accept", "")
    c = request.headers.get("Content-Type", "")
    return ("application/json" in a) or ("application/json" in c)

@app.errorhandler(404)
def _404(e):
    if _wants_json(): return jsonify({"error":"not found"}), 404
    if request.method == "GET": return send_from_directory("/app/static", "index.html")
    return "Not found", 404

@app.errorhandler(405)
def _405(e):
    return (jsonify({"error":"method not allowed"}), 405) if _wants_json() else ("Method not allowed", 405)

@app.errorhandler(500)
def _500(e):
    app.logger.error(f"[500] {e}")
    return (jsonify({"error":"server error"}), 500) if _wants_json() else ("Server error", 500)

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.get("/health")
def health(): return jsonify({"ok": True, "ts": time.time()})

@app.post("/signup")
def signup():
    init_db_pool()
    d = request.get_json(force=True)
    u = (d.get("username") or "").strip().lower()
    p = (d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p) != 4: return jsonify({"error":"invalid username or pin"}), 400
    ph = _hash_pin(u, p)
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("INSERT INTO app_users(username,pin_hash) VALUES(%s,%s) ON CONFLICT(username) DO NOTHING RETURNING id;", (u, ph))
            row = c.fetchone()
            if not row:
                c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;", (u,))
                row2 = c.fetchone()
                if not row2 or row2["pin_hash"] != ph: return jsonify({"error":"username already exists"}), 409
                uid = row2["id"]
            else:
                uid = row["id"]
    finally:
        db_pool.putconn(conn)
    return jsonify({"ok": True, "token": issue_token(uid, u)})

@app.post("/login")
def login():
    init_db_pool()
    d = request.get_json(force=True)
    u = (d.get("username") or "").strip().lower()
    p = (d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p) != 4: return jsonify({"error":"invalid credentials"}), 400
    ph = _hash_pin(u, p)
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;", (u,))
            row = c.fetchone()
            if not row or row["pin_hash"] != ph: return jsonify({"error":"invalid credentials"}), 401
            uid = row["id"]
    finally:
        db_pool.putconn(conn)
    return jsonify({"ok": True, "token": issue_token(uid, u)})

@app.get("/events")
@require_auth
def list_events(user):
    init_db_pool()
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""SELECT id,event_name,date::text AS date,city,country,lat,lon
                         FROM events WHERE user_id=%s ORDER BY date ASC, id ASC;""", (user["uid"],))
            return jsonify(c.fetchall())
    finally:
        db_pool.putconn(conn)

@app.post("/events")
@require_auth
def create_event(user):
    init_db_pool()
    d = request.get_json(force=True)
    name = (d.get("event_name") or "").strip()
    date = (d.get("date") or "").strip()
    city = (d.get("city") or "").strip() or None
    country = (d.get("country") or "").strip() or None
    lat = d.get("lat"); lon = d.get("lon")
    if not name or not date: return jsonify({"error":"missing fields"}), 400
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""INSERT INTO events(user_id,event_name,date,city,country,lat,lon)
                         VALUES(%s,%s,%s,%s,%s,%s,%s)
                         RETURNING id,event_name,date::text AS date,city,country,lat,lon;""",
                      (user["uid"], name, date, city, country, lat, lon))
            return jsonify(c.fetchone()), 201
    finally:
        db_pool.putconn(conn)

@app.put("/events/<int:event_id>")
@require_auth
def update_event(user, event_id:int):
    init_db_pool()
    d = request.get_json(force=True)
    name = (d.get("event_name") or "").strip()
    date = (d.get("date") or "").strip()
    city = (d.get("city") or "").strip() or None
    country = (d.get("country") or "").strip() or None
    lat = d.get("lat"); lon = d.get("lon")
    if not name or not date: return jsonify({"error":"missing fields"}), 400
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""UPDATE events SET event_name=%s,date=%s,city=%s,country=%s,lat=%s,lon=%s,updated_at=NOW()
                         WHERE id=%s AND user_id=%s
                         RETURNING id,event_name,date::text AS date,city,country,lat,lon;""",
                      (name, date, city, country, lat, lon, event_id, user["uid"]))
            row = c.fetchone()
            if not row: return jsonify({"error":"not found"}), 404
            return jsonify(row)
    finally:
        db_pool.putconn(conn)

@app.post("/suggest")
@require_auth
def suggest(user):
    """
    Accepts either:
      - { event_id }  -> loads event from DB
      - or { event_name, date, lat, lon }
    """
    d = request.get_json(force=True)
    event_name = (d.get("event_name") or "").strip()
    date = d.get("date")
    lat = d.get("lat")
    lon = d.get("lon")

    # Load by ID if provided (THIS WAS MISSING IN YOUR CURRENT RUN)
    event_id = d.get("event_id")
    if event_id and (date is None or lat is None or lon is None or not event_name):
        conn = db_pool.getconn()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as c:
                c.execute("""SELECT event_name, date::text AS date, lat, lon, city, country
                             FROM events WHERE id=%s AND user_id=%s;""",
                          (event_id, user["uid"]))
                row = c.fetchone()
                if not row:
                    return jsonify({"error":"event not found"}), 404
                event_name = event_name or (row.get("event_name") or "")
                date = date or row.get("date")
                lat = lat if lat is not None else row.get("lat")
                lon = lon if lon is not None else row.get("lon")
        finally:
            db_pool.putconn(conn)

    app.logger.info(f"[/suggest] event={event_name} date={date} coords=({lat},{lon})")

    mm = nasa = None
    if date and (lat is not None) and (lon is not None):
        try: mm = get_meteomatics_summary(float(lat), float(lon), date)
        except Exception as e:
            app.logger.error(f"[/suggest] Meteomatics error: {e}")
        try: nasa = get_nasa_power(float(lat), float(lon), date)
        except Exception as e:
            app.logger.error(f"[/suggest] NASA error: {e}")

    app.logger.info(f"[/suggest] mm={mm} nasa={nasa}")

    label, tips = interpret_conditions(mm, event_name)
    context = None
    if nasa and mm and (mm.get("t_max") is not None) and (nasa.get("avg_temp") is not None):
        diff = mm["t_max"] - nasa["avg_temp"]
        context = "Hotter than usual" if diff > 3 else "Cooler than usual" if diff < -3 else "Typical for this location"

    return jsonify({
        "predicted": label,
        "advice": tips,
        "metrics": mm or {},
        "nasa_power": nasa or {},
        "context": context,
        "note": "Forecast fused from Meteomatics and NASA POWER climatology." if (mm or nasa) else "No weather data available"
    })

@app.get("/reverse_geocode")
def api_reverse_geocode():
    lat = request.args.get("lat", type=float); lon = request.args.get("lon", type=float)
    if lat is None or lon is None: return jsonify({})
    return jsonify(reverse_geocode(lat, lon))

# ------------------------------------------------------------------------------
# Static frontend
# ------------------------------------------------------------------------------
@app.get("/")
def root(): return send_from_directory("/app/static", "index.html")

@app.get("/<path:path>")
def static_proxy(path):
    try: return send_from_directory("/app/static", path)
    except Exception: return _404(None)

# ------------------------------------------------------------------------------
init_db_pool()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
