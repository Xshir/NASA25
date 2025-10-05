import os, time, json, hashlib, datetime as dt, logging, requests
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2 import pool as psycopool
from psycopg2.extras import RealDictCursor

# ---------------------------------------------------------------------
# App & Config
# ---------------------------------------------------------------------
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

# ---------------------------------------------------------------------
# Database Setup
# ---------------------------------------------------------------------
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
    """Create or upgrade schema idempotently."""
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
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                cur.execute("""
                    ALTER TABLE events ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON app_users(username);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, date);")
                cur.execute("SELECT pg_advisory_unlock(420420);")
    finally:
        db_pool.putconn(conn)

# ---------------------------------------------------------------------
# Auth Helpers
# ---------------------------------------------------------------------
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
        payload = json.loads(data)
        if "exp" in payload and time.time() > payload["exp"]:
            return None
        return payload
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

# ---------------------------------------------------------------------
# Weather Data Fetching
# ---------------------------------------------------------------------
def get_meteomatics_summary(lat: float, lon: float, date_iso: str):
    """Fetch Meteomatics daily summary."""
    if not (MM_USER and MM_PASS):
        return None
    try:
        d = dt.datetime.fromisoformat(date_iso)
        params = "t_max_2m_24h:C,t_min_2m_24h:C,precip_24h:mm"
        url = f"https://api.meteomatics.com/{d:%Y-%m-%dT00:00:00Z}/{params}/{lat:.4f},{lon:.4f}/json"
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=15)
        if r.status_code != 200:
            app.logger.warning(f"[Meteomatics {r.status_code}] {r.text[:150]}")
            return None
        js = r.json()
        data = {p["parameter"]: p["coordinates"][0]["dates"][0]["value"]
                for p in js.get("data", []) if p.get("coordinates")}
        return {
            "t_max": data.get("t_max_2m_24h:C"),
            "t_min": data.get("t_min_2m_24h:C"),
            "precip_24h": data.get("precip_24h:mm", 0),
        }
    except Exception as e:
        app.logger.error(f"[Meteomatics EXC] {e}")
        return None

def get_nasa_power(lat: float, lon: float, date_iso: str):
    """NASA POWER climatology."""
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN"
            f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}"
            f"&start={d:%Y%m%d}&end={d:%Y%m%d}&format=JSON"
        )
        r = requests.get(url, timeout=12)
        if r.status_code != 200:
            app.logger.warning(f"[NASA] {r.status_code}")
            return None
        param = r.json().get("properties", {}).get("parameter", {})
        tmax = list(param.get("T2M_MAX", {}).values())[0]
        tmin = list(param.get("T2M_MIN", {}).values())[0]
        precip = list(param.get("PRECTOTCORR", {}).values())[0]
        solar = list(param.get("ALLSKY_SFC_SW_DWN", {}).values())[0]
        return {"tmax": tmax, "tmin": tmin, "precip": precip, "solar": solar}
    except Exception as e:
        app.logger.error(f"[NASA EXC] {e}")
        return None

# ---------------------------------------------------------------------
# Smart Recommendation System
# ---------------------------------------------------------------------
def interpret_conditions(metrics: dict | None, event_name: str):
    """
    Returns a descriptive label + list of recommendation notes.
    Always gives meaningful tips for every event type.
    """
    e = (event_name or "").lower()
    tips = []

    # Base label from weather
    if not metrics:
        label = "mixed conditions"
    else:
        tmax = metrics.get("t_max") or metrics.get("tmax")
        rain = metrics.get("precip_24h") or metrics.get("precip") or 0
        if tmax and tmax >= 34:
            label = "very hot"
            tips += ["stay hydrated", "use sunscreen", "set up shaded rest areas"]
        elif rain >= 10:
            label = "very wet"
            tips += ["bring umbrellas or ponchos", "cover electrical gear", "consider indoor backup"]
        elif tmax and tmax <= 18:
            label = "cool"
            tips += ["bring light jacket", "warm drinks", "prepare windbreakers"]
        else:
            label = "fair"
            tips += ["good outdoor weather", "still check UV levels", "keep hydration nearby"]

    # Contextual event intelligence
    if any(k in e for k in ["drone", "flying", "aerial", "uav", "fpv"]):
        tips += ["check wind speed", "verify NOTAM zones", "bring ND filters", "spare batteries"]
    elif any(k in e for k in ["wedding", "ceremony", "party", "festival"]):
        tips += ["confirm canopy vendor", "protect sound systems", "backup indoor option"]
    elif any(k in e for k in ["concert", "show", "performance"]):
        tips += ["check lighting", "cover audio equipment", "manage crowd cooling"]
    elif any(k in e for k in ["sports", "match", "run", "race", "tournament"]):
        tips += ["hydration points ready", "shade near seating", "heat index monitoring"]
    elif any(k in e for k in ["picnic", "bbq", "beach", "park"]):
        tips += ["bring cooler", "sunscreen", "avoid peak sun 12–3 pm"]
    elif any(k in e for k in ["hike", "trail", "camp", "forest"]):
        tips += ["carry insect repellent", "check rainfall for trail conditions"]
    elif any(k in e for k in ["market", "bazaar", "stall", "food"]):
        tips += ["keep perishables chilled", "secure tents", "prepare tarps"]
    elif any(k in e for k in ["shoot", "filming", "photo", "video"]):
        tips += ["check sunlight angles", "use ND filters", "keep batteries charged"]
    elif any(k in e for k in ["school", "outreach", "booth", "open house"]):
        tips += ["laminate posters", "check wind stability of displays"]
    elif any(k in e for k in ["meeting", "conference", "expo"]):
        tips += ["check AV setup", "backup presentation USB"]
    elif any(k in e for k in ["travel", "trip", "journey"]):
        tips += ["expect delays in bad weather", "carry compact umbrella"]

    general = [
        "monitor live weather 3h before start",
        "keep first-aid supplies ready",
        "assign weather safety in-charge",
    ]
    for g in general:
        if g not in tips: tips.append(g)

    if len(tips) < 3:
        tips += ["monitor conditions hourly", "pack essentials", "communicate updates"]

    seen = set()
    final_tips = [t for t in tips if not (t in seen or seen.add(t))]
    return label, final_tips

# ---------------------------------------------------------------------
# Reverse Geocode
# ---------------------------------------------------------------------
def reverse_geocode(lat, lon):
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format":"jsonv2","lat":lat,"lon":lon,"zoom":10,"addressdetails":1},
            headers={"User-Agent":"Plan4Cast/1.0"},
            timeout=8
        )
        if r.status_code != 200:
            return {}
        js = r.json()
        addr = js.get("address",{})
        city = addr.get("city") or addr.get("town") or addr.get("village")
        return {
            "city": city,
            "country": addr.get("country"),
            "country_code": addr.get("country_code","").upper(),
        }
    except Exception:
        return {}

# ---------------------------------------------------------------------
# Core Routes
# ---------------------------------------------------------------------
@app.get("/health")
def health(): return jsonify({"ok":True,"ts":time.time()})

@app.post("/signup")
def signup():
    init_db_pool()
    d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower()
    p=(d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p)!=4:
        return jsonify({"error":"invalid credentials"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("INSERT INTO app_users(username,pin_hash) VALUES(%s,%s) ON CONFLICT(username) DO NOTHING RETURNING id;",(u,ph))
            row=c.fetchone()
            if not row:
                c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
                row2=c.fetchone()
                if not row2 or row2["pin_hash"]!=ph:
                    return jsonify({"error":"username exists"}),409
                uid=row2["id"]
            else: uid=row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok":True,"token":issue_token(uid,u)})

@app.post("/login")
def login():
    init_db_pool()
    d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower()
    p=(d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p)!=4:
        return jsonify({"error":"invalid"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
            row=c.fetchone()
            if not row or row["pin_hash"]!=ph:
                return jsonify({"error":"invalid"}),401
            uid=row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok":True,"token":issue_token(uid,u)})

@app.get("/events")
@require_auth
def list_events(user):
    init_db_pool()
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,event_name,date::text,city,country,lat,lon FROM events WHERE user_id=%s ORDER BY date ASC;",(user["uid"],))
            return jsonify(c.fetchall())
    finally: db_pool.putconn(conn)

@app.post("/events")
@require_auth
def create_event(user):
    init_db_pool()
    d=request.get_json(force=True)
    name=(d.get("event_name") or "").strip()
    date=(d.get("date") or "").strip()
    city=(d.get("city") or "").strip() or None
    country=(d.get("country") or "").strip() or None
    lat=d.get("lat"); lon=d.get("lon")
    if not name or not date:
        return jsonify({"error":"missing fields"}),400
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                INSERT INTO events (user_id,event_name,date,city,country,lat,lon)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                RETURNING id,event_name,date::text,city,country,lat,lon;
            """,(user["uid"],name,date,city,country,lat,lon))
            return jsonify(c.fetchone()),201
    finally: db_pool.putconn(conn)

@app.put("/events/<int:event_id>")
@require_auth
def update_event(user,event_id:int):
    init_db_pool()
    d=request.get_json(force=True)
    name=(d.get("event_name") or "").strip()
    date=(d.get("date") or "").strip()
    city=(d.get("city") or "").strip() or None
    country=(d.get("country") or "").strip() or None
    lat=d.get("lat"); lon=d.get("lon")
    if not name or not date:
        return jsonify({"error":"missing fields"}),400
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                UPDATE events SET event_name=%s,date=%s,city=%s,country=%s,lat=%s,lon=%s,updated_at=NOW()
                WHERE id=%s AND user_id=%s
                RETURNING id,event_name,date::text,city,country,lat,lon;
            """,(name,date,city,country,lat,lon,event_id,user["uid"]))
            row=c.fetchone()
            if not row: return jsonify({"error":"not found"}),404
            return jsonify(row)
    finally: db_pool.putconn(conn)
import os, time, json, hashlib, datetime as dt, logging, requests
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2 import pool as psycopool
from psycopg2.extras import RealDictCursor

# ---------------------------------------------------------------------
# App & Config
# ---------------------------------------------------------------------
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

# ---------------------------------------------------------------------
# Database Setup
# ---------------------------------------------------------------------
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
    """Create or upgrade schema idempotently."""
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
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                cur.execute("""
                    ALTER TABLE events ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON app_users(username);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, date);")
                cur.execute("SELECT pg_advisory_unlock(420420);")
    finally:
        db_pool.putconn(conn)

# ---------------------------------------------------------------------
# Auth Helpers
# ---------------------------------------------------------------------
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
        payload = json.loads(data)
        if "exp" in payload and time.time() > payload["exp"]:
            return None
        return payload
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

# ---------------------------------------------------------------------
# Weather Data Fetching
# ---------------------------------------------------------------------
def get_meteomatics_summary(lat: float, lon: float, date_iso: str):
    """Fetch Meteomatics daily summary."""
    if not (MM_USER and MM_PASS):
        return None
    try:
        d = dt.datetime.fromisoformat(date_iso)
        params = "t_max_2m_24h:C,t_min_2m_24h:C,precip_24h:mm"
        url = f"https://api.meteomatics.com/{d:%Y-%m-%dT00:00:00Z}/{params}/{lat:.4f},{lon:.4f}/json"
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=15)
        if r.status_code != 200:
            app.logger.warning(f"[Meteomatics {r.status_code}] {r.text[:150]}")
            return None
        js = r.json()
        data = {p["parameter"]: p["coordinates"][0]["dates"][0]["value"]
                for p in js.get("data", []) if p.get("coordinates")}
        return {
            "t_max": data.get("t_max_2m_24h:C"),
            "t_min": data.get("t_min_2m_24h:C"),
            "precip_24h": data.get("precip_24h:mm", 0),
        }
    except Exception as e:
        app.logger.error(f"[Meteomatics EXC] {e}")
        return None

def get_nasa_power(lat: float, lon: float, date_iso: str):
    """NASA POWER climatology."""
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN"
            f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}"
            f"&start={d:%Y%m%d}&end={d:%Y%m%d}&format=JSON"
        )
        r = requests.get(url, timeout=12)
        if r.status_code != 200:
            app.logger.warning(f"[NASA] {r.status_code}")
            return None
        param = r.json().get("properties", {}).get("parameter", {})
        tmax = list(param.get("T2M_MAX", {}).values())[0]
        tmin = list(param.get("T2M_MIN", {}).values())[0]
        precip = list(param.get("PRECTOTCORR", {}).values())[0]
        solar = list(param.get("ALLSKY_SFC_SW_DWN", {}).values())[0]
        return {"tmax": tmax, "tmin": tmin, "precip": precip, "solar": solar}
    except Exception as e:
        app.logger.error(f"[NASA EXC] {e}")
        return None

# ---------------------------------------------------------------------
# Smart Recommendation System
# ---------------------------------------------------------------------
def interpret_conditions(metrics: dict | None, event_name: str):
    """
    Returns a descriptive label + list of recommendation notes.
    Always gives meaningful tips for every event type.
    """
    e = (event_name or "").lower()
    tips = []

    # Base label from weather
    if not metrics:
        label = "mixed conditions"
    else:
        tmax = metrics.get("t_max") or metrics.get("tmax")
        rain = metrics.get("precip_24h") or metrics.get("precip") or 0
        if tmax and tmax >= 34:
            label = "very hot"
            tips += ["stay hydrated", "use sunscreen", "set up shaded rest areas"]
        elif rain >= 10:
            label = "very wet"
            tips += ["bring umbrellas or ponchos", "cover electrical gear", "consider indoor backup"]
        elif tmax and tmax <= 18:
            label = "cool"
            tips += ["bring light jacket", "warm drinks", "prepare windbreakers"]
        else:
            label = "fair"
            tips += ["good outdoor weather", "still check UV levels", "keep hydration nearby"]

    # Contextual event intelligence
    if any(k in e for k in ["drone", "flying", "aerial", "uav", "fpv"]):
        tips += ["check wind speed", "verify NOTAM zones", "bring ND filters", "spare batteries"]
    elif any(k in e for k in ["wedding", "ceremony", "party", "festival"]):
        tips += ["confirm canopy vendor", "protect sound systems", "backup indoor option"]
    elif any(k in e for k in ["concert", "show", "performance"]):
        tips += ["check lighting", "cover audio equipment", "manage crowd cooling"]
    elif any(k in e for k in ["sports", "match", "run", "race", "tournament"]):
        tips += ["hydration points ready", "shade near seating", "heat index monitoring"]
    elif any(k in e for k in ["picnic", "bbq", "beach", "park"]):
        tips += ["bring cooler", "sunscreen", "avoid peak sun 12–3 pm"]
    elif any(k in e for k in ["hike", "trail", "camp", "forest"]):
        tips += ["carry insect repellent", "check rainfall for trail conditions"]
    elif any(k in e for k in ["market", "bazaar", "stall", "food"]):
        tips += ["keep perishables chilled", "secure tents", "prepare tarps"]
    elif any(k in e for k in ["shoot", "filming", "photo", "video"]):
        tips += ["check sunlight angles", "use ND filters", "keep batteries charged"]
    elif any(k in e for k in ["school", "outreach", "booth", "open house"]):
        tips += ["laminate posters", "check wind stability of displays"]
    elif any(k in e for k in ["meeting", "conference", "expo"]):
        tips += ["check AV setup", "backup presentation USB"]
    elif any(k in e for k in ["travel", "trip", "journey"]):
        tips += ["expect delays in bad weather", "carry compact umbrella"]

    general = [
        "monitor live weather 3h before start",
        "keep first-aid supplies ready",
        "assign weather safety in-charge",
    ]
    for g in general:
        if g not in tips: tips.append(g)

    if len(tips) < 3:
        tips += ["monitor conditions hourly", "pack essentials", "communicate updates"]

    seen = set()
    final_tips = [t for t in tips if not (t in seen or seen.add(t))]
    return label, final_tips

# ---------------------------------------------------------------------
# Reverse Geocode
# ---------------------------------------------------------------------
def reverse_geocode(lat, lon):
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format":"jsonv2","lat":lat,"lon":lon,"zoom":10,"addressdetails":1},
            headers={"User-Agent":"Plan4Cast/1.0"},
            timeout=8
        )
        if r.status_code != 200:
            return {}
        js = r.json()
        addr = js.get("address",{})
        city = addr.get("city") or addr.get("town") or addr.get("village")
        return {
            "city": city,
            "country": addr.get("country"),
            "country_code": addr.get("country_code","").upper(),
        }
    except Exception:
        return {}

# ---------------------------------------------------------------------
# Core Routes
# ---------------------------------------------------------------------
@app.get("/health")
def health(): return jsonify({"ok":True,"ts":time.time()})

@app.post("/signup")
def signup():
    init_db_pool()
    d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower()
    p=(d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p)!=4:
        return jsonify({"error":"invalid credentials"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("INSERT INTO app_users(username,pin_hash) VALUES(%s,%s) ON CONFLICT(username) DO NOTHING RETURNING id;",(u,ph))
            row=c.fetchone()
            if not row:
                c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
                row2=c.fetchone()
                if not row2 or row2["pin_hash"]!=ph:
                    return jsonify({"error":"username exists"}),409
                uid=row2["id"]
            else: uid=row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok":True,"token":issue_token(uid,u)})

@app.post("/login")
def login():
    init_db_pool()
    d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower()
    p=(d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p)!=4:
        return jsonify({"error":"invalid"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
            row=c.fetchone()
            if not row or row["pin_hash"]!=ph:
                return jsonify({"error":"invalid"}),401
            uid=row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok":True,"token":issue_token(uid,u)})

@app.get("/events")
@require_auth
def list_events(user):
    init_db_pool()
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,event_name,date::text,city,country,lat,lon FROM events WHERE user_id=%s ORDER BY date ASC;",(user["uid"],))
            return jsonify(c.fetchall())
    finally: db_pool.putconn(conn)

@app.post("/events")
@require_auth
def create_event(user):
    init_db_pool()
    d=request.get_json(force=True)
    name=(d.get("event_name") or "").strip()
    date=(d.get("date") or "").strip()
    city=(d.get("city") or "").strip() or None
    country=(d.get("country") or "").strip() or None
    lat=d.get("lat"); lon=d.get("lon")
    if not name or not date:
        return jsonify({"error":"missing fields"}),400
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                INSERT INTO events (user_id,event_name,date,city,country,lat,lon)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                RETURNING id,event_name,date::text,city,country,lat,lon;
            """,(user["uid"],name,date,city,country,lat,lon))
            return jsonify(c.fetchone()),201
    finally: db_pool.putconn(conn)

@app.put("/events/<int:event_id>")
@require_auth
def update_event(user,event_id:int):
    init_db_pool()
    d=request.get_json(force=True)
    name=(d.get("event_name") or "").strip()
    date=(d.get("date") or "").strip()
    city=(d.get("city") or "").strip() or None
    country=(d.get("country") or "").strip() or None
    lat=d.get("lat"); lon=d.get("lon")
    if not name or not date:
        return jsonify({"error":"missing fields"}),400
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                UPDATE events SET event_name=%s,date=%s,city=%s,country=%s,lat=%s,lon=%s,updated_at=NOW()
                WHERE id=%s AND user_id=%s
                RETURNING id,event_name,date::text,city,country,lat,lon;
            """,(name,date,city,country,lat,lon,event_id,user["uid"]))
            row=c.fetchone()
            if not row: return jsonify({"error":"not found"}),404
            return jsonify(row)
    finally: db_pool.putconn(conn)
