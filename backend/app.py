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
# In-memory caches for countries & cities
# ------------------------------------------------------------------------------
COUNTRY_CACHE = {"ts": 0, "data": []}                   # [{"name":"Singapore","code":"SG"}, ...]
CITY_CACHE: dict[str, dict] = {}                         # {"SG": {"ts": 0, "data": ["Singapore"]}, ...}
CACHE_TTL_COUNTRIES = 60 * 60 * 24 * 7                   # 7 days
CACHE_TTL_CITIES = 60 * 60 * 24 * 3                      # 3 days

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
    """Create/upgrade schema idempotently (safe even if table already exists)."""
    conn = db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(420420);")
                # Base tables
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
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );""")
                # Add missing columns safely
                cur.execute("""ALTER TABLE events
                               ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();""")
                # Indexes
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
# External weather data
# ------------------------------------------------------------------------------
def get_meteomatics_summary(lat: float, lon: float, date_iso: str):
    """Fetch Meteomatics daily summary (free-tier safe)."""
    if not (MM_USER and MM_PASS):
        app.logger.warning("[Meteomatics] Missing credentials")
        return None
    try:
        d = dt.datetime.fromisoformat(date_iso)
        params = "t_max_2m_24h:C,t_min_2m_24h:C,precip_24h:mm"
        url = f"https://api.meteomatics.com/{d:%Y-%m-%dT00:00:00Z}/{params}/{lat:.4f},{lon:.4f}/json"
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
            "source": "meteomatics (daily aggregate)"
        }
        app.logger.info(f"[Meteomatics summary] {out}")
        return out
    except Exception as e:
        app.logger.error(f"[Meteomatics EXC] {e}")
        return None

def get_nasa_power(lat: float, lon: float, date_iso: str):
    """NASA POWER climatology; skip gracefully for future dates."""
    try:
        d = dt.datetime.fromisoformat(date_iso)
        url = (
            "https://power.larc.nasa.gov/api/temporal/daily/point"
            f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN"
            f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}"
            f"&start={d:%Y%m%d}&end={d:%Y%m%d}&format=JSON"
        )
        r = requests.get(url, timeout=12)
        if r.status_code in (400, 500):
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
        out = {"tmax": tmax, "tmin": tmin, "avg_temp": (tmax + tmin)/2.0,
               "precip": precip, "solar": solar, "source": "nasa_power"}
        app.logger.info(f"[NASA POWER] {out}")
        return out
    except Exception as e:
        app.logger.error(f"[NASA EXC] {e}")
        return None

# ------------------------------------------------------------------------------
def interpret_conditions(m, event_name: str):
    """Convert metrics + event name into readable prediction + tips."""
    if not m:
        return "mixed conditions", ["bring umbrella just in case", "water bottle", "sunscreen"]

    tips = []
    tmax = m.get("t_max"); rain = m.get("precip_24h", 0) or 0
    if tmax is not None and tmax >= 33: label = "very hot"
    elif rain >= 10: label = "very wet"
    elif tmax is not None and tmax <= 18: label = "cool"
    else: label = "fair"

    if label == "very hot": tips += ["bring shade/canopy", "portable fans", "stay hydrated"]
    if label == "very wet": tips += ["raincoat", "waterproof bag", "check shelter options"]
    if label == "cool": tips += ["light jacket"]

    e = (event_name or "").lower()
    if any(k in e for k in ["drone", "flying", "aerial"]):
        tips += ["check wind before flight", "bring ND filters", "spare batteries", "consider skipping if winds exceed 10 m/s"]
    elif any(k in e for k in ["wedding", "ceremony", "party"]):
        tips += ["confirm canopy vendor", "backup indoor location", "protect photo gear"]
    elif any(k in e for k in ["picnic", "bbq", "beach", "park"]):
        tips += ["cooler with ice", "sunscreen", "ground mat"]
    elif any(k in e for k in ["hike", "trail", "trek"]):
        tips += ["hydration pack", "insect repellent", "trail shoes"]

    seen = set()
    tips = [t for t in tips if not (t in seen or seen.add(t))]
    return label, tips

# ------------------------------------------------------------------------------
# JSON error handlers
# ------------------------------------------------------------------------------
def _wants_json():
    a = request.headers.get("Accept",""); c = request.headers.get("Content-Type","")
    return ("application/json" in a) or ("application/json" in c)

@app.errorhandler(404)
def _404(e):
    if _wants_json(): return jsonify({"error":"not found"}),404
    if request.method=="GET": return send_from_directory("/app/static","index.html")
    return "Not found",404

@app.errorhandler(500)
def _500(e):
    app.logger.error(f"[500] {e}")
    return (jsonify({"error":"server error"}),500) if _wants_json() else ("Server error",500)

# ------------------------------------------------------------------------------
# Core routes
# ------------------------------------------------------------------------------
@app.get("/health")
def health(): return jsonify({"ok": True, "ts": time.time()})

@app.post("/signup")
def signup():
    init_db_pool()
    d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower()
    p=(d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p)!=4: return jsonify({"error":"invalid"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("INSERT INTO app_users(username,pin_hash) VALUES(%s,%s) ON CONFLICT(username) DO NOTHING RETURNING id;",(u,ph))
            row=c.fetchone()
            if not row:
                c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
                row2=c.fetchone()
                if not row2 or row2["pin_hash"]!=ph: return jsonify({"error":"username exists"}),409
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
    if not u or not p.isdigit() or len(p)!=4: return jsonify({"error":"invalid"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
            row=c.fetchone()
            if not row or row["pin_hash"]!=ph: return jsonify({"error":"invalid"}),401
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
            c.execute("""SELECT id,event_name,date::text AS date,city,country,lat,lon
                         FROM events WHERE user_id=%s ORDER BY date ASC,id ASC;""",(user["uid"],))
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
    if not name or not date: return jsonify({"error":"missing fields"}),400
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""INSERT INTO events(user_id,event_name,date,city,country,lat,lon)
                         VALUES(%s,%s,%s,%s,%s,%s,%s)
                         RETURNING id,event_name,date::text AS date,city,country,lat,lon;""",
                      (user["uid"],name,date,city,country,lat,lon))
            return jsonify(c.fetchone()),201
    finally: db_pool.putconn(conn)

@app.put("/events/<int:event_id>")
@require_auth
def update_event(user, event_id: int):
    init_db_pool()
    d=request.get_json(force=True)
    name=(d.get("event_name") or "").strip()
    date=(d.get("date") or "").strip()
    city=(d.get("city") or "").strip() or None
    country=(d.get("country") or "").strip() or None
    lat=d.get("lat"); lon=d.get("lon")
    if not name or not date: return jsonify({"error":"missing fields"}),400

    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""UPDATE events
                         SET event_name=%s,date=%s,city=%s,country=%s,lat=%s,lon=%s,updated_at=NOW()
                         WHERE id=%s AND user_id=%s
                         RETURNING id,event_name,date::text AS date,city,country,lat,lon;""",
                      (name,date,city,country,lat,lon,event_id,user["uid"]))
            row=c.fetchone()
            if not row: return jsonify({"error":"not found"}),404
            return jsonify(row)
    finally: db_pool.putconn(conn)

@app.post("/suggest")
@require_auth
def suggest(user):
    d=request.get_json(force=True)
    event_name=(d.get("event_name") or "").strip()
    date=d.get("date"); lat=d.get("lat"); lon=d.get("lon")
    event_id=d.get("event_id")
    if event_id and (not date or lat is None or lon is None or not event_name):
        conn=db_pool.getconn()
        try:
            with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
                c.execute("""SELECT event_name,date::text AS date,lat,lon FROM events
                             WHERE id=%s AND user_id=%s;""",(event_id,user["uid"]))
                row=c.fetchone()
                if not row: return jsonify({"error":"event not found"}),404
                event_name=event_name or row["event_name"]; date=date or row["date"]
                lat=lat if lat is not None else row["lat"]; lon=lon if lon is not None else row["lon"]
        finally: db_pool.putconn(conn)

    app.logger.info(f"[/suggest] event={event_name} date={date} coords=({lat},{lon})")
    mm=nasa=None
    if date and lat and lon:
        mm=get_meteomatics_summary(float(lat),float(lon),date)
        nasa=get_nasa_power(float(lat),float(lon),date)
    app.logger.info(f"[/suggest] mm={mm} nasa={nasa}")

    label,tips=interpret_conditions(mm,event_name)
    stats_text=None
    if mm:
        tmax=mm.get("t_max"); rain=mm.get("precip_24h",0)
        if tmax is not None:
            stats_text=f"(Max {tmax:.1f}°C, Rain {rain:.1f} mm)"
    elif nasa:
        stats_text=f"(Max {nasa.get('tmax',0):.1f}°C, Rain {nasa.get('precip',0):.1f} mm)"

    return jsonify({
        "predicted": f"{label} {stats_text or ''}".strip(),
        "advice": tips,
        "metrics": mm or {},
        "nasa_power": nasa or {},
        "note": "Forecast fused from Meteomatics and NASA POWER climatology."
    })

# ------------------------------------------------------------------------------
# Current weather for Home screen
# ------------------------------------------------------------------------------
@app.get("/current_weather")
def current_weather():
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    if lat is None or lon is None or not (MM_USER and MM_PASS):
        return jsonify({})
    try:
        now = dt.datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        params = "t_2m:C,weather_symbol_1h:idx"
        url = f"https://api.meteomatics.com/{now:%Y-%m-%dT%H:%M:%SZ}/{params}/{lat:.4f},{lon:.4f}/json"
        r = requests.get(url, auth=(MM_USER, MM_PASS), timeout=10)
        app.logger.info(f"[current_weather] {r.status_code} {url}")

        desc = "Unknown"
        temp = None
        if r.status_code == 200:
            js = r.json()
            vals = {p["parameter"]: p["coordinates"][0]["dates"][0]["value"]
                    for p in js.get("data", []) if p.get("coordinates")}
            temp = vals.get("t_2m:C")
            sym = vals.get("weather_symbol_1h:idx")
            if sym is not None:
                try: code = int(sym)
                except: code = 0
                desc = {
                    1:"Clear",2:"Mostly clear",3:"Partly cloudy",4:"Overcast",
                    5:"Fog",6:"Light rain",7:"Rain",8:"Heavy rain",9:"Snow",10:"Thunderstorms"
                }.get(code,"Unknown")

        if temp is None:
            return jsonify({})
        return jsonify({"temp": temp, "desc": desc})
    except Exception as e:
        app.logger.error(f"[current_weather EXC] {e}")
        return jsonify({})

# ------------------------------------------------------------------------------
# Geo endpoints: ALL countries + preset cities per country
# ------------------------------------------------------------------------------
@app.get("/geo/countries")
def geo_countries():
    """Return [{name, code}] of all countries (cached)."""
    try:
        now = time.time()
        if COUNTRY_CACHE["data"] and now - COUNTRY_CACHE["ts"] < CACHE_TTL_COUNTRIES:
            return jsonify(COUNTRY_CACHE["data"])
        r = requests.get("https://restcountries.com/v3.1/all?fields=name,cca2", timeout=15)
        r.raise_for_status()
        out = []
        for it in r.json():
            nm = (it.get("name",{}) or {}).get("common")
            code = it.get("cca2")
            if nm and code:
                out.append({"name": nm, "code": code.upper()})
        out.sort(key=lambda x: x["name"])
        COUNTRY_CACHE["data"] = out
        COUNTRY_CACHE["ts"] = now
        return jsonify(out)
    except Exception as e:
        app.logger.warning(f"[geo_countries] fallback due {e}")
        fallback = [
            {"name":"Singapore","code":"SG"},{"name":"Japan","code":"JP"},
            {"name":"United States","code":"US"},{"name":"Malaysia","code":"MY"},
            {"name":"Indonesia","code":"ID"},{"name":"Thailand","code":"TH"},
            {"name":"Vietnam","code":"VN"},{"name":"Philippines","code":"PH"},
            {"name":"India","code":"IN"},{"name":"China","code":"CN"},
            {"name":"Australia","code":"AU"},{"name":"United Kingdom","code":"GB"}
        ]
        return jsonify(fallback)

@app.get("/geo/cities")
def geo_cities():
    """
    Return top cities for a given country.
    Query: ?code=SG or ?country=Singapore
    Uses Overpass API (OSM) and caches results.
    """
    code = (request.args.get("code") or "").strip().upper()
    country = (request.args.get("country") or "").strip()

    # Special case: Singapore as a city-state
    if code == "SG" or country.lower() == "singapore":
        return jsonify({"code":"SG","country":"Singapore","cities":[],"cityless":True})

    # Resolve code via cache if only country provided
    if not code and country:
        if not COUNTRY_CACHE["data"]:
            try:
                rc = requests.get("https://restcountries.com/v3.1/all?fields=name,cca2", timeout=10)
                if rc.status_code == 200:
                    COUNTRY_CACHE["data"] = [
                        {"name": (it.get("name",{}) or {}).get("common"), "code": it.get("cca2","").upper()}
                        for it in rc.json() if (it.get("name",{}) or {}).get("common") and it.get("cca2")
                    ]
            except Exception:
                pass
        for item in COUNTRY_CACHE["data"]:
            if item["name"].lower() == country.lower():
                code = item["code"]
                break

    if not code:
        return jsonify({"cities":[]})

    # cache
    now = time.time()
    cached = CITY_CACHE.get(code)
    if cached and (now - cached["ts"] < CACHE_TTL_CITIES):
        return jsonify({"code": code, "country": country or code, "cities": cached["data"]})

    try:
        # Overpass query: cities and large towns within country by ISO3166-1 code
        q = f"""
        [out:json][timeout:25];
        area["ISO3166-1"="{code}"][admin_level=2]->.boundary;
        (
          node["place"="city"](area.boundary);
          node["place"="town"](area.boundary);
        );
        out tags;
        """
        r = requests.post("https://overpass-api.de/api/interpreter", data=q.encode("utf-8"), timeout=30)
        if r.status_code != 200:
            app.logger.warning(f"[geo_cities] Overpass {r.status_code}: {r.text[:120]}")
            return jsonify({"code":code, "country":country or code, "cities":[]})

        js = r.json()
        items = []
        for el in js.get("elements", []):
            tags = el.get("tags", {})
            nm = tags.get("name:en") or tags.get("name")
            if not nm: continue
            pop = tags.get("population")
            try: pop = int(str(pop).replace(",","")) if pop else 0
            except Exception: pop = 0
            items.append((nm, pop))

        # dedupe by name keep max pop
        byname = {}
        for nm, pop in items:
            if nm not in byname or pop > byname[nm]:
                byname[nm] = pop
        # sort by population desc, then name
        sorted_names = sorted(byname.items(), key=lambda x:(-x[1], x[0]))[:80]
        cities = [nm for nm,_ in sorted_names] or sorted(byname.keys())[:80]

        CITY_CACHE[code] = {"ts": now, "data": cities}
        return jsonify({"code": code, "country": country or code, "cities": cities})
    except Exception as e:
        app.logger.error(f"[geo_cities EXC] {e}")
        return jsonify({"code": code, "country": country or code, "cities": []})

# ------------------------------------------------------------------------------
# Reverse geocoding (adds country_code)
# ------------------------------------------------------------------------------
def reverse_geocode_core(lat: float, lon: float):
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
        code = addr.get("country_code").upper() if addr.get("country_code") else None
        return {"city": city, "country": country, "country_code": code}
    except Exception:
        return {}

@app.get("/reverse_geocode")
def api_reverse_geocode():
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    if lat is None or lon is None:
        return jsonify({})
    return jsonify(reverse_geocode_core(lat, lon))

# ------------------------------------------------------------------------------
# Static frontend
# ------------------------------------------------------------------------------
@app.get("/")
def root(): return send_from_directory("/app/static","index.html")

@app.get("/<path:path>")
def static_proxy(path):
    try: return send_from_directory("/app/static",path)
    except Exception: return _404(None)

# ------------------------------------------------------------------------------
init_db_pool()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=8000,debug=True)