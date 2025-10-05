import os, time, json, hashlib, datetime as dt, requests, logging
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2 import pool as psycopool
from psycopg2.extras import RealDictCursor

# ---------------------------------------------------------------------
# APP SETUP
# ---------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
CORS(app, supports_credentials=False)
app.logger.setLevel(logging.INFO)

APP_SECRET = os.getenv("APP_SECRET", "dev-secret")
MM_USER = os.getenv("MM_USERNAME")
MM_PASS = os.getenv("MM_PASSWORD")

DB_CFG = dict(
    host=os.getenv("POSTGRES_HOST", "db"),
    port=int(os.getenv("POSTGRES_PORT", "5432")),
    dbname=os.getenv("POSTGRES_DB", "nasa2025"),
    user=os.getenv("POSTGRES_USER", "nasa2025"),
    password=os.getenv("POSTGRES_PASSWORD", "nasa2025"),
)

db_pool = None

# ---------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------
def init_db_pool():
    global db_pool
    if db_pool:
        return
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            db_pool = psycopool.SimpleConnectionPool(1, 8, **DB_CFG)
            conn = db_pool.getconn()
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1;")
            db_pool.putconn(conn)
            break
        except Exception as e:
            app.logger.warning(f"[DB] retry {e}")
            time.sleep(2)
    if not db_pool:
        raise RuntimeError("DB not reachable")
    ensure_schema()

def ensure_schema():
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor() as cur:
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
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON app_users(username);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, date);")
            cur.execute("SELECT pg_advisory_unlock(420420);")
    finally:
        db_pool.putconn(conn)

# ---------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------
def _hash_pin(u,p): return hashlib.sha256(f"{u}:{p}:{APP_SECRET}".encode()).hexdigest()
def _sign(payload):
    data = json.dumps(payload,separators=(",",":"))
    sig  = hashlib.sha256((data+APP_SECRET).encode()).hexdigest()
    return f"{data}.{sig}"
def _verify(tok):
    try:
        data,sig = tok.rsplit(".",1)
        if hashlib.sha256((data+APP_SECRET).encode()).hexdigest()!=sig: return None
        p=json.loads(data)
        if "exp" in p and time.time()>p["exp"]: return None
        return p
    except: return None
def issue_token(uid,u): return _sign({"uid":uid,"username":u,"exp":time.time()+604800})
def require_auth(fn):
    @wraps(fn)
    def wrap(*a,**kw):
        h=request.headers.get("Authorization","")
        if not h.startswith("Bearer "): return jsonify({"error":"unauthorized"}),401
        p=_verify(h[7:])
        if not p: return jsonify({"error":"unauthorized"}),401
        return fn(user=p,*a,**kw)
    return wrap

# ---------------------------------------------------------------------
# EXTERNAL WEATHER HELPERS
# ---------------------------------------------------------------------
def get_meteomatics(lat,lon,date):
    if not (MM_USER and MM_PASS): return None
    try:
        d=dt.datetime.fromisoformat(date)
        url=f"https://api.meteomatics.com/{d:%Y-%m-%dT00:00:00Z}/t_max_2m_24h:C,t_min_2m_24h:C,precip_24h:mm/{lat:.4f},{lon:.4f}/json"
        r=requests.get(url,auth=(MM_USER,MM_PASS),timeout=12)
        if r.status_code!=200: return None
        js=r.json()
        data={p["parameter"]:p["coordinates"][0]["dates"][0]["value"] for p in js.get("data",[]) if p.get("coordinates")}
        return {"t_max":data.get("t_max_2m_24h:C"),"t_min":data.get("t_min_2m_24h:C"),"precip_24h":data.get("precip_24h:mm",0)}
    except: return None

def get_nasa_power(lat,lon,date):
    try:
        d=dt.datetime.fromisoformat(date)
        url=("https://power.larc.nasa.gov/api/temporal/daily/point"
             f"?parameters=T2M_MAX,T2M_MIN,PRECTOTCORR"
             f"&community=RE&longitude={lon:.4f}&latitude={lat:.4f}&start={d:%Y%m%d}&end={d:%Y%m%d}&format=JSON")
        r=requests.get(url,timeout=12)
        if r.status_code!=200: return None
        p=r.json().get("properties",{}).get("parameter",{})
        tmax=list(p.get("T2M_MAX",{}).values())[0]
        tmin=list(p.get("T2M_MIN",{}).values())[0]
        rain=list(p.get("PRECTOTCORR",{}).values())[0]
        return {"tmax":tmax,"tmin":tmin,"precip":rain}
    except: return None

def interpret_conditions(m,e):
    e=(e or "").lower();tips=[]
    if not m: label="mixed conditions"
    else:
        t=m.get("t_max") or m.get("tmax"); r=m.get("precip_24h") or m.get("precip") or 0
        if t and t>=33: label="very hot"; tips+=["bring water","shade","fans"]
        elif r>=10: label="very wet"; tips+=["raincoat","shelter plan"]
        elif t and t<=18: label="cool"; tips+=["light jacket"]
        else: label="fair"; tips+=["good weather"]
    if any(k in e for k in["drone","fly","aerial"]): tips+=["check wind","avoid >10 m/s gusts","extra batteries"]
    elif any(k in e for k in["wedding","ceremony"]): tips+=["confirm canopy","backup indoor plan"]
    elif any(k in e for k in["sports","match","run"]): tips+=["hydration","shade tents"]
    elif any(k in e for k in["picnic","bbq","beach"]): tips+=["cooler","repellent"]
    elif any(k in e for k in["hike","trail"]): tips+=["trail shoes","insect spray"]
    seen=set();tips=[t for t in tips if not(t in seen or seen.add(t))]
    return label,tips

def reverse_geocode(lat,lon):
    try:
        r=requests.get("https://nominatim.openstreetmap.org/reverse",
            params={"format":"jsonv2","lat":lat,"lon":lon,"zoom":10,"addressdetails":1},
            headers={"User-Agent":"Plan4Cast/1.0"},timeout=8)
        if r.status_code!=200:return{}
        a=r.json().get("address",{})
        return {"city":a.get("city")or a.get("town"),
                "country":a.get("country"),
                "country_code":(a.get("country_code") or "").upper()}
    except:return{}

# ---------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------
@app.get("/health")
def health(): return jsonify({"ok":True})

@app.post("/signup")
def signup():
    init_db_pool();d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower(); p=(d.get("pin") or "").strip()
    if not u or not p.isdigit() or len(p)!=4: return jsonify({"error":"invalid"}),400
    ph=_hash_pin(u,p)
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("INSERT INTO app_users(username,pin_hash) VALUES(%s,%s) ON CONFLICT(username) DO NOTHING RETURNING id;",(u,ph))
            row=c.fetchone()
            if not row:
                c.execute("SELECT id,pin_hash FROM app_users WHERE username=%s;",(u,))
                r2=c.fetchone()
                if not r2 or r2["pin_hash"]!=ph: return jsonify({"error":"username exists"}),409
                uid=r2["id"]
            else: uid=row["id"]
    finally: db_pool.putconn(conn)
    return jsonify({"ok":True,"token":issue_token(uid,u)})

@app.post("/login")
def login():
    init_db_pool();d=request.get_json(force=True)
    u=(d.get("username") or "").strip().lower(); p=(d.get("pin") or "").strip()
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
    init_db_pool();conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT id,event_name,date::text,city,country,lat,lon FROM events WHERE user_id=%s ORDER BY date;",(user["uid"],))
            return jsonify(c.fetchall())
    finally: db_pool.putconn(conn)

@app.post("/events")
@require_auth
def create_event(user):
    d=request.get_json(force=True)
    name=d.get("event_name"); date=d.get("date"); city=d.get("city"); country=d.get("country")
    lat=d.get("lat"); lon=d.get("lon")
    if not name or not date: return jsonify({"error":"missing"}),400
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""INSERT INTO events(user_id,event_name,date,city,country,lat,lon)
                         VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *;""",
                      (user["uid"],name,date,city,country,lat,lon))
            return jsonify(c.fetchone()),201
    finally: db_pool.putconn(conn)

@app.put("/events/<int:id>")
@require_auth
def update_event(user,id):
    d=request.get_json(force=True)
    name=d.get("event_name"); date=d.get("date"); city=d.get("city"); country=d.get("country")
    lat=d.get("lat"); lon=d.get("lon")
    conn=db_pool.getconn()
    try:
        with conn,conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""UPDATE events SET event_name=%s,date=%s,city=%s,country=%s,
                         lat=%s,lon=%s,updated_at=NOW()
                         WHERE id=%s AND user_id=%s RETURNING *;""",
                      (name,date,city,country,lat,lon,id,user["uid"]))
            row=c.fetchone()
            if not row: return jsonify({"error":"not found"}),404
            return jsonify(row)
    finally: db_pool.putconn(conn)

@app.post("/suggest")
@require_auth
def suggest(user):
    d=request.get_json(force=True)
    event=d.get("event_name"); date=d.get("date"); lat=d.get("lat"); lon=d.get("lon")
    if not(date and lat and lon): return jsonify({"error":"missing"}),400
    mm=get_meteomatics(float(lat),float(lon),date)
    ns=get_nasa_power(float(lat),float(lon),date)
    label,tips=interpret_conditions(mm or ns,event)
    tmax=(mm or ns or {}).get("t_max") or (mm or ns or {}).get("tmax")
    rain=(mm or ns or {}).get("precip_24h") or (mm or ns or {}).get("precip")
    emoji="🌤️"
    if label=="very hot":emoji="☀️"
    elif label=="very wet":emoji="🌧️"
    elif label=="cool":emoji="❄️"
    elif "wind" in label:emoji="💨"
    stats=f"(Max {tmax or 0:.1f}°C, Rain {rain or 0:.1f} mm)"
    return jsonify({"predicted":f"{emoji} {label.title()} {stats}",
                    "advice":tips,
                    "note":"Forecast generated using NASA POWER and Meteomatics APIs."})

@app.get("/current_weather")
def current_weather():
    lat=request.args.get("lat",type=float); lon=request.args.get("lon",type=float)
    if lat is None or lon is None: return jsonify({})
    try:
        now=dt.datetime.utcnow().replace(minute=0,second=0,microsecond=0)
        url=f"https://api.meteomatics.com/{now:%Y-%m-%dT%H:%M:%SZ}/t_2m:C,weather_symbol_1h:idx/{lat:.4f},{lon:.4f}/json"
        r=requests.get(url,auth=(MM_USER,MM_PASS),timeout=10)
        if r.status_code!=200: return jsonify({})
        js=r.json()
        vals={p["parameter"]:p["coordinates"][0]["dates"][0]["value"] for p in js.get("data",[])}
        desc={1:"Clear",2:"Mostly clear",3:"Partly cloudy",4:"Overcast",5:"Fog",6:"Light rain",
              7:"Rain",8:"Heavy rain",9:"Snow",10:"Thunderstorms"}.get(int(vals.get("weather_symbol_1h:idx",0)),"Unknown")
        return jsonify({"temp":vals.get("t_2m:C"),"desc":desc})
    except: return jsonify({})

@app.get("/geo/countries")
def geo_countries():
    try:
        r=requests.get("https://restcountries.com/v3.1/all?fields=name,cca2",timeout=15)
        out=[{"name":i["name"]["common"],"code":i["cca2"].upper()}for i in r.json()]
        return jsonify(sorted(out,key=lambda x:x["name"]))
    except: return jsonify([{"name":"Singapore","code":"SG"}])

@app.get("/geo/cities")
def geo_cities():
    code=(request.args.get("code") or "").upper()
    if code=="SG": return jsonify({"cities":["Singapore"],"cityless":True})
    try:
        q=f"""[out:json][timeout:20];area["ISO3166-1"="{code}"][admin_level=2]->.a;(node["place"="city"](area.a););out tags;"""
        r=requests.post("https://overpass-api.de/api/interpreter",data=q.encode(),timeout=20)
        if r.status_code!=200: return jsonify({"cities":[]})
        names=[e["tags"].get("name:en") or e["tags"].get("name") for e in r.json().get("elements",[]) if e.get("tags")]
        return jsonify({"cities":sorted(set(filter(None,names)))[:80]})
    except: return jsonify({"cities":[]})

@app.get("/reverse_geocode")
def reverse_geo(): 
    lat=request.args.get("lat",type=float); lon=request.args.get("lon",type=float)
    if lat is None or lon is None: return jsonify({})
    return jsonify(reverse_geocode(lat,lon))

@app.get("/")
def root(): return send_from_directory("/app/static","index.html")
@app.get("/<path:p>")
def static_files(p):
    try: return send_from_directory("/app/static",p)
    except: return send_from_directory("/app/static","index.html")

# ---------------------------------------------------------------------
init_db_pool()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=8000,debug=True)
