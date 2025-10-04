import requests  
from flask import Flask, request, jsonify, send_from_directory
import os, hashlib, secrets, datetime as dt, json
import psycopg2
from psycopg2 import pool

# -----------------------------------------------------------------------------
# Flask app
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder="static")

# -----------------------------------------------------------------------------
# DB connection pool
# -----------------------------------------------------------------------------
db_pool: pool.SimpleConnectionPool | None = None

def init_db_pool():
    """Create a small connection pool if it doesn't exist yet."""
    global db_pool
    if db_pool is None:
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL not set")
        db_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=db_url
        )
        ensure_schema()  # auto-migrate on startup (with advisory lock)

def ensure_schema():
    """Run idempotent schema setup under an advisory lock to avoid worker races."""
    conn = db_pool.getconn()
    conn.autocommit = False
    cur = conn.cursor()

    # Take a cluster-wide advisory lock (pick a constant big int)
    cur.execute("SELECT pg_advisory_lock(865042025);")
    try:
        # Base locations (keep for PostGIS geometry/mapping demos)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name TEXT,
                geom GEOGRAPHY(POINT, 4326),
                event TEXT,
                event_date DATE
            );
        """)

        # Users
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pin_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        # Sessions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_sessions (
                token TEXT PRIMARY KEY,
                user_id BIGINT REFERENCES app_users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL
            );
        """)

        # Events (include hidden tags JSONB)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_events (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT REFERENCES app_users(id) ON DELETE CASCADE,
                event_name TEXT NOT NULL,
                city TEXT,
                lat DOUBLE PRECISION,
                lon DOUBLE PRECISION,
                event_date DATE NOT NULL,
                tags JSONB DEFAULT '[]'::jsonb,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        # Ensure tags column exists if table predated it
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                  SELECT 1 FROM information_schema.columns
                  WHERE table_schema='public'
                    AND table_name='user_events'
                    AND column_name='tags'
                ) THEN
                  ALTER TABLE user_events ADD COLUMN tags JSONB DEFAULT '[]'::jsonb;
                END IF;
            END $$;
        """)

        conn.commit()
    finally:
        try:
            cur.execute("SELECT pg_advisory_unlock(865042025);")
            conn.commit()
        except Exception:
            conn.rollback()
        cur.close()
        db_pool.putconn(conn)

# Initialize at import
init_db_pool()

@app.before_request
def _ensure_pool():
    if db_pool is None:
        init_db_pool()

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def hash_pin(pin: str) -> str:
    salt = os.getenv("PIN_SALT", "nasa2025_salt")
    return hashlib.sha256((pin + salt).encode("utf-8")).hexdigest()

def validate_pin(pin: str) -> bool:
    return isinstance(pin, str) and len(pin) == 4 and pin.isdigit()

def new_token() -> str:
    return secrets.token_urlsafe(32)

def create_session(user_id: int) -> str:
    token = new_token()
    expires = dt.datetime.utcnow() + dt.timedelta(days=7)
    conn = db_pool.getconn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO app_sessions (token, user_id, expires_at) VALUES (%s, %s, %s);",
        (token, user_id, expires)
    )
    conn.commit()
    cur.close()
    db_pool.putconn(conn)
    return token

def auth_user_id_from_request():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    conn = db_pool.getconn()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id FROM app_sessions
        WHERE token = %s AND expires_at > NOW();
    """, (token,))
    row = cur.fetchone()
    cur.close()
    db_pool.putconn(conn)
    return row[0] if row else None

# ---------- Hidden event tag classifier (no UI) ----------
KEYWORDS = {
    "wind_sensitive":   ["drone", "uav", "kite", "gazebo", "balloon", "aerial", "stage backdrop"],
    "rain_sensitive":   ["wedding", "picnic", "bbq", "market", "festival", "fair", "concert", "outdoor class"],
    "heat_sensitive":   ["marathon", "run", "race", "soccer", "football", "hike", "camp", "picnic", "bbq"],
    "cold_sensitive":   ["swim", "pool", "beach", "outdoor yoga"],
    "sun_exposure":     ["beach", "picnic", "festival", "bbq", "hike", "drone", "shoot", "filming", "photography"],
    "lightning_risk":   ["football", "soccer", "golf", "drone", "concert", "festival"],
    "perishable_food":  ["bbq", "picnic", "catering", "food", "ice cream"],
    "crowd_comfort":    ["concert", "festival", "market", "ceremony", "wedding", "parade"],
    "mud_sensitive":    ["soccer", "football", "camp", "market", "festival", "outdoor class"],
    "water_activity":   ["kayak", "sailing", "boat", "swim", "beach", "surf"],
    "high_exertion":    ["run", "race", "marathon", "soccer", "football", "hike", "cycle", "cycling"],
    "fragile_gear":     ["filming", "camera", "photography", "stage", "pa system", "sound", "lights"],
    "visibility_needed":["filming", "photography", "drone", "stargazing", "astronomy", "sunrise", "sunset"]
}

def classify_event_name(name: str) -> list[str]:
    n = (name or "").lower()
    tags = set()
    for tag, words in KEYWORDS.items():
        for w in words:
            if w in n:
                tags.add(tag)
                break
    if not tags:
        tags.update({"crowd_comfort", "sun_exposure"})
    return sorted(tags)

# -----------------------------------------------------------------------------
# Static site
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.route("/db-check")
def db_check():
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("SELECT PostGIS_Version();")
        version = cur.fetchone()[0]
        cur.close()
        db_pool.putconn(conn)
        return f"Database connected. PostGIS version: {version}"
    except Exception as e:
        return f"DB error: {e}", 500

# -----------------------------------------------------------------------------
# Auth: signup & login
# -----------------------------------------------------------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    pin = str(data.get("pin") or "").strip()

    if not username or not validate_pin(pin):
        return jsonify({"error": "username required and pin must be 4 digits"}), 400

    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM app_users WHERE username = %s;", (username,))
        if cur.fetchone():
            cur.close(); db_pool.putconn(conn)
            return jsonify({"error": "username already exists"}), 409

        cur.execute(
            "INSERT INTO app_users (username, pin_hash) VALUES (%s, %s) RETURNING id;",
            (username, hash_pin(pin))
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        db_pool.putconn(conn)

        token = create_session(user_id)
        return jsonify({"ok": True, "token": token, "username": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    pin = str(data.get("pin") or "").strip()

    if not username or not validate_pin(pin):
        return jsonify({"error": "username required and pin must be 4 digits"}), 400

    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("SELECT id, pin_hash FROM app_users WHERE username = %s;", (username,))
        row = cur.fetchone()
        if not row or row[1] != hash_pin(pin):
            cur.close(); db_pool.putconn(conn)
            return jsonify({"error": "invalid credentials"}), 401

        user_id = row[0]
        cur.close(); db_pool.putconn(conn)

        token = create_session(user_id)
        return jsonify({"ok": True, "token": token, "username": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------------------------------
# Events (auth required)
# -----------------------------------------------------------------------------
@app.route("/events", methods=["POST"])
def create_event():
    user_id = auth_user_id_from_request()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    event_name = (data.get("event_name") or "").strip()
    city = (data.get("city") or "").strip() or None
    lat = data.get("lat")
    lon = data.get("lon")
    event_date = data.get("date")

    if not event_name or not event_date:
        return jsonify({"error": "event_name and date are required"}), 400

    # Hidden: classify and store tags automatically
    tags = classify_event_name(event_name)

    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_events (user_id, event_name, city, lat, lon, event_date, tags)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            RETURNING id;
            """,
            (user_id, event_name, city, lat, lon, event_date, json.dumps(tags))
        )
        eid = cur.fetchone()[0]

        if lat is not None and lon is not None:
            cur.execute(
                """
                INSERT INTO locations (name, geom, event, event_date)
                VALUES (%s, ST_SetSRID(ST_MakePoint(%s, %s), 4326), %s, %s);
                """,
                (city or event_name, float(lon), float(lat), event_name, event_date)
            )

        conn.commit()
        cur.close()
        db_pool.putconn(conn)

        return jsonify({
            "id": eid,
            "event_name": event_name,
            "city": city,
            "lat": lat,
            "lon": lon,
            "date": event_date
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/events", methods=["GET"])
def list_events():
    user_id = auth_user_id_from_request()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, event_name, city, lat, lon, event_date, created_at
            FROM user_events
            WHERE user_id = %s
            ORDER BY created_at DESC;
            """,
            (user_id,)
        )
        rows = cur.fetchall()
        cur.close()
        db_pool.putconn(conn)

        out = []
        for r in rows:
            out.append({
                "id": r[0],
                "event_name": r[1],
                "city": r[2],
                "lat": float(r[3]) if r[3] is not None else None,
                "lon": float(r[4]) if r[4] is not None else None,
                "date": str(r[5]),
                "created_at": r[6].isoformat() if r[6] else None
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------------------------------
# Suggestions (use stored tags by event_id, otherwise infer)
# -----------------------------------------------------------------------------
@app.route("/suggest", methods=["POST"])
def suggest():
    """
    Body: { "event_id": 123 }  -> uses saved tags
       or { "event_name": "picnic", "date":"2025-06-10", "lat":..., "lon":... } -> infers tags
    Weather-based logic will be added later; now we map tags to prep advice.
    """
    user_id = auth_user_id_from_request()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id")
    tags = None
    event_name = (data.get("event_name") or "").strip()

    # Prefer stored tags via event_id
    if event_id is not None:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("""
            SELECT event_name, COALESCE(tags, '[]'::jsonb)
            FROM user_events
            WHERE id = %s AND user_id = %s;
        """, (event_id, user_id))
        row = cur.fetchone()
        cur.close(); db_pool.putconn(conn)
        if row:
            event_name = row[0]
            try:
                tags = list(row[1]) if isinstance(row[1], list) else row[1]
            except Exception:
                tags = None

    # Fallback: infer from provided event_name
    if not tags:
        tags = classify_event_name(event_name)

    # Rule engine: tags -> tips (dedupe)
    adv = []
    if "wind_sensitive" in tags:   adv += ["check wind forecast limits", "bring extra weights/anchors", "avoid high structures"]
    if "rain_sensitive" in tags:   adv += ["pack rain covers", "identify indoor fallback", "check ground drainage"]
    if "heat_sensitive" in tags:   adv += ["shade tents / fans", "electrolytes & water", "schedule cooler hours"]
    if "cold_sensitive" in tags:   adv += ["warm layers", "thermal blankets", "hot drinks"]
    if "sun_exposure" in tags:     adv += ["sunscreen & hats", "shade areas", "UV index check"]
    if "lightning_risk" in tags:   adv += ["monitor lightning alerts", "define shelter protocol", "avoid tall metal poles"]
    if "perishable_food" in tags:  adv += ["coolers & ice packs", "food safety window < 2h", "shade for serving tables"]
    if "crowd_comfort" in tags:    adv += ["extra water points", "rest/shade zones", "first-aid ready"]
    if "mud_sensitive" in tags:    adv += ["ground mats/boards", "non-slip paths", "spare footwear"]
    if "water_activity" in tags:   adv += ["current/wave check", "life jackets", "no-go thresholds defined"]
    if "high_exertion" in tags:    adv += ["heat stress plan", "scheduled breaks", "buddy checks"]
    if "fragile_gear" in tags:     adv += ["hard cases & covers", "cables off ground", "GFCI power"]
    if "visibility_needed" in tags:adv += ["cloud cover check", "bring lights/reflectors", "backup time slot"]
    adv = sorted(list(dict.fromkeys(adv)))

    return jsonify({
        "predicted": "contextual tips (weather-driven soon)",
        "advice": adv,
        "note": "Event analyzed automatically; suggestions will incorporate NASA/Meteomatics next."
    })

@app.route("/reverse_geocode")
def reverse_geocode():
    """Server-side proxy to avoid CORS; returns {country, city} best-effort."""
    lat = request.args.get("lat")
    lon = request.args.get("lon")
    if not lat or not lon:
        return jsonify({"error": "lat and lon required"}), 400

    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": 10, "addressdetails": 1},
            headers={"User-Agent": "NASA_2025/1.0 (contact: team@example.com)"},  # put your email/team url
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()
        addr = data.get("address", {}) if isinstance(data, dict) else {}

        country = addr.get("country") or addr.get("country_code", "").upper() or None
        # Prefer city/town/village/suburb in that order
        city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("suburb") or addr.get("state")

        return jsonify({"country": country, "city": city})
    except Exception as e:
        return jsonify({"error": str(e)}), 502

@app.route("/events/<int:event_id>", methods=["PUT"])
def update_event(event_id):
    user_id = auth_user_id_from_request()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    event_name = (data.get("event_name") or "").strip()
    city = (data.get("city") or "").strip() or None
    lat = data.get("lat")
    lon = data.get("lon")
    event_date = data.get("date")

    if not event_name or not event_date:
        return jsonify({"error": "event_name and date are required"}), 400

    tags = classify_event_name(event_name)  # refresh tags if name changed

    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("""
            UPDATE user_events
               SET event_name=%s, city=%s, lat=%s, lon=%s, event_date=%s, tags=%s::jsonb
             WHERE id=%s AND user_id=%s
            RETURNING id;
        """, (event_name, city, lat, lon, event_date, json.dumps(tags), event_id, user_id))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            cur.close(); db_pool.putconn(conn)
            return jsonify({"error": "not found"}), 404

        conn.commit()
        cur.close(); db_pool.putconn(conn)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------------------------------
# Local dev entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if db_pool is None:
        init_db_pool()
    app.run(host="0.0.0.0", port=8000)
