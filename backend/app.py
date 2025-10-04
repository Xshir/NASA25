from flask import Flask, request, jsonify, send_from_directory
import os, hashlib, secrets, datetime as dt
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
        ensure_schema()  # auto-migrate on startup

def ensure_schema():
    """Run idempotent schema setup under an advisory lock to avoid worker races."""
    conn = db_pool.getconn()
    conn.autocommit = False
    cur = conn.cursor()

    # Take a cluster-wide advisory lock (choose any big int; keep it constant)
    cur.execute("SELECT pg_advisory_lock(865042025);")
    try:
        # Tables (IDENTITY is fine; the lock prevents sequence collisions)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name TEXT,
                geom GEOGRAPHY(POINT, 4326),
                event TEXT,
                event_date DATE
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pin_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_sessions (
                token TEXT PRIMARY KEY,
                user_id BIGINT REFERENCES app_users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_events (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT REFERENCES app_users(id) ON DELETE CASCADE,
                event_name TEXT NOT NULL,
                city TEXT,
                lat DOUBLE PRECISION,
                lon DOUBLE PRECISION,
                event_date DATE NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        conn.commit()
    finally:
        # Always release the lock
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
    # Keep it simple but not plain-text: hash( pin + salt )
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
    """Return user_id if Authorization: Bearer <token> is valid, else None."""
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
# Auth: signup & login (username -> lowercase, PIN = 4 digits)
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

    # Optional lat/lon; if provided, we record geometry as well
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_events (user_id, event_name, city, lat, lon, event_date)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (user_id, event_name, city, lat, lon, event_date)
        )
        eid = cur.fetchone()[0]

        # Also mirror to locations if lat/lon provided (keeps PostGIS usage simple)
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
# Suggestions (dummy rules by event type — plug real NASA/Meteomatics later)
# -----------------------------------------------------------------------------
@app.route("/suggest", methods=["POST"])
def suggest():
    """
    Body: { "event_name": "picnic", "date": "2025-06-10", "lat": 1.29, "lon": 103.85 }
    For now returns dummy suggestions using keyword rules.
    """
    user_id = auth_user_id_from_request()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    event_name = (data.get("event_name") or "").lower()

    # Very basic keyword mapping to suggestions (can expand later)
    suggestions = []
    headline = "normal"

    if "picnic" in event_name:
        suggestions = ["bring umbrella", "pack extra ice", "carry sunscreen", "portable fan"]
        headline = "might be hot"
    elif "drone" in event_name:
        suggestions = ["check wind limits", "spare batteries", "no-fly zones", "sun hat"]
        headline = "watch the wind"
    elif "hike" in event_name:
        suggestions = ["water + electrolytes", "insect repellent", "rain jacket", "hat"]
        headline = "humid & warm expected"
    else:
        suggestions = ["weather can vary—carry water", "light rain layer", "sun protection"]
        headline = "general advice"

    return jsonify({
        "predicted": headline,
        "advice": suggestions,
        "note": "dummy rules; NASA+Meteomatics integration pending"
    })

# -----------------------------------------------------------------------------
# Local dev entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if db_pool is None:
        init_db_pool()
    app.run(host="0.0.0.0", port=8000)
