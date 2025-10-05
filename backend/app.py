# app.py
import os
import json
import hashlib
import hmac
import time
from functools import wraps
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool

import requests  # used for reverse geocoding proxy

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DB_HOST = os.getenv("POSTGRES_HOST", "db")
DB_PORT = int(os.getenv("POSTGRES_PORT", 5432))
DB_NAME = os.getenv("POSTGRES_DB", "nasa2025")
DB_USER = os.getenv("POSTGRES_USER", "nasa2025")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "nasa2025")

SECRET = os.getenv("APP_SECRET", "change-me-please")  # used to sign tokens

# -----------------------------------------------------------------------------
# App & static
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", static_url_path="/")
CORS(app, supports_credentials=True)

# -----------------------------------------------------------------------------
# DB pool & schema
# -----------------------------------------------------------------------------
db_pool: pool.SimpleConnectionPool = None

def init_db_pool():
    global db_pool
    if db_pool:
        return
    db_pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1,
        maxconn=8,
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
    )
    ensure_schema()

def ensure_schema():
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
              id BIGSERIAL PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              pin_hash TEXT NOT NULL,
              created_at TIMESTAMPTZ DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS events (
              id BIGSERIAL PRIMARY KEY,
              user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
              event_name TEXT NOT NULL,
              date DATE NOT NULL,
              country TEXT,
              city TEXT,
              lat DOUBLE PRECISION,
              lon DOUBLE PRECISION,
              created_at TIMESTAMPTZ DEFAULT now()
            );
            """)
    finally:
        db_pool.putconn(conn)

# initialize at import time (no before_first_request)
init_db_pool()

# -----------------------------------------------------------------------------
# Tiny auth (PIN -> SHA256; token = signed JSON)
# -----------------------------------------------------------------------------
def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()

def make_token(user_id: int, username: str) -> str:
    payload = {"uid": user_id, "u": username, "ts": int(time.time())}
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def verify_token(token: str):
    try:
        body, sig = token.rsplit(".", 1)
        exp_sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, exp_sig):
            return None
        payload = json.loads(body)
        return payload
    except Exception:
        return None

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "unauthorized"}), 401
        # fetch user quick
        conn = db_pool.getconn()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, username FROM app_users WHERE id=%s", (payload["uid"],))
                user = cur.fetchone()
                if not user:
                    return jsonify({"error": "unauthorized"}), 401
        finally:
            db_pool.putconn(conn)
        return fn(user, *args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Static index
# -----------------------------------------------------------------------------
@app.get("/")
def index_html():
    return send_from_directory(app.static_folder, "index.html")

# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"ok": True, "time": datetime.utcnow().isoformat()}

# -----------------------------------------------------------------------------
# Auth endpoints
# -----------------------------------------------------------------------------
@app.post("/signup")
def signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    pin = (data.get("pin") or "").strip()
    if not username or not pin or not pin.isdigit() or len(pin) != 4:
        return jsonify({"error": "Username and 4-digit PIN required"}), 400

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM app_users WHERE username=%s", (username,))
            if cur.fetchone():
                return jsonify({"error": "username taken"}), 409
            cur.execute(
                "INSERT INTO app_users (username, pin_hash) VALUES (%s, %s) RETURNING id, username",
                (username, hash_pin(pin))
            )
            row = cur.fetchone()
            tok = make_token(row["id"], row["username"])
            return jsonify({"ok": True, "token": tok})
    finally:
        db_pool.putconn(conn)

@app.post("/login")
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    pin = (data.get("pin") or "").strip()
    if not username or not pin:
        return jsonify({"error": "Username and PIN required"}), 400

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, username, pin_hash FROM app_users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row or row["pin_hash"] != hash_pin(pin):
                return jsonify({"error": "invalid credentials"}), 401
            tok = make_token(row["id"], row["username"])
            return jsonify({"ok": True, "token": tok})
    finally:
        db_pool.putconn(conn)

# -----------------------------------------------------------------------------
# Events CRUD
# -----------------------------------------------------------------------------
@app.get("/events")
@require_auth
def list_events(user):
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, event_name, date::text AS date, country, city, lat, lon
                FROM events
                WHERE user_id=%s
                ORDER BY date ASC, id DESC
            """, (user["id"],))
            rows = cur.fetchall()
            return jsonify(rows)
    finally:
        db_pool.putconn(conn)

@app.post("/events")
@require_auth
def create_event(user):
    data = request.get_json(force=True)
    name = (data.get("event_name") or "").strip()
    date = data.get("date")
    country = (data.get("country") or "").strip() or None
    city = (data.get("city") or "").strip() or None
    lat = data.get("lat")
    lon = data.get("lon")

    if not name or not date:
        return jsonify({"error": "event_name and date are required"}), 400

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO events (user_id, event_name, date, country, city, lat, lon)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, event_name, date::text AS date, country, city, lat, lon
            """, (user["id"], name, date, country, city, lat, lon))
            row = cur.fetchone()
            return jsonify(row), 201
    finally:
        db_pool.putconn(conn)

@app.put("/events/<int:event_id>")
@require_auth
def update_event(user, event_id):
    data = request.get_json(force=True)
    name = (data.get("event_name") or "").strip()
    date = data.get("date")
    country = (data.get("country") or "").strip() or None
    city = (data.get("city") or "").strip() or None
    lat = data.get("lat")
    lon = data.get("lon")

    conn = db_pool.getconn()
    try:
        with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                UPDATE events
                SET event_name = COALESCE(NULLIF(%s,''), event_name),
                    date       = COALESCE(%s, date),
                    country    = COALESCE(%s, country),
                    city       = COALESCE(%s, city),
                    lat        = COALESCE(%s, lat),
                    lon        = COALESCE(%s, lon)
                WHERE id=%s AND user_id=%s
                RETURNING id, event_name, date::text AS date, country, city, lat, lon
            """, (name, date, country, city, lat, lon, event_id, user["id"]))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "event not found"}), 404
            return jsonify(row)
    finally:
        db_pool.putconn(conn)

@app.delete("/events/<int:event_id>")
@require_auth
def delete_event(user, event_id):
    conn = db_pool.getconn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("DELETE FROM events WHERE id=%s AND user_id=%s", (event_id, user["id"]))
            if cur.rowcount == 0:
                return jsonify({"error": "event not found"}), 404
            return jsonify({"ok": True})
    finally:
        db_pool.putconn(conn)

# -----------------------------------------------------------------------------
# Suggestions (stub logic; replace with NASA/Meteomatics integration later)
# -----------------------------------------------------------------------------
@app.post("/suggest")
@require_auth
def suggest(user):
    data = request.get_json(force=True)

    event_name = (data.get("event_name") or "").strip()
    date = data.get("date")
    lat = data.get("lat")
    lon = data.get("lon")

    # If event_id is provided, load event details from DB
    event_id = data.get("event_id")
    if event_id:
        conn = db_pool.getconn()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT event_name, date::text AS date, lat, lon, city, country
                    FROM events
                    WHERE id = %s AND user_id = %s
                """, (event_id, user["id"]))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "event not found"}), 404
                event_name = event_name or (row.get("event_name") or "")
                date = date or row.get("date")
                lat = lat if lat is not None else row.get("lat")
                lon = lon if lon is not None else row.get("lon")
        finally:
            db_pool.putconn(conn)

    # Simple prototype logic — varies by event name keywords
    e = event_name.lower()
    predicted = "mixed conditions" if not date else "might be hot"
    tips, activity = [], "general"

    if any(k in e for k in ["picnic","bbq","barbecue","beach","park"]):
        activity, tips = "picnic", ["bring umbrella", "pack extra ice", "carry sunscreen", "portable fan"]
    elif any(k in e for k in ["hike","trail","trek"]):
        activity, tips = "hike", ["hydration pack", "insect repellent", "light rain jacket", "trail shoes"]
    elif any(k in e for k in ["drone","flying","aerial"]):
        activity, tips = "drone", ["check wind speeds", "spare batteries", "ND filters", "avoid no-fly zones"]
    elif any(k in e for k in ["wedding","ceremony","outdoor event","party"]):
        activity, tips = "ceremony", ["rent canopy options", "cooling fans", "backup indoor space", "ice chests"]
    else:
        tips = ["umbrella just in case", "water bottle", "sunscreen"]

    return jsonify({
        "predicted": predicted,
        "activity": activity,
        "advice": tips,
        "note": "Prototype suggestions. NASA/Meteomatics integration coming next."
    })

# -----------------------------------------------------------------------------
# Reverse geocode proxy (avoids CORS on client)
# -----------------------------------------------------------------------------
@app.get("/reverse_geocode")
def reverse_geocode():
    lat = request.args.get("lat")
    lon = request.args.get("lon")
    if not lat or not lon:
        return jsonify({"error": "lat/lon required"}), 400
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": 10},
            headers={"User-Agent": "NASA_2025/1.0"}
        )
        r.raise_for_status()
        data = r.json()
        addr = data.get("address", {})
        return jsonify({
            "country": addr.get("country"),
            "city": addr.get("city") or addr.get("town") or addr.get("village") or addr.get("state") or ""
        })
    except Exception as e:
        return jsonify({"country": "", "city": ""})

# -----------------------------------------------------------------------------
# Run (gunicorn is used in Docker; this is only for local dev)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
