from flask import Flask, request, jsonify, send_from_directory
import os
import psycopg2
from psycopg2 import pool

# -----------------------------------------------------------------------------
# Flask app
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder="static")

# -----------------------------------------------------------------------------
# DB connection pool (psycopg2, per-gunicorn-worker)
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

# Initialize at import time so each Gunicorn worker has its own pool
init_db_pool()

@app.before_request
def _ensure_pool():
    # Safety: recreate pool if it was ever cleared
    if db_pool is None:
        init_db_pool()

# -----------------------------------------------------------------------------
# Static site (served from backend/static/index.html)
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    # Make sure backend/static/index.html exists
    return send_from_directory(app.static_folder, "index.html")

# -----------------------------------------------------------------------------
# Health / diagnostics
# -----------------------------------------------------------------------------
@app.route("/db-check")
def db_check():
    """Confirm DB + PostGIS are reachable."""
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
# Locations API (minimal demo)
# -----------------------------------------------------------------------------
@app.route("/add-location", methods=["POST"])
def add_location():
    """
    JSON body:
    {
      "name": "Singapore Botanic Gardens",
      "lat": 1.3138,
      "lon": 103.8159
    }
    """
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    lat = data.get("lat")
    lon = data.get("lon")

    if name is None or lat is None or lon is None:
        return jsonify({"error": "name, lat, and lon are required"}), 400

    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        # NOTE: PostGIS POINT expects (lon, lat)
        cur.execute(
            """
            INSERT INTO locations (name, geom)
            VALUES (%s, ST_SetSRID(ST_MakePoint(%s, %s), 4326))
            RETURNING id;
            """,
            (name, float(lon), float(lat))
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        db_pool.putconn(conn)
        return jsonify({"id": new_id, "name": name, "lat": lat, "lon": lon}), 201

    except Exception as e:
        # Return a simple message (avoid leaking internals)
        return jsonify({"error": str(e)}), 500

@app.route("/locations", methods=["GET"])
def get_locations():
    """List all stored locations with lat/lon extracted from PostGIS geography."""
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, name, ST_Y(geom::geometry) AS lat, ST_X(geom::geometry) AS lon
            FROM locations
            ORDER BY id;
            """
        )
        rows = cur.fetchall()
        cur.close()
        db_pool.putconn(conn)

        results = [
            {"id": r[0], "name": r[1], "lat": float(r[2]), "lon": float(r[3])}
            for r in rows
        ]
        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------------------------------
# Local dev entrypoint (not used with Gunicorn in Docker, but handy if needed)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if db_pool is None:
        init_db_pool()
    app.run(host="0.0.0.0", port=8000)
