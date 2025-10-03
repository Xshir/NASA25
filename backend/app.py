@app.route("/locations", methods=["GET"])
def get_locations():
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

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "name": row[1],
                "lat": float(row[2]),
                "lon": float(row[3])
            })

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
