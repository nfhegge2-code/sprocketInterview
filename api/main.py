"""
Read-only API in front of the honeypot's SQLite database, plus static file
serving for the Leaflet frontend. Kept deliberately dumb: the honeypot does
all the interesting work (capturing + enriching), this just reads and shapes
it for the map.
"""

import os
import sqlite3
from contextlib import closing
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

DB_PATH = os.environ.get("DB_PATH", "/data/honeypot.db")

app = FastAPI(title="Honeypot Attack Map API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


def query_db(sql: str, params: tuple = ()) -> list[dict]:
    # Explicit read-only URI connection: the /data volume is mounted :ro in
    # docker-compose.yml (the API should never be able to write to the
    # honeypot's log). sqlite3.connect() requests read-write access by
    # default even for SELECTs, which fails outright on a read-only mount --
    # mode=ro tells SQLite not to attempt that.
    with closing(sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/attacks")
def get_attacks(
    limit: int = Query(200, ge=1, le=2000),
    since_id: Optional[int] = Query(
        None, description="Only return attacks with id greater than this (for polling)"
    ),
) -> list[dict]:
    """Recent attacks, newest first, with lat/lon for mapping. Rows without a
    resolved location (GeoIP lookup failed or was skipped) are excluded so
    the frontend never has to null-check coordinates."""
    if since_id is not None:
        sql = """
            SELECT id, ts, source_ip, source_port, dest_port, client_banner,
                   country, city, lat, lon, isp
            FROM attacks
            WHERE id > ? AND lat IS NOT NULL AND lon IS NOT NULL
            ORDER BY id DESC
            LIMIT ?
        """
        return query_db(sql, (since_id, limit))

    sql = """
        SELECT id, ts, source_ip, source_port, dest_port, client_banner,
               country, city, lat, lon, isp
        FROM attacks
        WHERE lat IS NOT NULL AND lon IS NOT NULL
        ORDER BY id DESC
        LIMIT ?
    """
    return query_db(sql, (limit,))


@app.get("/api/stats")
def get_stats() -> dict:
    total = query_db("SELECT COUNT(*) AS n FROM attacks")[0]["n"]

    top_countries = query_db(
        """
        SELECT country, COUNT(*) AS n
        FROM attacks
        WHERE country IS NOT NULL
        GROUP BY country
        ORDER BY n DESC
        LIMIT 8
        """
    )

    top_ips = query_db(
        """
        SELECT source_ip, COUNT(*) AS n
        FROM attacks
        GROUP BY source_ip
        ORDER BY n DESC
        LIMIT 8
        """
    )

    last_hour = query_db(
        "SELECT COUNT(*) AS n FROM attacks WHERE datetime(ts) >= datetime('now', '-1 hour')"
    )[0]["n"]

    return {
        "total_attacks": total,
        "attacks_last_hour": last_hour,
        "top_countries": top_countries,
        "top_source_ips": top_ips,
    }


# Static frontend (Leaflet map + JS). Mounted last so /api/* routes above
# take precedence.
app.mount("/", StaticFiles(directory="static", html=True), name="static")