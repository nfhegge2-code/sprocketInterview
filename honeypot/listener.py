"""
Minimal SSH honeypot.

Listens on a TCP port, sends a real-looking SSH version banner, then reads
whatever the connecting client sends (SSH client version string, and in many
cases raw KEXINIT bytes from bots that don't bother finishing a handshake).
Every connection attempt is logged to a shared SQLite database, enriched with
GeoIP data so the API/map layer can plot it without doing its own lookups.

This intentionally does NOT implement the real SSH protocol (no key exchange,
no auth). It just looks enough like an SSH server on the wire to get scanned,
fingerprinted, and often probed with credentials by opportunistic bots -- and
none of that ever gets closer to a real shell than this Python file.
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone

import httpx

LISTEN_HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", "2222"))
DB_PATH = os.environ.get("DB_PATH", "/data/honeypot.db")
FAKE_BANNER = os.environ.get("FAKE_BANNER", "SSH-2.0-OpenSSH_9.2p1 Debian-2")
READ_TIMEOUT_SECONDS = 5
MAX_PAYLOAD_BYTES = 512
GEOIP_TIMEOUT_SECONDS = 3
GEOIP_CACHE_TTL_SECONDS = 6 * 60 * 60  # re-check an IP's geo at most every 6h

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("honeypot")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        #conn.execute("PRAGMA journal_mode=WAL;") - dosen't need shared memory coordination
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                dest_port INTEGER NOT NULL,
                client_banner TEXT,
                raw_payload TEXT,
                country TEXT,
                city TEXT,
                lat REAL,
                lon REAL,
                isp TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS geoip_cache (
                ip TEXT PRIMARY KEY,
                country TEXT,
                city TEXT,
                lat REAL,
                lon REAL,
                isp TEXT,
                fetched_at REAL NOT NULL
            );
            """
        )
        conn.commit()


def get_geoip(ip: str) -> dict:
    """Look up geolocation for an IP, using a local cache to avoid hammering
    the free ip-api.com endpoint (45 req/min limit). Private/loopback IPs
    (e.g. health checks, local testing) short-circuit with empty geo data."""
    if ip.startswith(("10.", "127.", "192.168.", "172.")):
        return {"country": None, "city": None, "lat": None, "lon": None, "isp": None}

    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT country, city, lat, lon, isp, fetched_at FROM geoip_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
        if row and (time.time() - row[5]) < GEOIP_CACHE_TTL_SECONDS:
            return {"country": row[0], "city": row[1], "lat": row[2], "lon": row[3], "isp": row[4]}

    geo = {"country": None, "city": None, "lat": None, "lon": None, "isp": None}
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,isp"},
            timeout=GEOIP_TIMEOUT_SECONDS,
        )
        data = resp.json()
        if data.get("status") == "success":
            geo = {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
            }
    except Exception as exc:  # noqa: BLE001 - geoip failures should never crash the honeypot
        log.warning("GeoIP lookup failed for %s: %s", ip, exc)

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO geoip_cache (ip, country, city, lat, lon, isp, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                country=excluded.country, city=excluded.city, lat=excluded.lat,
                lon=excluded.lon, isp=excluded.isp, fetched_at=excluded.fetched_at
            """,
            (ip, geo["country"], geo["city"], geo["lat"], geo["lon"], geo["isp"], time.time()),
        )
        conn.commit()

    return geo


def log_attack(source_ip: str, source_port: int, client_banner: str, raw_payload: bytes) -> None:
    geo = get_geoip(source_ip)
    payload_preview = raw_payload[:MAX_PAYLOAD_BYTES].decode("utf-8", errors="replace")

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO attacks
                (ts, source_ip, source_port, dest_port, client_banner, raw_payload,
                 country, city, lat, lon, isp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                source_ip,
                source_port,
                LISTEN_PORT,
                client_banner,
                payload_preview,
                geo["country"],
                geo["city"],
                geo["lat"],
                geo["lon"],
                geo["isp"],
            ),
        )
        conn.commit()

    log.info(
        "connection: %s:%s banner=%r geo=%s,%s",
        source_ip, source_port, client_banner, geo["city"], geo["country"],
    )


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    source_ip, source_port = (peer[0], peer[1]) if peer else ("unknown", 0)

    try:
        # Real SSH servers send their version string first; we do the same
        # so scanners/bots believe they've hit a real sshd and proceed to
        # send their own banner and often KEXINIT bytes.
        writer.write(f"{FAKE_BANNER}\r\n".encode())
        await writer.drain()

        raw_payload = b""
        try:
            raw_payload = await asyncio.wait_for(
                reader.read(MAX_PAYLOAD_BYTES), timeout=READ_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            pass

        client_banner = ""
        if raw_payload.startswith(b"SSH-"):
            client_banner = raw_payload.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")

        # Run the (blocking) DB + GeoIP work off the event loop so one slow
        # geoip lookup can't stall other concurrent connections.
        await asyncio.to_thread(log_attack, source_ip, source_port, client_banner, raw_payload)

    except Exception as exc:  # noqa: BLE001 - never let a bad client crash the listener
        log.warning("error handling connection from %s: %s", source_ip, exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def main() -> None:
    init_db()
    server = await asyncio.start_server(handle_connection, LISTEN_HOST, LISTEN_PORT)
    log.info("honeypot listening on %s:%s (fake banner: %s)", LISTEN_HOST, LISTEN_PORT, FAKE_BANNER)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
