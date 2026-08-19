# SSH Honeypot Attack Map

A tiny SSH honeypot that sits on a public VPS, logs every connection attempt
it receives, enriches each one with GeoIP data, and plots them live on a map.

Built for the Sprocket Security Jr DevOps take-home assessment ("a server
that does something").

![architecture](diagram/architecture.svg)

## What it actually does

1. **`honeypot/listener.py`** binds to a TCP port and pretends to be
   `OpenSSH_9.2p1`. It sends a real-looking version banner, reads whatever
   the connecting client sends back (most bots reply with their own SSH
   version string, some send raw `KEXINIT` bytes), and logs the source IP,
   port, timestamp, and payload to SQLite. It never implements the real SSH
   protocol -- no key exchange, no auth, nothing a connecting client can
   actually do besides get logged.
2. Each new source IP gets a **GeoIP lookup** (via the free `ip-api.com`
   endpoint, cached in SQLite so the same IP isn't looked up twice).
3. **`api/main.py`** is a read-only FastAPI service that serves that data as
   JSON (`/api/attacks`, `/api/stats`) and hosts the static frontend.
4. **`api/static/`** is a Leaflet map that polls the API every few seconds
   and drops a pulsing marker for each new attack, plus a live feed and
   basic stats (top countries, top source IPs, attacks in the last hour).

Everything is wired together with **Docker Compose** -- two containers
(`honeypot`, `api`) sharing one SQLite volume.

## Running it locally

```bash
docker compose up --build
```

- Honeypot listens on host port `2222` by default when run this way (see
  `docker-compose.yml` -- change to `22:2222` for the real deployment).
- API + map: http://localhost:8000

Test it by connecting to the honeypot port with `nc` or `ssh`:

```bash
nc localhost 2222
# you'll see a fake SSH banner come back; anything you type gets logged
```

Then check http://localhost:8000 -- you should see a pin appear (assuming
your test connection resolves to a public IP; loopback/private IPs are
skipped for GeoIP on purpose, see below).

## Deploying to a real VPS

1. **Spin up a cheap VPS** (DigitalOcean/Hetzner/Linode droplet, anything
   with a public IP and Docker support).
2. **Move real SSH off port 22 first.** Edit `/etc/ssh/sshd_config`, set
   `Port 2200` (or similar), restart `sshd`, confirm you can still log in
   on the new port **before** doing anything else. This step matters --
   skipping it locks you out once the honeypot claims port 22.
3. **Open the right ports in your firewall/security group**: `22` (now the
   honeypot), `8000` (the map). Close everything else.
4. Clone the repo onto the VPS and edit `docker-compose.yml`:
   ```yaml
   ports:
     - "22:2222"   # was 2222:2222 for local testing
   ```
5. `docker compose up -d --build`
6. Visit `http://<vps-ip>:8000` to see the live map. Internet background
   scanning noise typically starts hitting an exposed port within minutes.

(Optional, if you want it on a real domain/HTTPS: put Caddy or nginx in
front of the API container with a Let's Encrypt cert. Left out here to keep
the assessment scope reasonable -- see limitations below.)

## Design decisions worth knowing for the interview

- **The honeypot never touches port 22 directly as root.** It listens on an
  unprivileged port (2222) inside its container as a non-root user; Docker's
  port mapping handles the privileged-port binding on the host side. This
  avoids running any of the actual attacker-facing code with elevated
  privileges.
- **The API container mounts the shared volume read-only.** Even if the API
  layer were compromised, it can't tamper with the honeypot's log.
- **GeoIP lookups are cached and skip private IP ranges** (10.x, 172.16.x,
  192.168.x, 127.x) so local/health-check traffic doesn't burn API calls or
  clutter the map with garbage data.
- **SQLite with the default rollback journal** was chosen over Postgres/Redis
  to keep the stack to two containers for a 3-4 hour scope. WAL mode was
  tried first for better write concurrency, but WAL requires a shared-memory
  index file that SQLite tries to create even for read-only connections --
  which fails against the API container's genuinely read-only volume mount.
  The default journal mode has no such requirement and the honeypot's write
  volume doesn't need WAL's concurrency benefits anyway.

## Debugging notes from the actual deployment

Two real bugs came up going from "builds locally" to "running on a public
VPS" -- worth knowing going into the interview, since they're better
examples of actual troubleshooting than a clean happy-path build would be.

**1. Honeypot container crash-looping on startup.**
The honeypot runs as a non-root user inside its container (a deliberate
choice, see above). Docker creates named volumes owned by `root` by default
when nothing in the image pre-creates that path, so the non-root process
couldn't write its SQLite file into `/data` and crashed immediately on
every restart. Fixed by creating `/data` and `chown`-ing it to the
`honeypot` user *inside the Dockerfile*, before the `USER honeypot`
directive -- when Docker later mounts an empty named volume over that path,
it inherits the ownership that already existed there at build time.

**2. API returning 500s even after the first fix.**
The API container's volume is intentionally mounted `:ro` (read-only) --
the API should never be able to write to the honeypot's log. Two layers of
this bit us:

- `sqlite3.connect()` requests read-write access by default even for a
  plain `SELECT`, which fails outright against a read-only mount. Fixed by
  connecting via a `file:...?mode=ro` URI instead, which tells SQLite not
  to attempt that.
- That alone wasn't enough, because the honeypot was writing in **WAL
  journal mode**, which needs a shared-memory index file (`-shm`) for
  coordination that SQLite tries to create even for read-only connections.
  A truly read-only mount blocks that too. Since a honeypot's write volume
  is nowhere near what WAL's concurrency benefits are for, the real fix was
  dropping WAL entirely and using SQLite's default rollback journal, which
  has no such requirement.

**3. "Attacks in the last hour" showing nearly the same number as total
attacks, days into running it.**
Timestamps are stored as Python's `datetime.now(timezone.utc).isoformat()`,
e.g. `2026-08-19T21:55:00.123456+00:00`. The stats query compared that
directly against SQLite's own `datetime('now', '-1 hour')`, which outputs a
*different* string format (`2026-08-19 21:00:00` -- space separator, no
`T`, no offset). Comparing them as raw text rather than as actual datetime
values meant that, since `T` sorts after a space character, almost every
timestamp from the *current calendar day* -- regardless of actual hour --
looked "greater than" the cutoff and got miscounted as within the last
hour. Only entries from a previous calendar day were excluded correctly.
Fixed by wrapping both sides in SQLite's `datetime()` function so it
parses and normalizes both values before comparing them, instead of doing
a plain string comparison between two mismatched formats.

All three are the kind of interaction that's easy to miss when building and
testing everything on one machine as one user, and only surfaces once
you've got genuinely separate containers/users/mount permissions in play,
or once real data has accumulated over multiple days -- which is arguably
a decent illustration of why the interview cares about actual deployment
experience over just working code.

## Known limitations / what I'd address next

This was intentionally kept small for the assessment window. Things I'd
change for a "real" version:

- **No network segmentation.** The honeypot and API containers share a
  Docker bridge network with no explicit isolation between them. In
  production I'd put the honeypot on its own network with no route to
  anything except the shared volume, so a honeypot compromise (e.g. via an
  asyncio/parsing bug) can't reach the API container at all.
- **No log shipping off-box.** Everything lives in one SQLite file on one
  VPS. If that box goes down, the log goes with it. A real deployment would
  ship logs to something durable (S3, a log aggregator) on write.
- **Single point of failure.** One VPS, one honeypot process, one database.
  Fine for a demo; not fine for actually monitoring anything that matters.
- **GeoIP lookups are synchronous per-connection** against a free, rate
  -limited third-party API. Under an actual attack burst (dozens of
  connections/sec) this would either throttle hard or start dropping geo
  data. A local MaxMind GeoLite2 database would remove that dependency
  entirely and be the first thing I'd swap in.
- **Only SSH is emulated.** Real attackers scan far more than port 22.
  Extending to Telnet/HTTP/RDP honeypots would just mean more listeners
  writing to the same schema -- the architecture already supports it.
- **No alerting.** The map is a passive dashboard; nothing pages anyone on
  a spike or an interesting payload. A basic threshold-based webhook to
  Slack/Discord would be a natural next step.
- **No auth on the map itself.** Anyone with the URL can see the dashboard.
  Fine for a portfolio piece, not fine if this were monitoring something
  sensitive.

## Repo layout

```
honeypot-map/
├── docker-compose.yml
├── honeypot/            # SSH honeypot listener (asyncio, SQLite, GeoIP)
│   ├── listener.py
│   ├── requirements.txt
│   └── Dockerfile
├── api/                 # FastAPI backend + static Leaflet frontend
│   ├── main.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── static/
│       ├── index.html
│       ├── app.js
│       └── style.css
└── diagram/
    └── architecture.svg
```
