const POLL_INTERVAL_MS = 4000;
const FEED_MAX_ITEMS = 30;

const map = L.map("map", { worldCopyJump: true }).setView([20, 0], 2.3);
L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
  attribution: "&copy; OpenStreetMap &copy; CARTO",
  maxZoom: 18,
}).addTo(map);

const statusEl = document.getElementById("status");
const statTotal = document.getElementById("stat-total");
const statHour = document.getElementById("stat-hour");
const feedEl = document.getElementById("feed");
const topCountriesEl = document.getElementById("top-countries");
const topIpsEl = document.getElementById("top-ips");

let lastSeenId = 0;

function timeAgo(isoTs) {
  const diffMs = Date.now() - new Date(isoTs).getTime();
  const s = Math.max(1, Math.round(diffMs / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

function plotAttack(attack) {
  const marker = L.circleMarker([attack.lat, attack.lon], {
    radius: 5,
    color: "#ff4d4d",
    fillColor: "#ff4d4d",
    fillOpacity: 0.9,
    weight: 1,
  }).addTo(map);

  marker.bindPopup(
    `<strong>${attack.source_ip}</strong><br/>` +
    `${attack.city ?? "Unknown city"}, ${attack.country ?? "Unknown country"}<br/>` +
    `banner: ${attack.client_banner || "(none sent)"}<br/>` +
    `${new Date(attack.ts).toLocaleString()}`
  );

  // Expanding "radar pulse" ring, purely visual, removed after animation.
  const pulseIcon = L.divIcon({ className: "attack-pulse", iconSize: [14, 14] });
  const pulseMarker = L.marker([attack.lat, attack.lon], {
    icon: pulseIcon,
    interactive: false,
  }).addTo(map);
  setTimeout(() => map.removeLayer(pulseMarker), 1400);
}

function prependFeedItem(attack) {
  const li = document.createElement("li");
  li.innerHTML =
    `<span class="ip">${attack.source_ip}</span> &rarr; port ${attack.dest_port}` +
    `<span class="meta">${attack.city ?? "Unknown"}, ${attack.country ?? "Unknown"} &middot; ${timeAgo(attack.ts)}</span>`;
  feedEl.prepend(li);
  while (feedEl.children.length > FEED_MAX_ITEMS) {
    feedEl.removeChild(feedEl.lastChild);
  }
}

async function pollAttacks() {
  try {
    const url = lastSeenId
      ? `/api/attacks?since_id=${lastSeenId}&limit=200`
      : `/api/attacks?limit=100`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const attacks = await res.json();

    statusEl.textContent = "live";
    statusEl.classList.remove("offline");

    // API returns newest-first; plot oldest-of-batch first so the feed reads naturally.
    for (const attack of [...attacks].reverse()) {
      plotAttack(attack);
      prependFeedItem(attack);
      if (attack.id > lastSeenId) lastSeenId = attack.id;
    }
  } catch (err) {
    statusEl.textContent = "offline";
    statusEl.classList.add("offline");
    console.error("poll failed", err);
  }
}

async function pollStats() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const stats = await res.json();

    statTotal.textContent = stats.total_attacks;
    statHour.textContent = stats.attacks_last_hour;

    topCountriesEl.innerHTML = stats.top_countries
      .map((c) => `<li><span>${c.country}</span><span>${c.n}</span></li>`)
      .join("");

    topIpsEl.innerHTML = stats.top_source_ips
      .map((i) => `<li><span>${i.source_ip}</span><span>${i.n}</span></li>`)
      .join("");
  } catch (err) {
    console.error("stats poll failed", err);
  }
}

pollAttacks();
pollStats();
setInterval(pollAttacks, POLL_INTERVAL_MS);
setInterval(pollStats, POLL_INTERVAL_MS * 2);
