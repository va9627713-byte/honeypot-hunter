#!/usr/bin/env python3
"""Read-only local dashboard for honeypot telemetry."""

import argparse
import asyncio
import json
import logging
import sqlite3
import time
from collections import OrderedDict, deque
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ti_logger import analyze_risk

DB_PATH = Path(__file__).parent / "logs" / "threat_intel.db"
FAVICON = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           b'<rect width="32" height="32" rx="6" fill="#101614"/>'
           b'<path d="M16 4 27 10v12l-11 6L5 22V10z" fill="none" '
           b'stroke="#b7ed77" stroke-width="2.5"/></svg>')

# HTML page built programmatically to avoid quote escaping issues
HTML_HEAD = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" type="image/svg+xml" href="/favicon.svg"><title>Honeypot Operations</title>
<style>
:root{font:14px ui-monospace,Consolas,monospace;color:#e9f0eb;background:#101614;--line:#35443c;--muted:#92a49a;--lime:#b7ed77}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#1b2620,#101614 60%);min-height:100vh}header{padding:24px 4vw;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}h1{font-size:19px;margin:0}small,.muted{color:var(--muted)}main{padding:26px 4vw;max-width:1500px;margin:auto}.stats{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);margin-bottom:28px}.stat{padding:18px;border-right:1px solid var(--line)}.stat:last-child{border:0}.stat b{display:block;font-size:28px;color:var(--lime);margin-top:8px}.cols{display:grid;grid-template-columns:minmax(250px,.7fr) minmax(0,2fr);gap:28px}h2{font-size:13px;color:var(--muted);text-transform:uppercase;margin:0 0 12px}.row{padding:12px 8px;border-top:1px solid var(--line);overflow-wrap:anywhere}.row strong{color:var(--lime)}.row small{display:block;margin-top:5px}.table{overflow:auto;border-top:1px solid var(--line)}table{border-collapse:collapse;width:100%;min-width:690px;font-size:12px}td,th{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-weight:400}button{border:1px solid var(--line);background:#1b2721;color:inherit;padding:8px 12px;font:inherit;cursor:pointer}@media(max-width:750px){.stats{grid-template-columns:repeat(2,1fr)}.stat:nth-child(2){border-right:0}.stat:nth-child(-n+2){border-bottom:1px solid var(--line)}.cols{grid-template-columns:1fr}header{align-items:flex-start;gap:10px;flex-direction:column}}
.filters{display:flex;gap:16px;margin-bottom:18px;flex-wrap:wrap}.filters label{display:flex;gap:8px;align-items:center;color:var(--muted)}select{border:1px solid var(--line);background:#1b2721;color:inherit;padding:8px;font:inherit}
</style></head>"""

HTML_BODY = """<body><header><div><h1>HONEYPOT / OPERATIONS</h1><small>Live telemetry \u00b7 read-only</small></div><div><span id="state">Connecting\u2026</span> <button id="refresh">Refresh</button></div></header>
<main><div class="filters"><label>Time range <select id="time-range"><option value="all">All time</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option></select></label><label>Service <select id="service-filter"><option value="all">All services</option></select></label></div>
<div class="stats"><div class="stat">Events<b id="events">\u2014</b></div><div class="stat">Sources<b id="sources">\u2014</b></div><div class="stat">Local blocks (all time)<b id="blocks">\u2014</b></div><div class="stat">Services<b id="services-count">\u2014</b></div></div><div class="cols"><section><h2>Risk analysis (selected filters)</h2><div id="offenders"></div><h2 style="margin-top:28px">Events by service</h2><div id="services"></div><h2 style="margin-top:28px">Behavior clusters (all time)</h2><div id="clusters"></div></section><section><h2>Recent activity</h2><div class="table"><table><thead><tr><th>UTC</th><th>Source</th><th>Location</th><th>Service / event</th><th>Details</th></tr></thead><tbody id="recent"></tbody></table></div></section></div></main>"""

DASHBOARD_JS = """'use strict';
const byId = (id) => document.getElementById(id);
const text = (value) => value == null ? '' : String(value);
const element = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = text(value);
  return node;
};
const appendCell = (row, value) => row.appendChild(element('td', '', value));

let refreshInFlight = false;

async function refresh() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  const state = byId('state');
  const button = byId('refresh');
  button.disabled = true;
  button.textContent = 'Refreshing\u2026';
  state.textContent = 'Refreshing\u2026';
  try {
    const params = new URLSearchParams({
      window: byId('time-range').value,
      service: byId('service-filter').value,
    });
    const response = await fetch(`/api/summary?${params}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Dashboard API returned HTTP ${response.status}`);
    const data = await response.json();
    const serviceFilter = byId('service-filter');
    const selectedService = serviceFilter.value;
    const availableServices = ['all', ...data.service_options];
    if (!availableServices.includes(selectedService)) serviceFilter.value = 'all';
    if (serviceFilter.options.length !== availableServices.length) {
      serviceFilter.replaceChildren(element('option', '', 'All services'));
      serviceFilter.options[0].value = 'all';
      for (const service of data.service_options) {
        const option = element('option', '', service);
        option.value = service;
        serviceFilter.append(option);
      }
      serviceFilter.value = availableServices.includes(selectedService) ? selectedService : 'all';
    }
    for (const [id, key] of [
      ['events', 'total_events'],
      ['sources', 'total_sources'],
      ['blocks', 'blocked_sources'],
    ]) byId(id).textContent = text(data[key]);
    byId('services-count').textContent = text(data.services.length);

    const offenders = byId('offenders');
    offenders.replaceChildren();
    if (data.offenders.length) {
      for (const item of data.offenders) {
        const row = element('div', 'row');
        row.append(element('strong', '', `${text(item.src_ip)} \u00b7 ${text(item.risk_level.toUpperCase())} \u00b7 score ${text(item.score)}`));
        row.append(element('small', '', `${text(item.event_count)} events \u00b7 ${item.risk_signals.map((signal) => `${text(signal.count)} ${text(signal.label)}`).join(', ')}`));
        row.append(element('small', 'muted', item.risk_caveat));
        offenders.append(row);
      }
    } else {
      offenders.append(element('div', 'row muted', 'No observations'));
    }

    const services = byId('services');
    services.replaceChildren();
    for (const item of data.services) {
      const row = element('div', 'row');
      row.append(element('strong', '', item.service));
      row.append(element('small', '', `${text(item.count)} events`));
      services.append(row);
    }

    const clusters = byId('clusters');
    clusters.replaceChildren();
    if (data.clusters.length) {
      for (const item of data.clusters) {
        const row = element('div', 'row');
        row.append(element('strong', '', `${text(item.fingerprint)} \u00b7 ${text(item.source_count)} sources`));
        row.append(element('small', '', `${text(item.event_count)} sessions \u00b7 ${(item.behavior || []).map(text).join(', ')}`));
        clusters.append(row);
      }
    } else {
      clusters.append(element('div', 'row muted', 'No clustered sessions'));
    }

    const recent = byId('recent');
    recent.replaceChildren();
    for (const item of data.recent) {
      const row = document.createElement('tr');
      appendCell(row, item.ts);
      appendCell(row, `${text(item.src_ip)}:${text(item.src_port)}`);
      appendCell(row, [item.city, item.country_code].filter(Boolean).join(', ') || '\u2014');
      const event = document.createElement('td');
      event.append(document.createTextNode(text(item.service)));
      event.append(document.createElement('br'));
      event.append(document.createTextNode(text(item.event_type)));
      row.append(event);
      appendCell(row, JSON.stringify(item.detail));
      recent.append(row);
    }
    state.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    state.textContent = 'Dashboard data unavailable';
    console.error('Dashboard refresh failed:', error);
  } finally {
    refreshInFlight = false;
    button.disabled = false;
    button.textContent = 'Refresh';
  }
}

byId('refresh').addEventListener('click', refresh);
byId('time-range').addEventListener('change', refresh);
byId('service-filter').addEventListener('change', refresh);
refresh();
setInterval(refresh, 5000);
""".encode("utf-8")

PAGE = (HTML_HEAD + HTML_BODY + '<script src="/dashboard.js" defer></script></body></html>').encode("utf-8")

log = logging.getLogger("dashboard")

# Simple in-memory rate limiter for dashboard
_rate_limiter = OrderedDict()
_RATE_LIMIT = 120  # API requests per window
_RATE_WINDOW = 60  # seconds
_RATE_LIMIT_CLIENTS = 1000


def load_summary(db_path, window="all", service="all"):
    windows = {"all": None, "1h": timedelta(hours=1),
               "24h": timedelta(hours=24), "7d": timedelta(days=7)}
    if window not in windows:
        raise ValueError("window must be one of: all, 1h, 24h, 7d")

    conditions = []
    parameters = []
    if windows[window] is not None:
        cutoff = datetime.now(UTC) - windows[window]
        conditions.append("ts >= ?")
        parameters.append(cutoff.isoformat())
    if service != "all":
        conditions.append("service = ?")
        parameters.append(service)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    path = Path(db_path)
    if not path.exists():
        return {"total_events": 0, "total_sources": 0, "blocked_sources": 0,
                "offenders": [], "services": [], "service_options": [],
                "clusters": [], "recent": []}
    # Use read-only URI mode for :ro volumes (avoids WAL -shm/-wal issues)
    uri = f"file:{db_path}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=2)) as conn:
        conn.row_factory = sqlite3.Row
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        event_columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        city_column = "city" if "city" in event_columns else "NULL AS city"
        country_column = "country_code" if "country_code" in event_columns else "NULL AS country_code"
        result = {
            "total_events": conn.execute(
                f"SELECT COUNT(*) FROM events {where}", parameters).fetchone()[0],
            "total_sources": conn.execute(
                f"SELECT COUNT(DISTINCT src_ip) FROM events {where}", parameters).fetchone()[0],
            "blocked_sources": (conn.execute("SELECT COUNT(*) FROM blocked_sources").fetchone()[0]
                                if "blocked_sources" in tables else 0),
            "offenders": [],
            "services": [dict(row) for row in conn.execute(
                f"SELECT service, COUNT(*) AS count FROM events {where} "
                "GROUP BY service ORDER BY count DESC", parameters)],
            "service_options": [row[0] for row in conn.execute(
                "SELECT DISTINCT service FROM events ORDER BY service")],
            "clusters": ([dict(row) for row in conn.execute(
                "SELECT fingerprint, behavior, event_count, source_count, first_seen, last_seen "
                "FROM behavior_clusters ORDER BY source_count DESC, event_count DESC LIMIT 10")]
                if "behavior_clusters" in tables else []),
            "recent": [dict(row) for row in conn.execute(
                f"SELECT ts, src_ip, src_port, service, event_type, detail, {city_column}, {country_column} "
                f"FROM events {where} ORDER BY id DESC LIMIT 100", parameters)],
        }
        source_rows = conn.execute(
            f"SELECT src_ip, COUNT(*) AS event_count, MAX(ts) AS last_seen "
            f"FROM events {where} GROUP BY src_ip",
            parameters,
        ).fetchall()
        source_event_rows = conn.execute(
            f"SELECT src_ip, event_type, COUNT(*) AS event_count FROM events {where} "
            "GROUP BY src_ip, event_type",
            parameters,
        ).fetchall()
        event_counts_by_source = {}
        for row in source_event_rows:
            event_counts_by_source.setdefault(row["src_ip"], {})[row["event_type"]] = row["event_count"]
        for row in source_rows:
            assessment = analyze_risk(event_counts_by_source[row["src_ip"]])
            result["offenders"].append({
                "src_ip": row["src_ip"],
                "score": assessment["score"],
                "risk_level": assessment["level"],
                "risk_signals": assessment["signals"],
                "risk_caveat": assessment["caveat"],
                "event_count": row["event_count"],
                "last_seen": row["last_seen"],
            })
        result["offenders"].sort(key=lambda item: (-item["score"], item["src_ip"]))
        result["offenders"] = result["offenders"][:10]
    for event in result["recent"]:
        try:
            event["detail"] = json.loads(event["detail"] or "{}")
        except json.JSONDecodeError:
            event["detail"] = {}
    for cluster in result["clusters"]:
        try:
            cluster["behavior"] = json.loads(cluster["behavior"])
        except json.JSONDecodeError:
            cluster["behavior"] = []
    return result


async def _load_summary_async(db_path, window="all", service="all"):
    """Run load_summary in a thread pool to avoid blocking the event loop."""
    return await asyncio.to_thread(load_summary, db_path, window, service)


async def handle_client(reader, writer, db_path):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    try:
        request = await asyncio.wait_for(reader.readline(), timeout=3)
        parts = request.decode("ascii", errors="replace").strip().split()
        if len(parts) < 2:
            return
        method, target = parts[:2]
        parsed_target = urlsplit(target)
        path = parsed_target.path
        query = parse_qs(parsed_target.query)
        if method == "GET" and path == "/api/summary":
            now = time.time()
            recent = _rate_limiter.get(client_ip)
            if recent is None:
                if len(_rate_limiter) >= _RATE_LIMIT_CLIENTS:
                    _rate_limiter.popitem(last=False)
                recent = deque()
                _rate_limiter[client_ip] = recent
            else:
                _rate_limiter.move_to_end(client_ip)
            while recent and now - recent[0] > _RATE_WINDOW:
                recent.popleft()
            if len(recent) >= _RATE_LIMIT:
                body = b"Rate limit exceeded"
                writer.write((f"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n"
                              f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\n"
                              f"Retry-After: {_RATE_WINDOW}\r\n"
                              "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n").encode() + body)
                await writer.drain()
                return
            recent.append(now)
        for _ in range(50):
            header = await asyncio.wait_for(reader.readline(), timeout=3)
            if header in (b"\r\n", b"\n", b""):
                break
        else:
            return
        if method != "GET":
            status, mime, body = "405 Method Not Allowed", "text/plain", b"GET only"
        elif path == "/health":
            status, mime, body = "200 OK", "application/json; charset=utf-8", b'{"status": "healthy"}'
        elif path == "/api/summary":
            if set(query) - {"window", "service"} or any(
                len(values) != 1 for values in query.values()
            ):
                status, mime, body = (
                    "400 Bad Request", "application/json; charset=utf-8",
                    b'{"error":"Invalid summary filters"}',
                )
            else:
                window = query.get("window", ["all"])[0]
                service = query.get("service", ["all"])[0]
                try:
                    data = await _load_summary_async(db_path, window, service)
                except ValueError as exc:
                    status, mime = "400 Bad Request", "application/json; charset=utf-8"
                    body = json.dumps({"error": str(exc)}).encode()
                else:
                    status, mime = "200 OK", "application/json; charset=utf-8"
                    body = json.dumps(data, default=str).encode()
        elif path == "/favicon.ico":
            status, mime, body = "200 OK", "image/svg+xml", FAVICON
        elif path == "/favicon.svg":
            status, mime, body = "200 OK", "image/svg+xml", FAVICON
        elif path == "/dashboard.js":
            status, mime, body = "200 OK", "text/javascript; charset=utf-8", DASHBOARD_JS
        elif path == "/":
            status, mime, body = "200 OK", "text/html; charset=utf-8", PAGE
        else:
            status, mime, body = "404 Not Found", "text/plain", b"Not found"

        csp = ("default-src 'self'; "
               "script-src 'self'; "
               "style-src 'self' 'unsafe-inline'; "
               "img-src 'self' data:; "
               "connect-src 'self'; "
               "frame-ancestors 'none'; "
               "base-uri 'none'; "
               "form-action 'none'")
        writer.write((f"HTTP/1.1 {status}\r\nContent-Type: {mime}\r\n"
                      f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\n"
                      "X-Content-Type-Options: nosniff\r\n"
                      f"Content-Security-Policy: {csp}\r\n"
                      "Referrer-Policy: no-referrer\r\n"
                      "Connection: close\r\n\r\n").encode() + body)
        await writer.drain()
    except (TimeoutError, ValueError, ConnectionError, OSError, sqlite3.Error) as exc:
        log.debug("Dashboard request error from %s: %s", client_ip, exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def serve(host, port, db_path):
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, db_path), host, port, limit=16384)
    log.info("Dashboard: http://%s:%d/ (read-only) | Health: http://%s:%d/health", host, port, host, port)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Read-only honeypot dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        asyncio.run(serve(args.host, args.port, args.db))
    except KeyboardInterrupt:
        log.info("Dashboard shutting down.")


if __name__ == "__main__":
    main()
