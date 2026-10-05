"""
ti_logger.py
Threat Intelligence Logging backend for the honeypot.

Responsibilities:
  - Persist every event as a structured JSON line (append-only, tamper-evident-ish via hash chain)
  - Mirror events into SQLite for querying / reporting
  - Maintain a rolling per-IP threat score used to flag repeat offenders
  - Provide simple helper for exporting an IOC (Indicator of Compromise) feed
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import queue
import sqlite3
import threading
import urllib.error
import urllib.request
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("ti_logger")

DB_PATH = Path(__file__).parent / "logs" / "threat_intel.db"
JSONL_PATH = Path(__file__).parent / "logs" / "events.jsonl"

# Weight given to each event type when computing a per-source risk score.
EVENT_WEIGHTS = {
    "connection": 1,
    "auth_attempt": 3,
    "auth_success_fake": 5,   # honeypot always "accepts" after N tries to harvest more
    "command": 4,
    "payload_upload": 8,
    "port_scan_pattern": 6,
    "http_exploit_attempt": 7,
    "http_recon": 1,
    "malformed_request": 2,
}

ALERT_EVENT_TYPES = {"auth_success_fake", "http_exploit_attempt", "payload_upload"}

RISK_LEVELS = (
    (100, "critical"),
    (50, "high"),
    (25, "elevated"),
    (10, "guarded"),
    (0, "low"),
)
RISK_SIGNAL_LABELS = {
    "auth_attempt": "credential attempts",
    "auth_success_fake": "accepted simulated login",
    "command": "commands in simulated shell",
    "payload_upload": "uploaded payload",
    "port_scan_pattern": "unexpected protocol data",
    "http_exploit_attempt": "HTTP exploit pattern",
    "malformed_request": "malformed request",
}


def analyze_risk(event_counts):
    """Return a transparent heuristic risk assessment from event-type counts."""
    signals = []
    score = 0
    for event_type, count in event_counts.items():
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("event counts must be non-negative integers")
        if not count:
            continue
        weight = EVENT_WEIGHTS.get(event_type, 1)
        points = weight * count
        score += points
        signals.append({
            "event_type": event_type,
            "label": RISK_SIGNAL_LABELS.get(event_type, event_type.replace("_", " ")),
            "count": count,
            "points": points,
        })
    signals.sort(key=lambda signal: (-signal["points"], signal["event_type"]))
    level = next(name for threshold, name in RISK_LEVELS if score >= threshold)
    return {
        "score": score,
        "level": level,
        "signals": signals,
        "caveat": "Heuristic triage only; not proof of malicious intent.",
    }


class ThreatIntelLogger:
    def __init__(self, db_path: Path = DB_PATH, jsonl_path: Path = JSONL_PATH,
                 geoip_db_path: str = None, alert_webhook: str = None,
                 alert_event_types=None, auto_block_score: int = 0):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = "0" * 64
        self._geoip_reader = None
        if geoip_db_path:
            try:
                import geoip2.database
            except ImportError as exc:
                raise RuntimeError("Install geoip2 to enable GeoIP enrichment") from exc
            self._geoip_reader = geoip2.database.Reader(geoip_db_path)
        self._alert_webhook = alert_webhook
        self._alert_event_types = set(
            ALERT_EVENT_TYPES if alert_event_types is None else alert_event_types)
        self._auto_block_score = auto_block_score
        self._alert_queue = queue.Queue(maxsize=1000)
        self._alert_thread = None
        self._init_db()
        self._load_hash_chain()
        if alert_webhook:
            self._alert_thread = threading.Thread(target=self._deliver_alerts, daemon=True)
            self._alert_thread.start()

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    service TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    detail TEXT,
                    session_id TEXT,
                    hash TEXT,
                    country_code TEXT,
                    country_name TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL
                )
            """)
            event_columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            for column, column_type in (
                ("country_code", "TEXT"), ("country_name", "TEXT"), ("city", "TEXT"),
                ("latitude", "REAL"), ("longitude", "REAL"),
            ):
                if column not in event_columns:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {column} {column_type}")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS source_scores (
                    src_ip TEXT PRIMARY KEY,
                    score INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    event_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials_seen (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    service TEXT,
                    username TEXT,
                    password TEXT,
                    ts TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_sources (
                    src_ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    blocked_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS behavior_clusters (
                    fingerprint TEXT PRIMARY KEY,
                    behavior TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    source_count INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS behavior_cluster_sources (
                    fingerprint TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (fingerprint, src_ip)
                )
            """)
            self._scrub_legacy_credentials(conn)
            conn.commit()

    def _lookup_geoip(self, src_ip):
        empty = {"country_code": None, "country_name": None, "city": None,
                 "latitude": None, "longitude": None}
        if self._geoip_reader is None:
            return empty
        try:
            address = ipaddress.ip_address(src_ip)
            if not address.is_global:
                return empty
            response = self._geoip_reader.city(address)
        except (ValueError, OSError):
            return empty
        except Exception as exc:
            if exc.__class__.__name__ == "AddressNotFoundError":
                return empty
            log.warning("GeoIP lookup failed for %s: %s", src_ip, exc)
            return empty
        return {
            "country_code": response.country.iso_code,
            "country_name": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }

    def _deliver_alerts(self):
        while True:
            alert = self._alert_queue.get()
            if alert is None:
                self._alert_queue.task_done()
                return
            try:
                hostname = urlsplit(self._alert_webhook).hostname or ""
                if hostname.lower() == "hooks.slack.com":
                    summary = (
                        f"Honeypot {alert['event_type']} on {alert['service']} "
                        f"from {alert['src_ip']}"
                    )
                    payload = json.dumps({"text": summary}, separators=(",", ":")).encode("utf-8")
                else:
                    payload = json.dumps(alert, separators=(",", ":")).encode("utf-8")
                request = urllib.request.Request(
                    self._alert_webhook, data=payload,
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(request, timeout=3):
                    pass
            except (OSError, urllib.error.URLError, ValueError) as exc:
                log.warning("Failed to deliver configured alert webhook (%s)",
                            exc.__class__.__name__)
            finally:
                self._alert_queue.task_done()

    def close(self, timeout=1):
        if self._alert_thread is not None:
            try:
                self._alert_queue.put(None, timeout=timeout)
            except queue.Full:
                pass
            self._alert_thread.join(timeout=timeout)
        if self._geoip_reader is not None:
            self._geoip_reader.close()
            self._geoip_reader = None

    def _scrub_legacy_credentials(self, conn):
        conn.execute("UPDATE credentials_seen SET password='[REDACTED]' WHERE password!='[REDACTED]'")

        rows = conn.execute(
            "SELECT id, detail FROM events WHERE event_type='auth_attempt'"
        ).fetchall()
        for row_id, raw_detail in rows:
            try:
                detail = json.loads(raw_detail or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            password = detail.pop("password", None)
            if password is not None:
                detail["password"] = "[REDACTED]"
                conn.execute("UPDATE events SET detail=?, hash=NULL WHERE id=?",
                             (json.dumps(detail), row_id))

    def _load_hash_chain(self):
        previous_hash = "0" * 64
        if not self.jsonl_path.exists():
            self._last_hash = previous_hash
            return
        with self.jsonl_path.open("r", encoding="utf-8") as log_file:
            lines = log_file.readlines()
        valid_lines = []
        for line_number, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
                record_hash = record.pop("hash")
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                log.warning("Invalid JSONL record at line %d, truncating: %s", line_number, exc)
                break
            payload = previous_hash + json.dumps(record, sort_keys=True, default=self._json_default)
            expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if not isinstance(record_hash, str) or not hmac.compare_digest(record_hash, expected_hash):
                if line_number == len(lines):
                    log.warning("JSONL hash-chain verification failed at last line %d (likely incomplete write), truncating", line_number)
                else:
                    log.error("JSONL hash-chain verification failed at line %d (tampering detected)", line_number)
                    raise ValueError(f"JSONL hash-chain verification failed at line {line_number}")
                break
            previous_hash = record_hash
            valid_lines.append(line)
        if len(valid_lines) < len(lines):
            with self.jsonl_path.open("w", encoding="utf-8") as log_file:
                log_file.writelines(valid_lines)
            log.info("Truncated JSONL log from %d to %d valid lines", len(lines), len(valid_lines))
        self._last_hash = previous_hash
        log.debug("Hash chain loaded, last hash: %s", self._last_hash)

    def _chain_hash(self, record: dict) -> str:
        """Simple hash chain so log tampering after the fact is detectable."""
        payload = self._last_hash + json.dumps(record, sort_keys=True, default=self._json_default)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _json_default(obj):
        if isinstance(obj, (datetime, )):
            return obj.isoformat()
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)

    def log_event(self, src_ip: str, service: str, event_type: str,
                   detail: dict = None, src_port: int = None, session_id: str = None):
        ts = datetime.now(UTC).isoformat()
        safe_detail = dict(detail or {})
        password = safe_detail.pop("password", None) if event_type == "auth_attempt" else None
        if password is not None:
            safe_detail["password"] = "[REDACTED]"
        geo = self._lookup_geoip(src_ip)
        record = {
            "ts": ts,
            "src_ip": src_ip,
            "src_port": src_port,
            "service": service,
            "event_type": event_type,
            "detail": safe_detail,
            "session_id": session_id,
            "geo": geo,
        }
        with self._lock:
            record_hash = self._chain_hash(record)
            record["hash"] = record_hash

            # Append to JSONL (immutable-style event log)
            with self.jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=self._json_default) + "\n")
            self._last_hash = record_hash

            # Mirror into SQLite
            with closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute(
                    "INSERT INTO events (ts, src_ip, src_port, service, event_type, detail, session_id, hash, "
                    "country_code, country_name, city, latitude, longitude) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts, src_ip, src_port, service, event_type,
                     json.dumps(safe_detail), session_id, record_hash,
                     geo["country_code"], geo["country_name"], geo["city"],
                     geo["latitude"], geo["longitude"])
                )

                weight = EVENT_WEIGHTS.get(event_type, 1)
                row = conn.execute(
                    "SELECT score, event_count FROM source_scores WHERE src_ip=?", (src_ip,)
                ).fetchone()
                if row:
                    new_score = row[0] + weight
                    new_count = row[1] + 1
                    conn.execute(
                        "UPDATE source_scores SET score=?, last_seen=?, event_count=? WHERE src_ip=?",
                        (new_score, ts, new_count, src_ip)
                    )
                else:
                    new_score = weight
                    conn.execute(
                        "INSERT INTO source_scores (src_ip, score, first_seen, last_seen, event_count) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (src_ip, weight, ts, ts, 1)
                    )

                if self._auto_block_score > 0 and new_score >= self._auto_block_score:
                    conn.execute(
                        "INSERT OR IGNORE INTO blocked_sources (src_ip, reason, blocked_at) VALUES (?, ?, ?)",
                        (src_ip, f"risk_score>={self._auto_block_score}", ts)
                    )

                if event_type == "auth_attempt" and detail:
                    conn.execute(
                        "INSERT INTO credentials_seen (src_ip, service, username, password, ts) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (src_ip, service, safe_detail.get("username", ""), "[REDACTED]", ts)
                    )
                if event_type == "behavior_cluster":
                    fingerprint = safe_detail.get("fingerprint")
                    behavior = safe_detail.get("behavior")
                    if (isinstance(fingerprint, str) and len(fingerprint) == 20
                            and isinstance(behavior, list)):
                        conn.execute(
                            "INSERT INTO behavior_clusters "
                            "(fingerprint, behavior, event_count, source_count, first_seen, last_seen) "
                            "VALUES (?, ?, 1, 0, ?, ?) "
                            "ON CONFLICT(fingerprint) DO UPDATE SET "
                            "event_count=event_count+1, last_seen=excluded.last_seen",
                            (fingerprint, json.dumps(behavior), ts, ts),
                        )
                        conn.execute(
                            "INSERT INTO behavior_cluster_sources (fingerprint, src_ip, last_seen) "
                            "VALUES (?, ?, ?) ON CONFLICT(fingerprint, src_ip) "
                            "DO UPDATE SET last_seen=excluded.last_seen",
                            (fingerprint, src_ip, ts),
                        )
                        source_count = conn.execute(
                            "SELECT COUNT(*) FROM behavior_cluster_sources WHERE fingerprint=?",
                            (fingerprint,),
                        ).fetchone()[0]
                        conn.execute(
                            "UPDATE behavior_clusters SET source_count=? WHERE fingerprint=?",
                            (source_count, fingerprint),
                        )
                conn.commit()
            if self._alert_webhook and event_type in self._alert_event_types:
                alert = {"ts": ts, "src_ip": src_ip, "service": service,
                         "event_type": event_type, "detail": safe_detail, "geo": geo}
                try:
                    self._alert_queue.put_nowait(alert)
                except queue.Full:
                    log.warning("Alert queue full; dropped %s event for %s",
                                event_type, src_ip)
        return record

    def is_blocked(self, src_ip):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT 1 FROM blocked_sources WHERE src_ip=?", (src_ip,)
            ).fetchone() is not None

    def blocked_sources(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT src_ip, reason, blocked_at FROM blocked_sources ORDER BY blocked_at DESC"
            ).fetchall()

    def top_offenders(self, limit=10):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT src_ip, score, event_count, first_seen, last_seen "
                "FROM source_scores ORDER BY score DESC LIMIT ?", (limit,)
            ).fetchall()

    def source_risk_analysis(self, src_ip):
        """Analyze the full stored event history for one source IP."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT event_type, COUNT(*) FROM events WHERE src_ip=? GROUP BY event_type",
                (src_ip,),
            ).fetchall()
        return analyze_risk(dict(rows))

    def top_credentials(self, limit=15):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT username, COUNT(*) as tries "
                "FROM credentials_seen GROUP BY username "
                "ORDER BY tries DESC LIMIT ?", (limit,)
            ).fetchall()

    def event_counts_by_service(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT service, COUNT(*) FROM events GROUP BY service ORDER BY 2 DESC"
            ).fetchall()

    def top_behavior_clusters(self, limit=10):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT fingerprint, behavior, event_count, source_count, first_seen, last_seen "
                "FROM behavior_clusters ORDER BY source_count DESC, event_count DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def export_ioc_feed(self, min_score=10, include_non_global=False):
        """Return scored IPs, excluding non-global addresses unless explicitly requested."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT src_ip, score, event_count, first_seen, last_seen "
                "FROM source_scores WHERE score >= ? ORDER BY score DESC", (min_score,)
            ).fetchall()
        results = []
        for row in rows:
            try:
                is_global = ipaddress.ip_address(row[0]).is_global
            except ValueError:
                log.warning("Skipping invalid source IP from IOC feed: %r", row[0])
                continue
            if include_non_global or is_global:
                analysis = self.source_risk_analysis(row[0])
                results.append(
                    {"ip": row[0], "risk_score": row[1], "event_count": row[2],
                     "risk_level": analysis["level"], "risk_signals": analysis["signals"],
                     "first_seen": row[3], "last_seen": row[4]}
                )
        return results
