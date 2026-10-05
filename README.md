# Custom Honeypot with Threat Intelligence Logging

A defensive honeypot platform that emulates SSH, Telnet, FTP, HTTP, MySQL,
Redis, SMTP, Docker, Kubernetes, Modbus, and MQTT services, captures activity against
them, and turns that activity into structured threat intelligence: per-IP
risk scores, a credential-attempt table, and an exportable IOC (Indicator
of Compromise) feed.

**Project site:** [va9627713-byte.github.io/honeypot-hunter](https://va9627713-byte.github.io/honeypot-hunter/)  
The Pages site is static project information only; it does not run this Python
application or display live honeypot events.

The platform includes optional offline GeoIP enrichment, webhook alerts,
per-source rate limiting, a persistent local denylist, MITRE ATT&CK event tags,
behavior clustering, a read-only live dashboard, and a loopback-only attack
simulator. Regression tests cover privacy, integrity, configuration, dashboard,
and protocol behavior. Run them with
`python -m unittest -v test_hardening test_dashboard`.

This project is a prototype, not a certified or production-ready security
product. Run it only on an isolated host you control, and review the deployment
and data-retention risks before exposing any listener to a network.

## How it works

```
honeypot.py    → asyncio server exposing eleven fake services
ti_logger.py   → hash-chained JSONL + SQLite, optional GeoIP and alerts
system_state.py → deployment-specific synthetic system state
artifact_analysis.py → bounded static triage and optional isolated-sandbox handoff
local_llm.py   → optional local command-output generation and event classification
dashboard.py  → read-only local dashboard and summary API
report.py      → terminal summary and IOC export
simulate_attacks.py → harmless local-only test traffic
```

The dashboard supports filtering event summaries by time range and service.
Its HTML is served separately from same-origin JavaScript, event values are
rendered with text nodes, and SQLite work runs outside the asyncio event loop.
The dashboard rate limit applies only to summary API requests, leaving page
assets and health checks available during repeated refreshes.
The dashboard polls every five seconds; the event feed is current telemetry,
not a traffic generator. Run `python simulate_attacks.py` separately for safe
loopback-only demo traffic. Optional event classification can be enabled with
`python dashboard.py --enable-local-ai-classification`; it sends only the
selected event evidence to the configured local Ollama endpoint. Classification
is off by default, is advisory, and is not a substitute for analyst review.
The dashboard can download a JSON incident snapshot for the selected filters.

**Only the SSH transport is real.** SSH uses AsyncSSH for key exchange and
password authentication by default, but accepts credentials and presents only
a simulated shell. Commands are logged and answered from synthetic system
state; they are never executed. SSH forwarding and subsystems are not provided.
Its host key is generated once per process unless `host_key_path` names an
existing private key. Raw passwords are redacted by the logger; the default
`credential_retention: hashed` records a short SHA-256 fingerprint, which can
still be guessed offline if a password is weak. Set it to `off` to omit that
fingerprint. Set `real_ssh: false` only for the legacy plaintext prompt used
by simple scanners; real SSH clients will not speak that prompt.

Telnet, FTP, HTTP, MySQL, Redis, SMTP, Docker, Kubernetes, Modbus, and MQTT
remain protocol-specific emulations. FTP never stores files. HTTP request
samples are inspected in memory only; no sample is written to disk or
executed. Other observed activity is recorded and answered with a plausible
fake response; this is a deception/monitoring tool, not a real application
server.

### What gets logged, per event
- Timestamp (UTC), source IP + port, service, event type
- `connection`, `auth_attempt` (username/password), `command`,
  `payload_upload` (filename), `http_exploit_attempt` (path + matched
  signature + User-Agent), `port_scan_pattern` (raw bytes of unexpected
  protocol handshakes)
- Routine HTTP health, metrics, readiness, and generic `/api/` probes are
  stored as low-weight `http_recon` events and are excluded from the default
  alert event types.
- A SHA-256 hash chained to the previous event, so if someone edits an
  old log line after the fact, the chain breaks and it's detectable. The
  chain is verified and resumed at startup; startup fails closed if tampering
  or malformed records are detected.
- Passwords are not retained by new versions. Auth events retain the username
  and a redaction marker; reports aggregate username attempt counts only.
  Existing SQLite credential rows are scrubbed on startup. Historical JSONL records
  created by earlier versions may still contain plaintext and should be
  treated as sensitive. Earlier versions also reset the hash chain at each
  launch, so archive old JSONL logs securely and move them out of the active
  log path before upgrading; the current version refuses unverified logs.

GeoIP is offline-only and requires a licensed MaxMind GeoLite2 City database
configured via `geoip_db_path`. Install its optional reader with
`pip install -r requirements-geoip.txt`. Private/reserved IPs have no location.
Webhook alerts are disabled by default and use a bounded background queue. Configure
`alert_webhook` only after assessing the information sent to its receiver.
Auto-blocking only populates the honeypot's persistent local denylist; it never
edits system or cloud firewall rules and is disabled by default. Per-source
rate limiting is enabled.

### Adaptive emulation, artifacts, and containment

The emulated shell uses a per-deployment fake identity, network, process list,
filesystem, and changing uptime/load/resource values. Common discovery commands
read that synthetic state. Unknown commands can optionally be answered by an
Ollama-compatible model running on loopback; set `llm_enabled: true` and
`llm_model` in the config after installing and loading that model locally.
Only loopback and the Compose-internal `ollama` sidecar name are accepted;
other network hosts are rejected. Model output is never executed.
Service banners are randomized per deployment by default; set
`randomize_banners: false` only when a fixed configured identity is desired.

HTTP `POST`, `PUT`, or `PATCH` bodies up to `max_sample_size` are statically
triaged (SHA-256, file signature, entropy, strings, URL/IP candidates, and
simple indicators). Static triage never detonates a sample. To request dynamic
analysis, configure `sandbox_submit_url` to an operator-managed, isolated
analysis service. The adapter sends the raw sample bytes to that exact
configured endpoint; it does not provide a sandbox itself. Keep the endpoint
disabled unless its containment, access control, retention, and egress policy
are understood. Optional bearer credentials are read from the environment
variable named by `sandbox_auth_token_env`.

Compose attaches the honeypot and dashboard to a user-defined bridge network
with `internal: false`. The published ports bind to loopback by default, but
this network does not block container egress. Apply and verify host/cloud
firewall egress restrictions before exposing the honeypot to the internet.
The listeners never execute attacker-supplied commands or run samples.
Container services also use read-only roots, no added capabilities, and
resource/PID limits. Logs and the synthetic deployment state persist only as
documented; virtual shell modifications reset at every session.
The shell flags likely container-escape command patterns (runtime sockets,
host `/proc` paths, namespace tools, privileged-container flags, and mount
operations) as `escape_attempt`; this is an alerting heuristic, not a proof of
an escape.

The optional Ollama service is started with
`docker compose --profile llm up -d ollama`. Populate its model volume with
`docker compose exec ollama ollama pull qwen2.5:3b` before enabling
`llm_enabled`. Ollama is attached to an additional network for model retrieval.
Removing that network alone does not block egress from the default bridge;
enforce outbound restrictions with a host/cloud firewall and verify them
independently.

Configure `alert_webhook` with a Slack incoming-webhook URL to send concise
Slack notifications, or use a compatible JSON webhook. Do not expose the
read-only dashboard to untrusted networks.

### Risk scoring
Each event type has a weight (e.g. a credential attempt scores higher
than a bare connection; an uploaded payload scores highest). Scores
accumulate per source IP in `source_scores`. The dashboard and reports now
show explainable low, guarded, elevated, high, or critical triage bands with
the event types and counts contributing to the assessment. This is a
deterministic heuristic for prioritization, not a calibrated probability,
attribution, or proof of malicious intent. Treat it as analyst context rather
than an automated verdict.

## Quick start

```bash
pip install -r requirements.txt
python3 honeypot.py                    # uses built-in default ports
python3 honeypot.py --config config.yaml
python3 dashboard.py                  # http://127.0.0.1:8765
python3 dashboard.py --enable-local-ai-classification  # optional local Ollama triage
python3 check_ports.py --config config.yaml
```

## Free project website

The static project site is in `docs/`. GitHub Actions publishes that directory
to GitHub Pages when changes are pushed to `main` (or when the workflow is
manually run). In the repository settings, choose **Settings → Pages →
GitHub Actions** as the build and deployment source. The expected project URL
is `https://va9627713-byte.github.io/honeypot-hunter/`.

GitHub Pages serves static files only. It does not run the honeypot, the Python
dashboard, or a database. Never publish logs, captured indicators, credentials,
configuration secrets, or a live dashboard as part of the Pages site. Keep
public honeypot listeners on a separate, dedicated and firewalled host.

Listeners bind to `127.0.0.1` by default. Set `bind_host: 0.0.0.0` only when
you deliberately intend to expose the service from a dedicated, firewalled
honeypot host. Configure a firewall to restrict outbound traffic: this tool
does not itself enforce egress isolation.

When started with `config.yaml`, representative listener lines are:
```
[+] SSH honeypot listening on ('127.0.0.1', 2222)
[+] TELNET honeypot listening on ('127.0.0.1', 2323)
[+] FTP honeypot listening on ('127.0.0.1', 2121)
[+] HTTP honeypot listening on ('127.0.0.1', 8080)
[+] MYSQL honeypot listening on ('127.0.0.1', 13306)
[+] REDIS honeypot listening on ('127.0.0.1', 16379)
[+] SMTP honeypot listening on ('127.0.0.1', 12525)
[+] DOCKER honeypot listening on ('127.0.0.1', 2375)
[+] KUBERNETES honeypot listening on ('127.0.0.1', 6443)
[+] MODBUS honeypot listening on ('127.0.0.1', 1502)
[+] MQTT honeypot listening on ('127.0.0.1', 1883)
```

Generate harmless test traffic against local listeners (non-loopback targets
are refused):
```bash
python3 check_ports.py --config config.yaml
python3 simulate_attacks.py
python3 simulate_attacks.py --config config.yaml
```

Generate a report at any time (the honeypot doesn't need to be stopped):
```bash
python3 report.py --json ioc_feed.json
```

This prints event counts by service, top offending IPs by risk score,
common attempted usernames (never passwords), and writes an IOC feed like:
```json
[
  {"ip": "203.0.113.7", "risk_score": 82, "event_count": 23,
   "first_seen": "...", "last_seen": "..."}
]
```
That JSON is ready to feed into a SIEM, a firewall blocklist, or a
threat-intel platform (MISP, etc.).
Non-global, private, loopback, and reserved addresses are excluded from IOC
exports by default to avoid publishing simulator or internal-network addresses.
Use `report.py --include-non-global` only when preparing an internal-network
feed intentionally.

## Exposing it to real attacker traffic

The default ports (2222/2323/2121/8080) are unprivileged so you can run
this without root for local testing. To actually attract internet
scanner/bot traffic (which is the point of a honeypot), either:

- Run it on a low-cost cloud VM with **no other services**, and forward
  the standard ports to it (22→2222, 23→2323, 21→2121, 80→8080) with
  `iptables`/security-group rules, or
- Run the process on a dedicated isolated host with the required low-port
  capabilities and change the configured ports directly.

Do not deploy this on a host containing valuable workloads or management
services. The production Compose override publishes the honeypot listeners
on host ports, including ports 22 and 80; check for host-port conflicts and
restrict ingress and egress with a separately tested host/cloud firewall.
The app does not enforce egress isolation.

For the production Compose override, first create the runtime config from the
supported example and review it:
```bash
cp docker-config.prod.example.yaml config.prod.yaml
```
Keep `config.prod.yaml` out of version control and replace the example alert
webhook only through a secret-managed local configuration. Start with:
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```
The dashboard is bound to host loopback at `127.0.0.1:8765`; it has no
built-in authentication or TLS. Access it locally, through an SSH tunnel, or
through a separately configured reverse proxy that enforces authentication
and TLS. Do not change the dashboard port binding to a public interface.
For SSH-tunnel access, run this from your workstation:
```bash
ssh -L 8765:127.0.0.1:8765 user@honeypot-host
```
Then open `http://127.0.0.1:8765` locally.

For isolated local evaluation, `docker compose up --build` starts the honeypot
and dashboard with all eleven emulated services. Every host-published port is bound to `127.0.0.1`; only change
this for a dedicated isolated deployment with deliberate firewall policy. The
dashboard has no authentication and must not be exposed to untrusted networks.
For container GeoIP, add a read-only mount for your licensed database at
`/geo/GeoLite2-City.mmdb` under the honeypot service's `volumes`, then set
`geoip_db_path` in `docker-config.yaml` and build with the optional reader
installed by setting `INSTALL_GEOIP=true` in the environment.

## Extending it

- Add more fake services by writing a new `handle_<service>` coroutine
  in `honeypot.py` and calling `self.ti.log_event(...)` at each
  interesting point — the logging/scoring backend is already generic.
- Feed `logs/events.jsonl` into Elasticsearch/Grafana/Splunk; it is
  newline-delimited JSON.

## Product roadmap

The current repository is a prototype; the following are goals, not claims
about shipped functionality:

- **SOC workflows:** dashboard time-range/service filters are implemented.
  Incident timelines, analyst annotations, richer evidence bundles, and
  documented retention/purge controls remain future work.
- **ICS/OT operations:** Modbus and MQTT protocol emulations are included.
  OT-specific safe profiles, protocol-focused investigation views, and
  environment validation need further design and testing with qualified
  operators before production use.
- **Research and education:** the loopback-only simulator and synthetic state
  support local demonstrations. Named reproducible scenarios, seeded runs,
  and machine-readable lab results remain future work.
- **Operational readiness:** CI now runs the regression suite across the
  declared Python versions, builds the package and container, audits runtime
  dependencies, scans the image, and publishes an SPDX SBOM artifact. Load and
  parser-fuzz testing plus externally validated network controls remain future
  work; a passing CI scan is not a production security certification.

## Legal and ethical use

- Only deploy this on infrastructure you own or are explicitly
  authorized to monitor.
- A honeypot exists to observe unsolicited/malicious traffic that
  reaches it on its own (scanners, credential-stuffing bots) — don't
  use it to lure or entrap specific individuals, and don't place it
  inside a network you don't control.
- Check your hosting provider's and local jurisdiction's rules on
  running deception services before exposing this to the internet.
- Captured credentials/IPs are sensitive data — handle and store the
  `logs/` directory accordingly (access control, retention policy).
