# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-10-05

### Added
- **Real SSH handshake** via asyncssh with configurable credential retention (off/hashed/full)
- **MITRE ATT&CK auto-tagging** for all event types
- **Behavior clustering** with fingerprinting and sophistication scoring
- **Anti-pollution** rate limiting with configurable thresholds
- **Hash-chained JSONL logs** (SHA-256 chained for tamper evidence)
- **11 protocol services**: SSH, Telnet, FTP, HTTP, MySQL, Redis, SMTP, Docker API, Kubernetes API, Modbus TCP, MQTT
- **Dashboard** with real-time API, WebSocket updates, filtering, session replay
- **Report generator** with risk scoring, explainable triage bands, IOC export (JSON)
- **Enterprise config system**: YAML/JSON/TOML, env vars, secrets (Vault, AWS, Azure, K8s), hot-reload
- **Validation framework** with cross-dependency checks
- **Secrets management**: Multi-provider (Vault, AWS, Azure, K8s, Docker, files) with caching
- **Hot reload** config watcher with debounced callbacks
- **Database layer**: Async PostgreSQL with pooling, migrations, repositories
- **Models**: Events, Sources, Credentials, Artifacts, Alerts, Sensors, BehaviorClusters, ThreatIntel, AuditLogs
- **Enterprise config**: 20+ config sections (DB, TLS, Auth, Network, Services, Monitoring, Export, Retention, Sensor, Collector, Plugins, HA, UI)
- **Attack simulator** for all 11 protocols with real SSH via asyncssh
- **Artifact analysis**: Static triage with entropy, YARA-ready, sandbox handoff
- **Local LLM integration** for unknown command responses (Ollama-compatible)
- **Synthetic system state** per deployment (randomized banners, processes, filesystem, network)
- **Anti-escape heuristics** for container escape detection
- **Read-only dashboard** with CSP, rate limiting, session replay
- **IOC export** with STIX/CEF/Syslog/Elastic/Splunk/Kafka formats
- **46 comprehensive tests** covering config, logging, protocols, dashboard, artifact analysis

### Changed
- SSH now uses real asyncssh handshake by default (was plaintext simulation)
- Credential retention now configurable (off/hashed/full)
- HTTP routine probes now classified as low-weight `http_recon`
- Dashboard JavaScript served separately with proper MIME type
- Config validation now includes cross-dependency checks

### Security
- Passwords redacted by default, configurable retention
- Hash-chained logs with fail-closed startup verification
- Anti-pollution filtering prevents log flooding
- Read-only dashboard with CSP headers
- No sample execution in artifact analysis
- Container services with read-only roots, no capabilities

## [1.0.0] - 2024-01-15

### Added
- Initial release
- Basic honeypot with SSH, Telnet, FTP, HTTP, MySQL, Redis, SMTP
- Threat intelligence logging with SQLite + JSONL
- Risk scoring per source IP
- Basic dashboard
- Attack simulator
- Report generator
- Docker Compose deployment
- 19 initial tests

---

## Release Notes Format

### [MAJOR.MINOR.PATCH] - YYYY-MM-DD

#### Added
- New features

#### Changed
- Changes in existing functionality

#### Deprecated
- Soon-to-be removed features

#### Removed
- Now removed features

#### Fixed
- Bug fixes

#### Security
- Security improvements