#!/usr/bin/env python3
"""
honeypot.py — Custom multi-service honeypot with threat intelligence logging.

Purpose:
  A defensive deception tool. It opens fake network services that look
  interesting to attackers/scanners, records everything they do (source IP,
  credentials tried, commands run, payloads sent), and scores each source
  by risk so you can build a threat-intel feed of hostile IPs.

Services emulated (all fake — no real shell, no real file access):
  - SSH   (banner + fake auth prompt, logs credential attempts)
  - Telnet(banner + fake auth prompt + fake shell that logs "commands")
  - HTTP  (fake web server; logs paths, headers, common exploit probes)
  - FTP   (banner + fake auth + fake command handling)
  - MySQL (fake handshake + auth logging)
  - Redis (RESP protocol + command logging)
  - SMTP  (ESMTP + AUTH logging)
  - Docker API (fake Docker daemon API)
  - Kubernetes API (fake K8s API server)
  - Modbus TCP (ICS/SCADA protocol)
  - MQTT (IoT messaging protocol)

Run:
  python3 honeypot.py --config config.yaml
  python3 honeypot.py                       # uses built-in defaults

IMPORTANT / LEGAL:
  Only deploy on infrastructure you own or are authorized to monitor.
  Do not use this to attract or entrap unauthorized third parties into
  a network you do not control. Default ports below are UNPRIVILEGED
  (>1024) so the tool can run without root; map them to standard ports
  (22, 21, 23, 80) via your firewall/NAT if you want real attacker traffic.
"""

import argparse
import asyncio
import base64
import binascii
import copy
import hashlib
import json
import logging
import os
import posixpath
import random
import re
import signal
import time
import urllib.error
from collections import defaultdict, deque
from datetime import UTC, datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

from artifact_analysis import (
    MAX_SAMPLE_SIZE,
    analyze_sample,
    submit_to_sandbox,
    validate_sandbox_url,
)
from local_llm import generate_shell_output, validate_local_llm_url
from system_state import SystemState, get_system_state
from ti_logger import ThreatIntelLogger

# Optional asyncssh for real SSH support
try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    asyncssh = None  # type: ignore
    ASYNCSSH_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("honeypot")

# MITRE ATT&CK technique mappings for common honeypot events
MITRE_TECHNIQUES = {
    "ssh.auth_attempt": ["T1110.001", "T1021.004"],  # Brute Force: Password Guessing, Remote Services: SSH
    "ssh.auth_success_fake": ["T1021.004", "T1078.003"],  # Remote Services: SSH, Valid Accounts: Local
    "telnet.auth_attempt": ["T1110.001", "T1021.001"],  # Brute Force, Remote Services: Telnet
    "telnet.auth_success_fake": ["T1021.001", "T1078.003"],
    "ftp.auth_attempt": ["T1110.001", "T1021.002"],  # Remote Services: SMB/FTP
    "ftp.payload_upload": ["T1105", "T1505.003"],  # Ingress Tool Transfer, Web Shell
    "http.http_exploit_attempt": ["T1190", "T1505.003"],  # Exploit Public-Facing Application, Web Shell
    "http.http_recon": ["T1595"],  # Active Scanning
    "http.command": ["T1505.003", "T1059.001"],  # Web Shell, Command and Scripting Interpreter
    "http.payload_upload": ["T1105", "T1505.003"],
    "mysql.auth_attempt": ["T1110.001", "T1505.004"],  # Brute Force, SQL Injection
    "redis.auth_attempt": ["T1110.001", "T1505.003"],
    "redis.command": ["T1059.001", "T1505.003"],
    "smtp.auth_attempt": ["T1110.001", "T1566.001"],  # Phishing: Spearphishing Attachment
    "smtp.command": ["T1566.001"],
    "docker.command": ["T1505.004", "T1611"],  # Escape to Host, Container API
    "ssh.escape_attempt": ["T1611"],
    "telnet.escape_attempt": ["T1611"],
    "kubernetes.command": ["T1505.004", "T1610"],  # Deploy Container, Container Orchestration
    "modbus.command": ["T0883", "T0831"],  # Manipulate I/O, Manipulate Control
    "mqtt.auth_attempt": ["T1110.001", "T1505.003"],
    "mqtt.publish": ["T1071.004"],
}

# Realistic banner pools for anti-fingerprinting
SSH_BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
    "SSH-2.0-OpenSSH_8.0p1",
    "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7.1",
    "SSH-2.0-OpenSSH_8.6p1",
    "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb10u7",
    "SSH-2.0-OpenSSH_8.7p1 Ubuntu-3ubuntu0.2",
]

TELNET_BANNERS = [
    "Ubuntu 22.04.3 LTS",
    "Ubuntu 20.04.6 LTS",
    "Debian GNU/Linux 11",
    "Debian GNU/Linux 12",
    "CentOS Linux 7 (Core)",
    "Rocky Linux 8.9 (Green Obsidian)",
    "Alpine Linux 3.18",
    "Linux Mint 21.2",
    "Fedora Linux 38",
    "openSUSE Leap 15.5",
]

FTP_BANNERS = [
    "220 (vsFTPd 3.0.5)",
    "220 ProFTPD 1.3.7a Server",
    "220 Pure-FTPd [TLS]",
    "220 Microsoft FTP Service",
    "220 vsftpd 3.0.3",
    "220 (vsFTPd 3.0.3)",
]

HTTP_SERVER_HEADERS = [
    "Apache/2.4.52 (Ubuntu)",
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0 (Ubuntu)",
    "nginx/1.20.1",
    "nginx/1.14.0 (Debian)",
    "Microsoft-IIS/10.0",
    "lighttpd/1.4.59",
    "Apache/2.4.57 (Debian)",
    "openresty/1.21.4.1",
    "Caddy/2.6.4",
]

MYSQL_BANNERS = [
    "8.0.36-honeypot",
    "8.0.33-0ubuntu0.20.04.2",
    "8.0.36-0ubuntu0.22.04.1",
    "5.7.42-0ubuntu0.20.04.1",
    "10.11.4-MariaDB-1:10.11.4+maria~ubu2204",
    "10.6.12-MariaDB-1:10.6.12+maria~deb11",
]

REDIS_BANNERS = [
    "7.2.4",
    "7.0.12",
    "6.2.7",
    "6.0.16",
    "5.0.14",
]

SMTP_HOSTNAMES = [
    "mail.local",
    "mail.internal",
    "smtp.corp",
    "mail.example.com",
    "mx1.internal",
    "postfix.local",
]

DOCKER_API_VERSIONS = [
    "1.44",
    "1.43",
    "1.42",
    "1.41",
]

KUBERNETES_VERSIONS = [
    "v1.28.3",
    "v1.27.7",
    "v1.26.10",
    "v1.25.14",
]

HTTP_EXPLOIT_SIGNATURES = [
    "/etc/passwd", "..%2f", "../../", "cmd.exe", "/wp-login.php", "/phpmyadmin",
    "select+*+from", "union select", "<script>", "/.env", "/.git/config",
    "/actuator/env", "/actuator/heapdump", "/actuator/configprops",
    "/actuator/mappings", "boot.ini", "/solr/", "xp_cmdshell",
    "/admin", "/wp-admin", "/administrator", "/config", "/backup", "/.well-known",
    "/server-status", "/server-info", "/phpinfo", "/test.php", "/shell.php",
    "eval(", "base64_decode", "system(", "exec(", "shell_exec", "passthru",
    "/wp-json", "/xmlrpc", "/drupal", "/joomla", "/magento",
    "/jenkins", "/gitlab", "/harbor", "/registry", "/kibana", "/grafana",
    "wp-config", "config.php", "local.xml", "settings.py", "manage.py",
    "/vendor/", "/composer", "/package.json", "/.npm", "/.docker",
    "/k8s", "/kubernetes", "/rancher", "/consul", "/vault", "/nomad",
    "/docker/",
    "wp-admin/admin-ajax.php", "xmlrpc.php", "wp-cron.php",
    "configuration.php", "local.xml", "app/etc/local.xml",
    "/.git/HEAD", "/.svn/entries", "/.hg/store",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    "web.config", ".htaccess", ".env", ".env.local", ".env.production",
]

HTTP_RECON_SIGNATURES = (
    "/actuator/health", "/metrics", "/health", "/ready", "/live", "/api/",
)

DEFAULT_CONFIG = {
    "bind_host": "127.0.0.1",
    "max_connections": 100,
    "max_request_headers": 100,
    "rate_limit_connections": 30,
    "rate_limit_window_seconds": 60,
    "max_rate_limit_sources": 10000,
    "geoip_db_path": None,
    "alert_webhook": None,
    "alert_event_types": ["auth_success_fake", "http_exploit_attempt", "payload_upload", "docker.command", "kubernetes.command", "escape_attempt"],
    "auto_block_score": 0,
    "sandbox_submit_url": None,
    "sandbox_auth_token_env": None,
    "llm_enabled": False,
    "llm_endpoint": "http://127.0.0.1:11434/api/generate",
    "llm_model": "qwen2.5:3b",
    "max_sample_size": MAX_SAMPLE_SIZE,
    "services": {
        "ssh":    {"enabled": True, "port": 2222, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "real_ssh": True, "credential_retention": "hashed", "host_key_path": None},
        "telnet": {"enabled": True, "port": 2323, "banner": "Ubuntu 22.04 LTS"},
        "ftp":    {"enabled": True, "port": 2121, "banner": "220 (vsFTPd 3.0.5)"},
        "http":   {"enabled": True, "port": 8080, "server_header": "Apache/2.4.52 (Ubuntu)"},
        "mysql":  {"enabled": True, "port": 3306, "banner": "8.0.36-honeypot"},
        "redis":  {"enabled": True, "port": 6379, "banner": "7.2.4"},
        "smtp":   {"enabled": True, "port": 2525, "hostname": "mail.local"},
        "docker": {"enabled": True, "port": 2375, "api_version": "1.44"},
        "kubernetes": {"enabled": True, "port": 6443, "version": "v1.28.3"},
        "modbus": {"enabled": True, "port": 1502, "unit_id": 1},
        "mqtt":   {"enabled": True, "port": 1883, "broker_name": "mosquitto-1"},
    },
    "max_session_seconds": 60,
    "fake_login_fail_count": 3,
    "system_seed": None,  # None = randomize per run
    "enable_mitre_tagging": True,
    "anti_pollution": True,
    "pollution_threshold": 100,  # events per minute from same IP = pollution
    "randomize_banners": True,
}


if ASYNCSSH_AVAILABLE:
    class _HoneypotSSHProtocol(asyncssh.SSHServer):
        def __init__(self, honeypot, credential_retention):
            self.honeypot = honeypot
            self.credential_retention = credential_retention
            self.ip = "unknown"
            self.port = 0
            self.session_id = None
            self.username = None
            self.conn = None
            self._accepted = False
            self._success_logged = False
            self._timeout_handle = None

        def connection_made(self, conn):
            self.conn = conn
            peer = conn.get_extra_info("peername")
            self.ip, self.port = (peer[0], peer[1]) if peer else ("unknown", 0)
            self._accepted = self.honeypot._begin_connection(self.ip, "ssh")
            if not self._accepted:
                conn.close()
                return
            self.session_id = self.honeypot._new_session_id("ssh")
            self.honeypot._log_event(
                self.ip, "ssh", "connection", {"port": self.port}, self.port, self.session_id
            )
            self._timeout_handle = asyncio.get_running_loop().call_later(
                self.honeypot.config["max_session_seconds"], conn.close
            )

        def connection_lost(self, exc):
            if self._timeout_handle is not None:
                self._timeout_handle.cancel()
            if self._accepted:
                self.honeypot._end_connection()
                self._accepted = False

        def begin_auth(self, username):
            self.username = username
            return True

        def password_auth_supported(self):
            return True

        def public_key_auth_supported(self):
            return False

        def validate_password(self, username, password):
            self.username = username
            detail = {"username": username}
            if self.credential_retention == "hashed":
                detail["password_hash"] = hashlib.sha256(password.encode()).hexdigest()[:16]
            self.honeypot._log_event(
                self.ip, "ssh", "auth_attempt", detail, self.port, self.session_id
            )
            return True

        def session_requested(self):
            if not self._accepted:
                return False
            if not self._success_logged:
                self.honeypot._log_event(
                    self.ip,
                    "ssh",
                    "auth_success_fake",
                    {"username": self.username},
                    self.port,
                    self.session_id,
                )
                self._success_logged = True
            return _HoneypotSSHSession(self)


    class _HoneypotSSHSession(asyncssh.SSHServerSession):
        def __init__(self, protocol):
            self.protocol = protocol
            self.channel = None
            self.command = None
            self._input = bytearray()

        def connection_made(self, channel):
            self.channel = channel

        def pty_requested(self, term_type, term_size, term_modes):
            return True

        def shell_requested(self):
            return True

        def exec_requested(self, command):
            self.command = command
            return True

        def subsystem_requested(self, subsystem):
            return False

        def session_started(self):
            if self.command is not None:
                self._execute_command(self.command, close_channel=True)
                return
            now = datetime.now(UTC).strftime("%a %b %d %H:%M:%S %Y")
            self.channel.write(f"\r\nLast login: {now} from 10.0.0.1\r\n$ ".encode())

        def data_received(self, data, datatype):
            if self.command is not None or datatype is not None:
                return
            self._input.extend(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
            if len(self._input) > 4096 and b"\n" not in self._input:
                self._input.clear()
                self.channel.write(b"Command too long.\r\n$ ")
                return
            while b"\n" in self._input:
                raw_command, _, remainder = self._input.partition(b"\n")
                self._input = bytearray(remainder)
                command = raw_command.decode(errors="replace").strip()
                if self._execute_command(command, close_channel=False):
                    return
                self.channel.write(b"$ ")

        def _execute_command(self, command, close_channel):
            hp = self.protocol.honeypot
            hp._log_event(
                self.protocol.ip,
                "ssh",
                "command",
                {"cmd": command},
                self.protocol.port,
                self.protocol.session_id,
            )
            output = hp._fake_command_output(command) or b""
            if output:
                self.channel.write(output.rstrip(b"\r\n") + b"\r\n")
            if command.strip() in ("exit", "logout", "quit") or close_channel:
                self.channel.exit(0)
                self.channel.close()
                return True
            return False
else:
    _HoneypotSSHProtocol = None
    _HoneypotSSHSession = None


# Global system state instance
_system_state: Optional[SystemState] = None


class Honeypot:
    def __init__(self, config: dict):
        self.config = copy.deepcopy(config)
        seed = self.config.get("system_seed")
        self._rng = random.Random(seed if seed is not None else random.SystemRandom().getrandbits(128))
        self.ti = ThreatIntelLogger(
            geoip_db_path=self.config.get("geoip_db_path"),
            alert_webhook=self.config.get("alert_webhook"),
            alert_event_types=self.config.get("alert_event_types"),
            auto_block_score=self.config.get("auto_block_score", 0),
        )
        self.session_counter = 0
        self.active_connections = 0
        self.source_connections = defaultdict(deque)
        self.rate_limited_sources = set()
        self._shutdown = False
        self._servers = []
        self._ssh_host_key = None
        
        # Initialize system state
        global _system_state
        _system_state = get_system_state(seed)
        self.sys = _system_state
        
        # Anti-pollution tracking
        self.pollution_counts = defaultdict(deque)
        self.pollution_reported = set()
        
        # Randomize banners if not specified
        self._randomize_banners()

    def _new_session_id(self, service: str) -> str:
        self.session_counter += 1
        return f"{service}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.session_counter}"

    def _signal_handler(self, sig):
        log.info("Received signal %s, initiating graceful shutdown...", sig)
        self._shutdown = True
        for server in self._servers:
            server.close()

    def _randomize_banners(self):
        """Randomize service banners for anti-fingerprinting."""
        if not self.config.get("randomize_banners", False):
            return
        svc = self.config["services"]
        svc["ssh"]["banner"] = self._rng.choice(SSH_BANNERS)
        svc["telnet"]["banner"] = self._rng.choice(TELNET_BANNERS)
        svc["ftp"]["banner"] = self._rng.choice(FTP_BANNERS)
        svc["http"]["server_header"] = self._rng.choice(HTTP_SERVER_HEADERS)
        svc["mysql"]["banner"] = self._rng.choice(MYSQL_BANNERS)
        svc["redis"]["banner"] = self._rng.choice(REDIS_BANNERS)
        svc["smtp"]["hostname"] = self._rng.choice(SMTP_HOSTNAMES)
        svc["docker"]["api_version"] = self._rng.choice(DOCKER_API_VERSIONS)
        svc["kubernetes"]["version"] = self._rng.choice(KUBERNETES_VERSIONS)
        svc["mqtt"]["broker_name"] = f"mosquitto-{self._rng.randint(1, 3)}"

    def _add_mitre_tags(self, detail: dict, service: str, event_type: str):
        """Add MITRE ATT&CK tags to event detail."""
        if not self.config.get("enable_mitre_tagging", True):
            return
        key = f"{service}.{event_type}"
        techniques = MITRE_TECHNIQUES.get(key, [])
        if techniques:
            detail["mitre_techniques"] = techniques

    def _check_pollution(self, ip: str) -> bool:
        """Check if source IP is polluting (too many events)."""
        if not self.config.get("anti_pollution", True):
            return False
        now = time.monotonic()
        window = 60  # 1 minute window
        threshold = self.config.get("pollution_threshold", 100)
        if ip not in self.pollution_counts and len(self.pollution_counts) >= self.config["max_rate_limit_sources"]:
            oldest_ip = next(iter(self.pollution_counts))
            self.pollution_counts.pop(oldest_ip, None)
            self.pollution_reported.discard(oldest_ip)
        recent = self.pollution_counts[ip]
        while recent and now - recent[0] > window:
            recent.popleft()
        if len(recent) < threshold:
            self.pollution_reported.discard(ip)
            recent.append(now)
            return False
        return True

    def _log_event(self, ip: str, service: str, event_type: str, detail: dict, port: int = None, session_id: str = None):
        """Wrapper to log events with MITRE tags and pollution checking."""
        detail = dict(detail or {})
        if self._check_pollution(ip):
            if ip not in self.pollution_reported:
                self.pollution_reported.add(ip)
                self.ti.log_event(ip, service, "pollution_detected",
                                  {"suppressed_event_type": event_type}, port, session_id)
            return
        
        self._add_mitre_tags(detail, service, event_type)
        self.ti.log_event(ip, service, event_type, detail, port, session_id)

    def _begin_connection(self, source_ip: str, service_name: str) -> bool:
        if self.ti.is_blocked(source_ip):
            return False
        now = time.monotonic()
        if (source_ip not in self.source_connections
                and len(self.source_connections) >= self.config["max_rate_limit_sources"]):
            oldest_ip = next(iter(self.source_connections))
            self.source_connections.pop(oldest_ip, None)
            self.rate_limited_sources.discard(oldest_ip)
        recent = self.source_connections[source_ip]
        while recent and now - recent[0] > self.config["rate_limit_window_seconds"]:
            recent.popleft()
        if not recent:
            self.rate_limited_sources.discard(source_ip)
        if len(recent) >= self.config["rate_limit_connections"]:
            if source_ip not in self.rate_limited_sources:
                self.rate_limited_sources.add(source_ip)
                self.ti.log_event(
                    source_ip,
                    service_name,
                    "rate_limited",
                    {"window_seconds": self.config["rate_limit_window_seconds"]},
                )
            return False
        recent.append(now)
        if self.active_connections >= self.config["max_connections"]:
            return False
        self.active_connections += 1
        return True

    def _end_connection(self) -> None:
        self.active_connections = max(0, self.active_connections - 1)

    def _get_ssh_host_key(self, cfg: dict):
        if self._ssh_host_key is not None:
            return self._ssh_host_key
        if not ASYNCSSH_AVAILABLE:
            raise RuntimeError("Real SSH requires AsyncSSH; install the project runtime dependencies")
        host_key_path = cfg.get("host_key_path")
        if host_key_path:
            if not os.path.isfile(host_key_path):
                raise FileNotFoundError(f"Configured SSH host key does not exist: {host_key_path}")
            self._ssh_host_key = asyncssh.read_private_key(host_key_path)
        else:
            self._ssh_host_key = asyncssh.generate_private_key("ssh-ed25519")
        return self._ssh_host_key

    async def _start_ssh_server(self, cfg: dict):
        if not ASYNCSSH_AVAILABLE:
            raise RuntimeError("Real SSH requires AsyncSSH; install the project runtime dependencies")
        server_version = cfg["banner"].removeprefix("SSH-2.0-")
        return await asyncssh.create_server(
            lambda: _HoneypotSSHProtocol(self, cfg.get("credential_retention", "hashed")),
            self.config["bind_host"],
            cfg["port"],
            server_host_keys=[self._get_ssh_host_key(cfg)],
            server_version=server_version,
            encoding=None,
            login_timeout=30,
        )

    # ---------------------------------------------------------------- SSH --
    async def handle_ssh(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("ssh")
        cfg = self.config["services"]["ssh"]

        self._log_event(ip, "ssh", "connection", {"port": port}, port, session_id)
        try:
            writer.write((cfg["banner"] + "\r\n").encode())
            await writer.drain()

            try:
                raw = await asyncio.wait_for(reader.read(256), timeout=5)
                if raw:
                    self._log_event(ip, "ssh", "port_scan_pattern",
                                       {"raw_client_hello": raw[:120].hex()}, port, session_id)
            except asyncio.TimeoutError:
                pass

            fails = 0
            while fails < self.config["fake_login_fail_count"] + 2:
                writer.write(b"login as: ")
                await writer.drain()
                username = await self._readline(reader)
                if username is None:
                    break
                writer.write(f"{username}@server's password: ".encode())
                await writer.drain()
                password = await self._readline(reader, echo_hidden=True)
                if password is None:
                    break

                self._log_event(ip, "ssh", "auth_attempt",
                                   {"username": username, "password": password}, port, session_id)
                fails += 1
                if fails > self.config["fake_login_fail_count"]:
                    self._log_event(ip, "ssh", "auth_success_fake",
                                       {"username": username}, port, session_id)
                    await self._fake_shell(reader, writer, ip, "ssh", session_id)
                    break
                else:
                    writer.write(b"Permission denied, please try again.\r\n")
                    await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    # ------------------------------------------------------------- Telnet --
    async def handle_telnet(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("telnet")
        cfg = self.config["services"]["telnet"]

        self._log_event(ip, "telnet", "connection", {"port": port}, port, session_id)
        try:
            writer.write((cfg["banner"] + "\r\nlogin: ").encode())
            await writer.drain()

            fails = 0
            while fails < self.config["fake_login_fail_count"] + 2:
                username = await self._readline(reader)
                if username is None:
                    break
                writer.write(b"Password: ")
                await writer.drain()
                password = await self._readline(reader, echo_hidden=True)
                if password is None:
                    break

                self._log_event(ip, "telnet", "auth_attempt",
                                   {"username": username, "password": password}, port, session_id)
                fails += 1
                if fails > self.config["fake_login_fail_count"]:
                    self._log_event(ip, "telnet", "auth_success_fake",
                                       {"username": username}, port, session_id)
                    await self._fake_shell(reader, writer, ip, "telnet", session_id)
                    break
                else:
                    writer.write(b"\r\nLogin incorrect\r\nlogin: ")
                    await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    # ---------------------------------------------------------------- FTP --
    async def handle_ftp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("ftp")
        cfg = self.config["services"]["ftp"]

        self._log_event(ip, "ftp", "connection", {"port": port}, port, session_id)
        try:
            writer.write((cfg["banner"] + "\r\n").encode())
            await writer.drain()
            username = None
            while True:
                line = await self._readline(reader)
                if line is None:
                    break
                parts = line.strip().split(" ", 1)
                cmd = parts[0].upper() if parts else ""
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    username = arg
                    writer.write(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    self._log_event(ip, "ftp", "auth_attempt",
                                       {"username": username, "password": arg}, port, session_id)
                    writer.write(b"530 Login incorrect.\r\n")
                elif cmd == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                elif cmd in ("STOR", "APPE"):
                    self._log_event(ip, "ftp", "payload_upload", {"filename": arg}, port, session_id)
                    writer.write(b"550 Permission denied.\r\n")
                else:
                    self._log_event(ip, "ftp", "command", {"cmd": cmd, "arg": arg}, port, session_id)
                    writer.write(b"502 Command not implemented.\r\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    # ---------------------------------------------------------------- HTTP --
    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("http")
        cfg = self.config["services"]["http"]

        self._log_event(ip, "http", "connection", {"port": port}, port, session_id)
        try:
            request_line = await self._readline(reader)
            if request_line is None:
                writer.close()
                return
            headers = {}
            header_count = 0
            while True:
                line = await self._readline(reader)
                if line is None or line == "":
                    break
                header_count += 1
                if header_count > self.config["max_request_headers"]:
                    self._log_event(ip, "http", "malformed_request",
                                      {"reason": "too_many_headers"}, port, session_id)
                    return
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            try:
                method, path, _ = request_line.split(" ", 2)
            except ValueError:
                method, path = "GET", "/"

            content_length = 0
            if "transfer-encoding" in headers:
                self._log_event(ip, "http", "malformed_request",
                                {"reason": "transfer_encoding_not_supported"}, port, session_id)
                status, body = "501 Not Implemented", b""
            else:
                try:
                    content_length = int(headers.get("content-length", "0"))
                except ValueError:
                    content_length = -1
                if content_length < 0:
                    self._log_event(ip, "http", "malformed_request",
                                    {"reason": "invalid_content_length"}, port, session_id)
                    status, body = "400 Bad Request", b""
                elif content_length > self.config["max_sample_size"]:
                    self._log_event(ip, "http", "malformed_request", {
                        "reason": "sample_too_large",
                        "size": content_length,
                        "limit": self.config["max_sample_size"],
                    }, port, session_id)
                    status, body = "413 Content Too Large", b""
                else:
                    status = "200 OK"
                    body = b"<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"
                    if method.upper() in ("POST", "PUT", "PATCH") and content_length:
                        try:
                            sample = await asyncio.wait_for(
                                reader.readexactly(content_length), timeout=5
                            )
                        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                            self._log_event(ip, "http", "malformed_request",
                                            {"reason": "incomplete_upload"}, port, session_id)
                            status, body = "400 Bad Request", b""
                        else:
                            triage = analyze_sample(sample)
                            detail = {
                                "method": method,
                                "path": path,
                                "sha256": triage["sha256"],
                                "size": triage["size"],
                                "file_type": triage["file_type"],
                                "entropy": triage["entropy"],
                                "urls": triage["urls"],
                                "ipv4_candidates": triage["ipv4_candidates"],
                                "static_markers": triage["static_markers"],
                            }
                            self._log_event(ip, "http", "payload_upload", detail, port, session_id)
                            self._log_event(ip, "http", "sample_triage", triage, port, session_id)
                            await self._submit_sample(ip, "http", session_id, sample, triage["sha256"])
                            status, body = "202 Accepted", b""

            detail = {"method": method, "path": path, "user_agent": headers.get("user-agent", "")}
            normalized_path = unquote(urlsplit(path).path).lower()
            exploit_sig = next(
                (signature for signature in HTTP_EXPLOIT_SIGNATURES
                 if signature in normalized_path),
                None,
            )
            recon_sig = next(
                (signature for signature in HTTP_RECON_SIGNATURES
                 if signature in normalized_path),
                None,
            )
            if exploit_sig:
                detail["matched_signature"] = exploit_sig
                self._log_event(ip, "http", "http_exploit_attempt", detail, port, session_id)
            elif recon_sig:
                detail["matched_signature"] = recon_sig
                self._log_event(ip, "http", "http_recon", detail, port, session_id)
            else:
                self._log_event(ip, "http", "command", detail, port, session_id)

            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Server: {cfg['server_header']}\r\n"
                f"Content-Type: {'text/html' if body else 'text/plain'}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body
            writer.write(response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    async def _submit_sample(self, ip: str, service: str, session_id: str,
                             sample: bytes, sha256: str) -> None:
        endpoint = self.config.get("sandbox_submit_url")
        if not endpoint:
            return
        env_name = self.config.get("sandbox_auth_token_env")
        token = os.environ.get(env_name) if env_name else None
        if env_name and not token:
            log.error("Sandbox submission skipped: configured token environment variable is unset")
            self._log_event(ip, service, "sandbox_submission_failed",
                            {"sha256": sha256, "reason": "missing_auth_token"},
                            session_id=session_id)
            return
        try:
            status = await asyncio.to_thread(submit_to_sandbox, endpoint, sample, token)
        except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            log.warning("Isolated sandbox submission failed for sample %s: %s", sha256, exc)
            self._log_event(ip, service, "sandbox_submission_failed",
                            {"sha256": sha256, "reason": exc.__class__.__name__},
                            session_id=session_id)
            return
        self._log_event(ip, service, "sandbox_submission",
                        {"sha256": sha256, "http_status": status}, session_id=session_id)

    # ------------------------------------------------------------- MySQL --
    @staticmethod
    def _mysql_packet(payload: bytes, sequence: int) -> bytes:
        return len(payload).to_bytes(3, "little") + bytes((sequence,)) + payload

    async def handle_mysql(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("mysql")
        self._log_event(ip, "mysql", "connection", {"port": port}, port, session_id)
        server_version = self.config["services"]["mysql"]["banner"].encode("ascii", errors="replace")
        scramble = b"honeypot-scramble-01"
        capabilities = 0x00088200
        greeting = (
            b"\x0a" + server_version + b"\x00" + (1).to_bytes(4, "little") +
            scramble[:8] + b"\x00" + (capabilities & 0xffff).to_bytes(2, "little") +
            b"\x21" + b"\x02\x00" + (capabilities >> 16).to_bytes(2, "little") +
            bytes((len(scramble) + 1,)) + b"\x00" * 10 + scramble[8:] + b"\x00" +
            b"mysql_native_password\x00"
        )
        try:
            writer.write(self._mysql_packet(greeting, 0))
            await writer.drain()
            try:
                header = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                self._log_event(ip, "mysql", "malformed_request", {"reason": "incomplete_header"}, port, session_id)
                return
            packet_length = int.from_bytes(header[:3], "little")
            if packet_length > 1024 * 1024:
                self._log_event(ip, "mysql", "malformed_request", {"reason": "packet_too_large"}, port, session_id)
                return
            try:
                payload = await reader.readexactly(packet_length)
            except asyncio.IncompleteReadError:
                self._log_event(ip, "mysql", "malformed_request", {"reason": "incomplete_payload"}, port, session_id)
                return
            username = ""
            if len(payload) >= 33:
                username_raw = payload[32:].split(b"\x00", 1)[0]
                username = username_raw.decode("utf-8", errors="replace")[:128]
            self._log_event(ip, "mysql", "auth_attempt", {"username": username}, port, session_id)
            error = (b"\xff" + (1045).to_bytes(2, "little") + b"#28000" +
                     b"Access denied for user")
            writer.write(self._mysql_packet(error, (header[3] + 1) & 0xff))
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # ------------------------------------------------------------- Redis --
    async def _read_redis_command(self, reader):
        prefix = await reader.readexactly(1)
        if prefix == b"*":
            count_line = await reader.readline()
            if not count_line:
                raise ValueError("incomplete RESP array count")
            try:
                count = int(count_line.strip())
            except ValueError:
                raise ValueError("invalid RESP array size")
            if not 1 <= count <= 32:
                raise ValueError("invalid RESP array size")
            parts = []
            for _ in range(count):
                if await reader.readexactly(1) != b"$":
                    raise ValueError("expected RESP bulk string")
                size_line = await reader.readline()
                if not size_line:
                    raise ValueError("incomplete RESP bulk string size")
                try:
                    size = int(size_line.strip())
                except ValueError:
                    raise ValueError("invalid RESP bulk string size")
                if not 0 <= size <= 8192:
                    raise ValueError("invalid RESP bulk string size")
                data = await reader.readexactly(size)
                parts.append(data.decode("utf-8", errors="replace"))
                if await reader.readexactly(2) != b"\r\n":
                    raise ValueError("invalid RESP terminator")
            return parts
        line = prefix + await reader.readline()
        return line.decode("utf-8", errors="replace").strip().split()

    async def handle_redis(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("redis")
        cfg = self.config["services"]["redis"]
        self._log_event(ip, "redis", "connection", {"port": port}, port, session_id)
        try:
            while True:
                try:
                    parts = await self._read_redis_command(reader)
                except (asyncio.IncompleteReadError, ValueError, UnicodeError):
                    self._log_event(ip, "redis", "malformed_request", {}, port, session_id)
                    break
                if not parts:
                    break
                command = parts[0].upper()
                args = parts[1:]
                self._log_event(ip, "redis", "command",
                                  {"cmd": command, "argument_count": len(args)}, port, session_id)
                if command == "AUTH":
                    username = args[-2] if len(args) > 1 else "default"
                    self._log_event(ip, "redis", "auth_attempt", {"username": username[:128]}, port, session_id)
                    response = b"+OK\r\n"
                elif command == "PING":
                    response = b"+PONG\r\n"
                elif command == "INFO":
                    body = f"# Server\r\nredis_version:{cfg['banner']}\r\n".encode()
                    response = b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n"
                elif command in ("SET", "MSET", "DEL", "EXPIRE"):
                    response = b":1\r\n" if command in ("DEL", "EXPIRE") else b"+OK\r\n"
                elif command in ("GET", "HGET", "LRANGE", "SMEMBERS"):
                    response = b"$-1\r\n"
                elif command == "QUIT":
                    response = b"+OK\r\n"
                    writer.write(response)
                    await writer.drain()
                    break
                else:
                    response = b"-ERR unknown command\r\n"
                writer.write(response)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # --------------------------------------------------------------- SMTP --
    async def handle_smtp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("smtp")
        hostname = self.config["services"]["smtp"]["hostname"]
        self._log_event(ip, "smtp", "connection", {"port": port}, port, session_id)
        writer.write(f"220 {hostname} ESMTP ready\r\n".encode("ascii", errors="replace"))
        await writer.drain()
        auth_state = None
        in_data = False
        data_lines = 0
        data_size = 0
        try:
            while True:
                line = await self._readline(reader, timeout=20)
                if line is None:
                    break
                if len(line) > 2048:
                    self._log_event(ip, "smtp", "malformed_request", {"reason": "line_too_long"}, port, session_id)
                    break
                if auth_state == "username":
                    try:
                        username = base64.b64decode(line, validate=True).decode("utf-8", errors="replace")[:128]
                    except (binascii.Error, ValueError):
                        username = ""
                    self._log_event(ip, "smtp", "auth_username", {"username": username}, port, session_id)
                    auth_state = "password"
                    writer.write(b"334 UGFzc3dvcmQ6\r\n")
                elif auth_state == "password":
                    try:
                        base64.b64decode(line, validate=True)
                    except (binascii.Error, ValueError):
                        self._log_event(ip, "smtp", "malformed_request",
                                        {"reason": "invalid_auth_encoding"}, port, session_id)
                    self._log_event(ip, "smtp", "auth_attempt", {"username": "[SMTP AUTH]"}, port, session_id)
                    auth_state = None
                    writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")
                elif in_data and line == ".":
                    self._log_event(ip, "smtp", "message_attempt", {"line_count": data_lines, "byte_count": data_size}, port, session_id)
                    data_lines = data_size = 0
                    in_data = False
                    writer.write(b"250 2.0.0 Message accepted for inspection\r\n")
                elif in_data:
                    data_lines += 1
                    data_size += len(line)
                    if data_lines > 500 or data_size > 65536:
                        self._log_event(ip, "smtp", "malformed_request", {"reason": "message_limit"}, port, session_id)
                        break
                else:
                    parts = line.split(None, 1)
                    command = parts[0].upper() if parts else ""
                    argument = parts[1] if len(parts) > 1 else ""
                    self._log_event(ip, "smtp", "command", {"cmd": command}, port, session_id)
                    if command in ("EHLO", "HELO"):
                        writer.write(f"250-{hostname}\r\n250-AUTH LOGIN PLAIN\r\n250 SIZE 65536\r\n".encode())
                    elif command == "AUTH":
                        auth_parts = argument.split()
                        mechanism = auth_parts[0].upper() if auth_parts else ""
                        if mechanism == "PLAIN" and len(auth_parts) > 1:
                            try:
                                decoded = base64.b64decode(auth_parts[1], validate=True).decode("utf-8", errors="replace")
                                username = decoded.split("\x00")[-2][:128]
                            except (binascii.Error, ValueError, IndexError):
                                username = ""
                            self._log_event(ip, "smtp", "auth_attempt", {"username": username}, port, session_id)
                            writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")
                        elif mechanism == "LOGIN":
                            auth_state = "username"
                            writer.write(b"334 VXNlcm5hbWU6\r\n")
                        else:
                            writer.write(b"504 5.5.4 Unsupported authentication mechanism\r\n")
                    elif command == "DATA":
                        in_data = True
                        data_lines = 0
                        data_size = 0
                        writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    elif command == "QUIT":
                        writer.write(b"221 2.0.0 Bye\r\n")
                        await writer.drain()
                        break
                    elif command in ("MAIL", "RCPT", "RSET", "NOOP"):
                        writer.write(b"250 2.1.0 OK\r\n")
                    else:
                        writer.write(b"500 5.5.2 Command not recognized\r\n")
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def handle_docker(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        await self._handle_fake_http_api(reader, writer, "docker")

    async def handle_kubernetes(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        await self._handle_fake_http_api(reader, writer, "kubernetes")

    async def _handle_fake_http_api(self, reader, writer, service):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id(service)
        self._log_event(ip, service, "connection", {"port": port}, port, session_id)
        try:
            request_line = await self._readline(reader, timeout=5)
            if not request_line or len(request_line) > 2048:
                return
            try:
                method, path, _ = request_line.split(" ", 2)
            except ValueError:
                self._log_event(ip, service, "malformed_request", {}, port, session_id)
                return
            headers = {}
            for _ in range(self.config["max_request_headers"]):
                line = await self._readline(reader, timeout=5)
                if line is None or line == "":
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            else:
                self._log_event(ip, service, "malformed_request",
                                {"reason": "too_many_headers"}, port, session_id)
                return

            try:
                body_size = int(headers.get("content-length", "0"))
            except ValueError:
                body_size = -1
            if not 0 <= body_size <= self.config["max_sample_size"]:
                self._log_event(ip, service, "malformed_request",
                                {"reason": "invalid_or_oversized_body"}, port, session_id)
                return
            if body_size:
                try:
                    await asyncio.wait_for(reader.readexactly(body_size), timeout=5)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    self._log_event(ip, service, "malformed_request",
                                    {"reason": "incomplete_body"}, port, session_id)
                    return

            clean_path = path.split("?", 1)[0]
            detail = {"method": method, "path": clean_path}
            status, response_body = self._fake_api_response(service, method.upper(), clean_path)
            if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                detail["body_size"] = body_size
                detail["change_attempt"] = True
            self._log_event(ip, service, "command", detail, port, session_id)
            payload = json.dumps(response_body, separators=(",", ":")).encode("utf-8")
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload
            )
            await writer.drain()
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()

    def _fake_api_response(self, service: str, method: str, path: str):
        if service == "docker":
            version = self.config["services"]["docker"]["api_version"]
            if path == "/_ping":
                return "200 OK", {"message": "OK", "api_version": version}
            if path == "/version":
                return "200 OK", {
                    "Version": "24.0.7", "ApiVersion": version,
                    "MinAPIVersion": "1.12", "Os": "linux", "Arch": "amd64",
                }
            if re.fullmatch(r"/v[^/]+/containers/json", path) or path == "/containers/json":
                return "200 OK", [{
                    "Id": hashlib.sha256(b"web-prod-01").hexdigest()[:64],
                    "Names": ["/web-prod-01"], "Image": "nginx:1.24",
                    "State": "running", "Status": "Up 3 weeks",
                }]
            if path.endswith("/containers/create") and method == "POST":
                return "201 Created", {
                    "Id": hashlib.sha256(path.encode()).hexdigest()[:64],
                    "Warnings": ["Container creation simulated; execution disabled"],
                }
            if path.endswith("/images/json"):
                return "200 OK", [{"Id": "sha256:" + hashlib.sha256(b"nginx").hexdigest(),
                                   "RepoTags": ["nginx:1.24"]}]
            return "404 Not Found", {"message": "page not found"}

        version = self.config["services"]["kubernetes"]["version"]
        if path == "/version":
            return "200 OK", {"major": version[1:3], "minor": version[3:],
                              "gitVersion": version, "platform": "linux/amd64"}
        if path in ("/api", "/api/v1", "/apis"):
            return "200 OK", {"kind": "APIVersions", "versions": ["v1"],
                              "serverAddressByClientCIDRs": []}
        if path == "/api/v1/namespaces":
            return "200 OK", {
                "apiVersion": "v1", "kind": "NamespaceList",
                "items": [{"metadata": {"name": name}}
                          for name in ("default", "kube-system", "production")],
            }
        if path == "/api/v1/nodes":
            return "200 OK", {
                "apiVersion": "v1", "kind": "NodeList",
                "items": [{"metadata": {"name": self.sys.identity["hostname"]},
                           "status": {"nodeInfo": {"kubeletVersion": version,
                                                   "operatingSystem": "linux"}}}],
            }
        if path.endswith("/pods") or path == "/api/v1/pods":
            return "200 OK", {
                "apiVersion": "v1", "kind": "PodList",
                "items": [{"metadata": {"name": "web-7d9f4d8b7c-x2q4m",
                                        "namespace": "production"},
                           "status": {"phase": "Running"}}],
            }
        return "404 Not Found", {
            "apiVersion": "v1", "kind": "Status", "status": "Failure",
            "message": f"{path} not found", "reason": "NotFound", "code": 404,
        }

    async def handle_modbus(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("modbus")
        self._log_event(ip, "modbus", "connection", {"port": port}, port, session_id)
        registers = [self._rng.randint(0, 65535) for _ in range(256)]
        coils = [self._rng.randint(0, 1) for _ in range(256)]
        try:
            while True:
                header = await reader.readexactly(7)
                transaction_id = header[:2]
                protocol_id = header[2:4]
                length = int.from_bytes(header[4:6], "big")
                unit_id = header[6]
                if protocol_id != b"\x00\x00" or not 2 <= length <= 254:
                    self._log_event(ip, "modbus", "malformed_request", {}, port, session_id)
                    break
                pdu = await reader.readexactly(length - 1)
                function = pdu[0]
                self._log_event(ip, "modbus", "command", {
                    "function_code": function,
                    "unit_id": unit_id,
                    "request_size": len(pdu),
                }, port, session_id)
                response_pdu = bytes((function | 0x80, 0x01))
                if function in (1, 2, 3, 4) and len(pdu) == 5:
                    start = int.from_bytes(pdu[1:3], "big")
                    quantity = int.from_bytes(pdu[3:5], "big")
                    max_quantity = 2000 if function in (1, 2) else 125
                    table = coils if function in (1, 2) else registers
                    if 1 <= quantity <= max_quantity and start + quantity <= len(table):
                        if function in (1, 2):
                            packed = bytearray((quantity + 7) // 8)
                            for index, value in enumerate(table[start:start + quantity]):
                                packed[index // 8] |= (value & 1) << (index % 8)
                            data = bytes(packed)
                        else:
                            data = b"".join(
                                int(value).to_bytes(2, "big")
                                for value in table[start:start + quantity]
                            )
                        response_pdu = bytes((function, len(data))) + data
                elif function == 5 and len(pdu) == 5:
                    address = int.from_bytes(pdu[1:3], "big")
                    value = int.from_bytes(pdu[3:5], "big")
                    if address < len(coils) and value in (0x0000, 0xFF00):
                        coils[address] = int(value == 0xFF00)
                        response_pdu = pdu
                elif function == 6 and len(pdu) == 5:
                    address = int.from_bytes(pdu[1:3], "big")
                    if address < len(registers):
                        registers[address] = int.from_bytes(pdu[3:5], "big")
                        response_pdu = pdu
                response = (transaction_id + protocol_id
                            + (len(response_pdu) + 1).to_bytes(2, "big")
                            + bytes((unit_id,)) + response_pdu)
                writer.write(response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def handle_mqtt(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
        session_id = self._new_session_id("mqtt")
        self._log_event(ip, "mqtt", "connection", {"port": port}, port, session_id)
        try:
            while True:
                first = await reader.readexactly(1)
                multiplier = 1
                remaining = 0
                for _ in range(4):
                    byte = (await reader.readexactly(1))[0]
                    remaining += (byte & 0x7F) * multiplier
                    if not byte & 0x80:
                        break
                    multiplier *= 128
                else:
                    self._log_event(ip, "mqtt", "malformed_request",
                                    {"reason": "invalid_remaining_length"}, port, session_id)
                    break
                if remaining > 65536:
                    self._log_event(ip, "mqtt", "malformed_request",
                                    {"reason": "packet_too_large"}, port, session_id)
                    break
                packet = await reader.readexactly(remaining)
                packet_type = first[0] >> 4
                self._log_event(ip, "mqtt", "command", {
                    "packet_type": packet_type, "packet_size": remaining,
                }, port, session_id)
                if packet_type == 1:
                    username = ""
                    if len(packet) >= 10:
                        protocol_size = int.from_bytes(packet[:2], "big")
                        cursor = 2 + protocol_size + 4
                        if cursor + 2 <= len(packet):
                            client_len = int.from_bytes(packet[cursor:cursor + 2], "big")
                            cursor += 2 + client_len
                            flags = packet[protocol_size + 3] if protocol_size + 3 < len(packet) else 0
                            if flags & 0x04 and cursor + 2 <= len(packet):
                                will_len = int.from_bytes(packet[cursor:cursor + 2], "big")
                                cursor += 2 + will_len
                                if cursor + 2 <= len(packet):
                                    will_size = int.from_bytes(packet[cursor:cursor + 2], "big")
                                    cursor += 2 + will_size
                            if flags & 0x80 and cursor + 2 <= len(packet):
                                username_size = int.from_bytes(packet[cursor:cursor + 2], "big")
                                cursor += 2
                                username = packet[cursor:cursor + username_size].decode(
                                    "utf-8", errors="replace"
                                )[:128]
                    self._log_event(ip, "mqtt", "auth_attempt", {"username": username},
                                    port, session_id)
                    writer.write(b"\x20\x02\x00\x00")
                    await writer.drain()
                elif packet_type == 3:
                    if len(packet) >= 2:
                        topic_size = int.from_bytes(packet[:2], "big")
                        topic = packet[2:2 + topic_size].decode("utf-8", errors="replace")[:256]
                        self._log_event(ip, "mqtt", "publish", {
                            "topic": topic, "payload_size": max(0, len(packet) - topic_size - 2),
                        }, port, session_id)
                    qos = (first[0] >> 1) & 0x03
                    if qos == 1 and len(packet) >= 4:
                        writer.write(b"\x40\x02" + packet[2 + topic_size:4 + topic_size])
                elif packet_type == 8 and len(packet) >= 2:
                    packet_id = packet[:2]
                    topic_qos = []
                    cursor = 2
                    while cursor + 3 <= len(packet):
                        size = int.from_bytes(packet[cursor:cursor + 2], "big")
                        cursor += 2 + size
                        if cursor >= len(packet):
                            break
                        topic_qos.append(0)
                        cursor += 1
                    self._log_event(ip, "mqtt", "subscribe", {
                        "filter_count": len(topic_qos),
                    }, port, session_id)
                    writer.write(b"\x90" + bytes((2 + len(topic_qos),)) + packet_id + bytes(topic_qos))
                elif packet_type == 12:
                    writer.write(b"\xd0\x00")
                elif packet_type == 14:
                    break
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # ------------------------------------------------------------- shared --
    async def _fake_shell(self, reader, writer, ip, service, session_id):
        """A shell that accepts anything, logs it, and returns plausible fake output."""
        prompt = b"$ " if service == "ssh" else b"# "
        last_login = self.sys.users[1]["last_login"] if len(self.sys.users) > 1 else datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
        writer.write(b"\r\nLast login: " + last_login.encode() +
                     f" from {self.sys.network['interfaces'][0]['ipv4']}\r\n".encode() + prompt)
        await writer.drain()
        loop = asyncio.get_running_loop()
        end_time = loop.time() + self.config["max_session_seconds"]
        shell_state = {
            "cwd": "/root", "files": {}, "directories": set(), "deleted": set(),
            "mtimes": {},
        }
        behavior = []
        command_count = 0
        try:
            while loop.time() < end_time:
                cmd = await self._readline(reader, timeout=15)
                if cmd is None:
                    break
                command_count += 1
                if command_count > 500:
                    self._log_event(ip, service, "pollution_detected",
                                    {"reason": "session_command_limit"}, session_id=session_id)
                    break
                cmd = cmd[:4096]
                self._log_event(ip, service, "command", {"cmd": cmd}, session_id=session_id)
                escape_indicators = self._escape_indicators(cmd)
                if escape_indicators:
                    self._log_event(ip, service, "escape_attempt",
                                    {"indicators": escape_indicators}, session_id=session_id)
                if len(behavior) < 100:
                    category = self._command_category(cmd)
                    if not behavior or behavior[-1] != category:
                        behavior.append(category)
                output = self._fake_command_output(cmd, shell_state)
                if output is None:
                    output = await self._local_llm_output(cmd)
                await asyncio.sleep(self._rng.uniform(0.02, 0.12))
                writer.write(output + b"\r\n" + prompt)
                await writer.drain()
                if cmd.strip() in ("exit", "logout", "quit"):
                    break
        finally:
            if behavior:
                fingerprint = hashlib.sha256(">".join(behavior).encode()).hexdigest()[:20]
                self._log_event(ip, service, "behavior_cluster", {
                    "fingerprint": fingerprint,
                    "command_count": len(behavior),
                    "behavior": behavior[:20],
                }, session_id=session_id)
            shell_state.clear()

    @staticmethod
    def _escape_indicators(cmd: str) -> list:
        normalized = cmd.lower()
        indicators = (
            ("container-runtime-socket", r"/(?:var/run|run)/docker\.sock|containerd\.sock"),
            ("host-proc-root", r"/proc/(?:1|self)/root"),
            ("namespace-entry", r"\bnsenter\b|\bunshare\b"),
            ("privileged-container", r"--privileged\b"),
            ("mount-operation", r"\bmount\b.*(?:/dev/|/proc|/sys|/host)"),
        )
        return [label for label, pattern in indicators if re.search(pattern, normalized)]

    @staticmethod
    def _command_category(cmd: str) -> str:
        normalized = cmd.lower()
        categories = (
            ("credential-access", r"(shadow|authorized_keys|\.aws|\.kube|password|credential)"),
            ("network-recon", r"\b(ip|ifconfig|netstat|ss|ping|nslookup|dig|route)\b"),
            ("transfer", r"\b(curl|wget|tftp|scp|ftp|nc|ncat)\b"),
            ("persistence", r"(crontab|systemctl|rc\.local|authorized_keys|\.bashrc)"),
            ("execution", r"\b(sh|bash|python\d*|perl|php|chmod|chown|nohup)\b"),
            ("file-access", r"\b(cat|less|more|head|tail|find|grep|ls|stat)\b"),
            ("discovery", r"\b(whoami|id|uname|hostname|pwd|ps|uptime|w|last)\b"),
        )
        for category, pattern in categories:
            if re.search(pattern, normalized):
                return category
        return "other"

    async def _local_llm_output(self, cmd: str) -> bytes:
        if self.config.get("llm_enabled"):
            identity = self.sys.identity
            description = (
                f"{identity['distro_name']} {identity['distro_version']}; "
                f"hostname {identity['fqdn']}; kernel {identity['kernel_version']}"
            )
            response = await generate_shell_output(
                self.config["llm_endpoint"], self.config["llm_model"], cmd, description
            )
            if response:
                safe = "".join(
                    char for char in response
                    if char in "\n\t" or (char.isprintable() and char != "\r")
                )
                return safe.encode("utf-8", errors="replace")
        command = cmd.split()[0] if cmd.split() else cmd
        return f"bash: {command}: command not found".encode("utf-8", errors="replace")

    def _fake_command_output(self, cmd: str, state: dict = None) -> Optional[bytes]:
        """Generate realistic command output using system state."""
        cmd = cmd.strip().lower()
        state = state if state is not None else {
            "cwd": "/root", "files": {}, "directories": set(), "deleted": set(),
            "mtimes": {},
        }
        cwd = state["cwd"]

        def resolve(path):
            return posixpath.normpath(path if path.startswith("/") else posixpath.join(cwd, path))

        if cmd in ("exit", "logout", "quit", "clear"):
            return b""
        if cmd.startswith("cd"):
            parts = cmd.split(maxsplit=1)
            destination = resolve(parts[1]) if len(parts) > 1 else "/root"
            if destination in self.sys.filesystem["directories"] or destination in state["directories"]:
                state["cwd"] = destination
                return b""
            return f"bash: cd: {destination}: No such file or directory".encode()
        if cmd.startswith("touch "):
            for item in cmd.split()[1:]:
                path = resolve(item)
                state["deleted"].discard(path)
                state["files"].setdefault(path, "")
                state["mtimes"][path] = time.time()
            return b""
        if cmd.startswith("mkdir "):
            for item in cmd.split()[1:]:
                state["directories"].add(resolve(item))
            return b""
        if cmd.startswith("rm "):
            for item in cmd.split()[1:]:
                if not item.startswith("-"):
                    path = resolve(item)
                    state["deleted"].add(path)
                    state["files"].pop(path, None)
                    state["directories"].discard(path)
            return b""
        if cmd.startswith("stat "):
            path = resolve(cmd.split(maxsplit=1)[1])
            mtime = state["mtimes"].get(path)
            timestamp = (
                datetime.fromtimestamp(mtime, timezone.utc)
                if mtime is not None else self.sys.file_timestamp(path)
            ).strftime("%Y-%m-%d %H:%M:%S.%f %z")
            return (
                f"  File: {path}\n  Size: 4096       Blocks: 8          IO Block: 4096   directory\n"
                f"Modify: {timestamp}\nChange: {timestamp}\n Birth: {timestamp}"
            ).encode()
        if cmd.startswith("ls"):
            parts = cmd.split()
            target = resolve(next((part for part in parts[1:] if not part.startswith("-")), "."))
            entries = list(self.sys.filesystem["directories"].get(target, []))
            entries.extend(
                posixpath.basename(path) for path in self.sys.filesystem["key_files"]
                if posixpath.dirname(path) == target and path not in state["deleted"]
            )
            entries.extend(
                posixpath.basename(path) for path in state["files"]
                if posixpath.dirname(path) == target and path not in state["deleted"]
            )
            if "-l" in parts or "-la" in parts or "-al" in parts:
                lines = [f"total {len(entries)}"]
                for entry in sorted(set(entries)):
                    path = posixpath.join(target, entry)
                    mtime = state["mtimes"].get(path)
                    stamp = (
                        datetime.fromtimestamp(mtime, timezone.utc)
                        if mtime is not None else self.sys.file_timestamp(path)
                    ).strftime("%b %d %H:%M")
                    lines.append(f"-rw-r--r-- 1 root root 4096 {stamp} {entry}")
                return "\n".join(lines).encode()
            return "  ".join(sorted(set(entries))).encode()
        if cmd.startswith("cat "):
            path = resolve(cmd.split(maxsplit=1)[1])
            if path in state["deleted"]:
                return f"cat: {path}: No such file or directory".encode()
            content = state["files"].get(path, self.sys.filesystem["key_files"].get(path))
            if content is not None:
                return content.encode() if isinstance(content, str) else content
        if cmd.startswith("echo ") and ">" in cmd:
            content, path = cmd[5:].split(">", 1)
            path = resolve(path.strip().lstrip(">"))
            state["files"][path] = content.strip().strip("'\"")
            state["deleted"].discard(path)
            state["mtimes"][path] = time.time()
            return b""
        if cmd.startswith("wget ") or cmd.startswith("curl "):
            parts = cmd.split()
            output_path = None
            if "-o" in parts:
                index = parts.index("-o")
                if index + 1 < len(parts):
                    output_path = parts[index + 1]
            if output_path:
                path = resolve(output_path)
                state["files"][path] = ""
                state["mtimes"][path] = time.time()
                return b""
        if cmd == "date":
            return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y").encode()
        if cmd == "ip a" or cmd == "ip addr":
            return "\n".join(
                f"{index}: {iface['name']}: <{','.join(iface['flags'])}> mtu {iface['mtu']}\n"
                f"    link/ether {iface['mac']}\n    inet {iface['ipv4']}/24"
                for index, iface in enumerate(self.sys.network["interfaces"], 1)
            ).encode()
        if cmd == "ip route":
            gateway = self.sys.network["interfaces"][0]["gateway"]
            return f"default via {gateway} dev eth0".encode()
        if cmd == "df":
            return self._fake_command_output("df -h", state)
        if cmd == "cat /proc/uptime":
            uptime = self.sys.uptime_seconds()
            return f"{uptime:.2f} {uptime * self.sys.identity['cpu_cores'] * 0.8:.2f}".encode()
        if cmd == "cat /etc/hostname":
            return (self.sys.identity["hostname"] + "\n").encode()
        if cmd == "cat /root/.aws/credentials":
            return self.sys.filesystem["key_files"]["/root/.aws/credentials"].encode()
        if cmd == "cat /home/admin/.kube/config":
            return self.sys.filesystem["key_files"]["/home/admin/.kube/config"].encode()
        
        # Use system state for realistic responses
        if cmd == "whoami":
            return b"root"
        elif cmd == "id":
            return b"uid=0(root) gid=0(root) groups=0(root)"
        elif cmd == "uname -a":
            return f"Linux {self.sys.identity['hostname']} {self.sys.identity['kernel_version']} #1 SMP x86_64 GNU/Linux".encode()
        elif cmd == "hostname":
            return self.sys.identity["fqdn"].encode()
        elif cmd == "uptime":
            load = self.sys.get_load_average()
            return f" {datetime.now().strftime('%H:%M:%S')} up {self.sys.uptime_string()},  1 user,  load average: {load[0]}, {load[1]}, {load[2]}".encode()
        elif cmd == "pwd":
            return state["cwd"].encode()
        elif cmd == "ls":
            return b"backup.tar.gz  config.yml  scripts  snap"
        elif cmd == "ls -la":
            return b"total 24\ndrwxr-xr-x  3 root root 4096 Jan 15 10:00 .\ndrwxr-xr-x 18 root root 4096 Jan 15 09:55 ..\n-rw-r--r--  1 root root 1024 Jan 10 08:00 backup.tar.gz\n-rw-r--r--  1 root root  512 Jan 12 14:30 config.yml\ndrwxr-xr-x  2 root root 4096 Jan 14 16:20 scripts\n-rw-r--r--  1 root root  2048 Jan 15 09:55 .bash_history"
        elif cmd == "ps aux":
            lines = ["USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
            for p in self.sys.get_processes()[:15]:
                lines.append(f"{p['user']:<10} {p['pid']:<6} {p['cpu']:<4} {p['mem']:<4}  123456  7890 ?        Ss   {p['start']}   0:00 {p['cmd']}")
            return "\n".join(lines).encode()
        elif cmd.startswith("ps"):
            lines = ["  PID TTY          TIME CMD"]
            for p in self.sys.get_processes()[:10]:
                lines.append(f"{p['pid']:>5} ?        00:00:00 {p['cmd'][:30]}")
            return "\n".join(lines).encode()
        elif cmd == "top -b -n 1":
            load = self.sys.get_load_average()
            mem = self.sys.get_memory_info()
            lines = [
                f"top - {datetime.now().strftime('%H:%M:%S')} up {self.sys.uptime_string()},  1 user,  load average: {load[0]}, {load[1]}, {load[2]}",
                f"Tasks: {len(self.sys.processes)} total,   1 running, {len(self.sys.processes)-1} sleeping,   0 stopped,   0 zombie",
                f"%Cpu(s):  5.2 us,  1.3 sy,  0.0 ni, 92.5 id,  0.0 wa,  0.0 hi,  1.0 si,  0.0 st",
                f"MiB Mem :  {mem['total']//1024} total,   {mem['free']//1024} free,   {mem['used']//1024} used,   {mem['cached']//1024} buff/cache",
                f"MiB Swap:   2048 total,   2048 free,      0 used.  {mem['available']//1024} avail Mem",
                "",
                "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
            ]
            for p in self.sys.get_processes()[:10]:
                lines.append(f"   {p['pid']:>5} {p['user']:<8}  20   0  123456  78900  1234 S  {p['cpu']:<4} {p['mem']:<4}   0:00.00 {p['cmd'][:20]}")
            return "\n".join(lines).encode()
        elif cmd == "df -h":
            lines = ["Filesystem      Size  Used Avail Use% Mounted on"]
            for mount in self.sys.filesystem["mounts"]:
                if mount["size_gb"] > 0:
                    used_pct = int((mount["used_gb"] / mount["size_gb"]) * 100)
                    lines.append(f"/dev/sda1       {mount['size_gb']}G  {mount['used_gb']}G  {mount['size_gb']-mount['used_gb']}G  {used_pct}% {mount['mount']}")
            lines.append("tmpfs           2.0G     0  2.0G   0% /run")
            lines.append("tmpfs           4.0G     0  4.0G   0% /tmp")
            return "\n".join(lines).encode()
        elif cmd == "free -h":
            mem = self.sys.get_memory_info()
            return f"              total        used        free      shared  buff/cache   available\nMem:           {mem['total']//1024//1024}Gi       {mem['used']//1024//1024}Gi       {mem['free']//1024//1024}Gi       123Mi       {mem['cached']//1024//1024}Gi       {mem['available']//1024//1024}Gi\nSwap:          2.0Gi          0B       2.0Gi".encode()
        elif cmd == "netstat -tulpn" or cmd == "ss -tulpn":
            lines = ["Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"]
            for iface in self.sys.network["interfaces"]:
                if iface["ipv4"] != "127.0.0.1":
                    lines.append(f"tcp        0      0 {iface['ipv4']}:22           0.0.0.0:*               LISTEN      500/sshd")
                    lines.append(f"tcp        0      0 {iface['ipv4']}:80           0.0.0.0:*               LISTEN      504/nginx")
                    lines.append(f"tcp        0      0 {iface['ipv4']}:443          0.0.0.0:*               LISTEN      504/nginx")
            lines.append("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      603/postgres")
            lines.append("tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      602/redis")
            return "\n".join(lines).encode()
        elif cmd == "ifconfig" or cmd == "ip a":
            lines = []
            for iface in self.sys.network["interfaces"]:
                rx_packets, rx_bytes, tx_packets, tx_bytes = self.sys.get_interface_counters(
                    iface["name"]
                )
                lines.append(f"{iface['name']}: flags={','.join(iface['flags'])}  mtu {iface['mtu']}")
                lines.append(f"        inet {iface['ipv4']}  netmask {iface['netmask']}  broadcast {iface['ipv4'].rsplit('.', 1)[0]}.255")
                lines.append(f"        ether {iface['mac']}  txqueuelen 1000  (Ethernet)")
                lines.append(f"        RX packets {rx_packets}  bytes {rx_bytes}")
                lines.append(f"        TX packets {tx_packets}  bytes {tx_bytes}")
                lines.append("")
            return "\n".join(lines).encode()
        elif cmd == "cat /etc/os-release":
            return f'NAME="{self.sys.identity["distro_name"]}"\nVERSION="{self.sys.identity["distro_version"]}"\nID={self.sys.identity["distro_name"].lower()}\nVERSION_ID="{self.sys.identity["distro_version"].split()[0]}"\nPRETTY_NAME="{self.sys.identity["distro_name"]} {self.sys.identity["distro_version"]}"\n'.encode()
        elif cmd == "cat /etc/passwd":
            lines = []
            for user in self.sys.users:
                lines.append(f"{user['username']}:x:{user['uid']}:{user['gid']}:{user['username']}:{user['home']}:{user['shell']}")
            return "\n".join(lines).encode()
        elif cmd == "cat /proc/cpuinfo":
            return f"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 79\nmodel name\t: {self.sys.identity['cpu_model']}\nstepping\t: 1\ncpu MHz\t\t: 2400.000\ncache size\t: 25600 KB\ncpu cores\t: {self.sys.identity['cpu_cores']}\n".encode()
        elif cmd == "cat /proc/meminfo":
            mem = self.sys.get_memory_info()
            return f"MemTotal:       {mem['total']} kB\nMemFree:        {mem['free']} kB\nMemAvailable:   {mem['available']} kB\nBuffers:        {mem['buffers']} kB\nCached:         {mem['cached']} kB\nSwapCached:            0 kB\nActive:         {mem['used']//2} kB\nInactive:       {mem['cached']//2} kB\n".encode()
        elif cmd == "lsblk":
            lines = ["NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT"]
            for mount in self.sys.filesystem["mounts"]:
                if mount["device"].startswith("/dev/"):
                    lines.append(f"{mount['device'].replace('/dev/', '')}    8:0    0  {mount['size_gb']}G  0 disk {mount['mount']}")
            return "\n".join(lines).encode()
        elif cmd == "systemctl list-units --type=service --state=running":
            lines = ["UNIT                         LOAD   ACTIVE SUB     DESCRIPTION"]
            services = ["systemd-journald.service", "systemd-udevd.service", "ssh.service", "cron.service", "docker.service", "containerd.service", "nginx.service"]
            for svc in services:
                lines.append(f"{svc:<30} loaded active running {svc.replace('.service', '').capitalize()}")
            lines.append("")
            lines.append(f"LOAD   = Reflects whether the unit definition was properly loaded.")
            lines.append(f"ACTIVE = The high-level unit activation state")
            lines.append(f"SUB    = The low-level unit activation state")
            return "\n".join(lines).encode()
        elif cmd.startswith("cat "):
            filepath = cmd[4:].strip()
            if filepath in self.sys.filesystem["key_files"]:
                return self.sys.filesystem["key_files"][filepath].encode()
            # Try to find in directories
            for dir_path, files in self.sys.filesystem["directories"].items():
                if any(filepath == posixpath.join(dir_path, name) for name in files):
                    return f"# Contents of {filepath}\n# [simulated file content]".encode()
            return b"cat: " + filepath.encode() + b": No such file or directory"
        elif cmd.startswith(("wget ", "curl ")):
            return b""
        elif cmd.startswith(("chmod ", "rm ", "mkdir ", "touch ")):
            return b""
        elif cmd == "":
            return b""
        else:
            return None

    @staticmethod
    async def _readline(reader: asyncio.StreamReader, timeout=20, echo_hidden=False) -> str:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except (asyncio.TimeoutError, ConnectionResetError, ValueError):
            return None
        if not raw:
            return None
        try:
            return raw.decode(errors="ignore").strip("\r\n")
        except Exception:
            return ""

    # ------------------------------------------------------------- runner --
    async def start(self):
        servers = []
        handlers = {
            "ssh": self.handle_ssh,
            "telnet": self.handle_telnet,
            "ftp": self.handle_ftp,
            "http": self.handle_http,
            "mysql": self.handle_mysql,
            "redis": self.handle_redis,
            "smtp": self.handle_smtp,
            "docker": self.handle_docker,
            "kubernetes": self.handle_kubernetes,
            "modbus": self.handle_modbus,
            "mqtt": self.handle_mqtt,
        }
        for name, handler in handlers.items():
            cfg = self.config["services"].get(name, {})
            if not cfg.get("enabled"):
                continue
            async def dispatch(reader, writer, service_handler=handler, service_name=name):
                peer = writer.get_extra_info("peername")
                source_ip = peer[0] if peer else "unknown"
                if not self._begin_connection(source_ip, service_name):
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass
                    return
                try:
                    await asyncio.wait_for(
                        service_handler(reader, writer),
                        timeout=self.config["max_session_seconds"],
                    )
                finally:
                    self._end_connection()
                    if not writer.is_closing():
                        writer.close()
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass

            try:
                if name == "ssh" and cfg.get("real_ssh", False):
                    server = await self._start_ssh_server(cfg)
                    addr = ", ".join(str(address) for address in server.get_addresses())
                else:
                    server = await asyncio.start_server(
                        dispatch, self.config["bind_host"], cfg["port"], limit=8192
                    )
                    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
                log.info("%s honeypot listening on %s", name.upper(), addr)
                servers.append(server)
            except OSError as e:
                log.warning("Failed to start %s honeypot on port %d: %s", name.upper(), cfg['port'], e)
                continue

        if not servers:
            log.warning("No services enabled. Check your config.")
            self.ti.close()
            return

        loop = asyncio.get_running_loop()
        self._servers = servers
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda s=sig: self._signal_handler(s))
            except NotImplementedError:
                pass  # Windows doesn't support add_signal_handler

        try:
            await asyncio.gather(*(server.wait_closed() for server in servers))
        except asyncio.CancelledError:
            pass
        finally:
            for server in servers:
                server.close()
            await asyncio.gather(*(server.wait_closed() for server in servers))
            self.ti.close()


def load_config(path: str) -> dict:
    if not path:
        return copy.deepcopy(DEFAULT_CONFIG)
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"Config file not found: {path}")
    if p.suffix in (".yaml", ".yml"):
        import yaml
        with open(p) as f:
            user_cfg = yaml.safe_load(f)
    else:
        with open(p) as f:
            user_cfg = json.load(f)
    if not isinstance(user_cfg, dict):
        raise ValueError("Config must contain a mapping/object at its top level")
    allowed_keys = {
        "bind_host", "max_connections", "max_request_headers",
        "rate_limit_connections", "rate_limit_window_seconds", "max_rate_limit_sources",
        "geoip_db_path", "alert_webhook", "alert_event_types", "auto_block_score",
        "max_session_seconds", "fake_login_fail_count", "system_seed",
        "enable_mitre_tagging", "anti_pollution", "pollution_threshold",
        "randomize_banners",
        "sandbox_submit_url", "sandbox_auth_token_env", "llm_enabled",
        "llm_endpoint", "llm_model", "max_sample_size",
        "services",
    }
    unknown_keys = set(user_cfg) - allowed_keys
    if unknown_keys:
        raise ValueError(f"Unknown config key(s): {', '.join(sorted(unknown_keys))}")

    merged = copy.deepcopy(DEFAULT_CONFIG)
    merged.update(user_cfg)
    supplied_services = user_cfg.get("services") or {}
    if not isinstance(supplied_services, dict):
        raise ValueError("services must be a mapping/object")
    unknown_services = set(supplied_services) - set(DEFAULT_CONFIG["services"])
    if unknown_services:
        raise ValueError(f"Unknown service(s): {', '.join(sorted(unknown_services))}")
    service_options = {
        "ssh": {"enabled", "port", "banner", "real_ssh", "credential_retention", "host_key_path"},
        "telnet": {"enabled", "port", "banner"},
        "ftp": {"enabled", "port", "banner"},
        "http": {"enabled", "port", "server_header"},
        "mysql": {"enabled", "port", "banner"},
        "redis": {"enabled", "port", "banner"},
        "smtp": {"enabled", "port", "hostname"},
        "docker": {"enabled", "port", "api_version"},
        "kubernetes": {"enabled", "port", "version"},
        "modbus": {"enabled", "port", "unit_id"},
        "mqtt": {"enabled", "port", "broker_name"},
    }
    for name, supplied in supplied_services.items():
        if not isinstance(supplied, dict):
            raise ValueError(f"services.{name} must be a mapping/object")
        unknown_options = set(supplied) - service_options[name]
        if unknown_options:
            raise ValueError(f"Unknown services.{name} option(s): {', '.join(sorted(unknown_options))}")
    merged["services"] = {
        name: {**defaults, **supplied_services.get(name, {})}
        for name, defaults in DEFAULT_CONFIG["services"].items()
    }
    for k, v in user_cfg.items():
        if k != "services":
            merged[k] = v

    if not isinstance(merged["bind_host"], str) or not merged["bind_host"].strip():
        raise ValueError("bind_host must be a non-empty IP address or hostname")
    _validate_integer(merged, "max_connections", 1, 10000)
    _validate_integer(merged, "max_request_headers", 1, 1000)
    _validate_integer(merged, "rate_limit_connections", 1, 100000)
    _validate_integer(merged, "rate_limit_window_seconds", 1, 86400)
    _validate_integer(merged, "max_rate_limit_sources", 100, 1000000)
    _validate_integer(merged, "fake_login_fail_count", 0, 100)
    _validate_integer(merged, "auto_block_score", 0, 1000000)
    _validate_integer(merged, "pollution_threshold", 1, 1000000)
    _validate_integer(merged, "max_sample_size", 1, MAX_SAMPLE_SIZE)
    if merged["geoip_db_path"] is not None and not isinstance(merged["geoip_db_path"], str):
        raise ValueError("geoip_db_path must be a path string or null")
    if merged["alert_webhook"] is not None and (
            not isinstance(merged["alert_webhook"], str)
            or not merged["alert_webhook"].startswith(("https://", "http://"))):
        raise ValueError("alert_webhook must be an http(s) URL or null")
    if (not isinstance(merged["alert_event_types"], list)
            or any(not isinstance(item, str) for item in merged["alert_event_types"])):
        raise ValueError("alert_event_types must be a list of strings")
    for key in ("enable_mitre_tagging", "anti_pollution", "llm_enabled", "randomize_banners"):
        if not isinstance(merged[key], bool):
            raise ValueError(f"{key} must be true or false")
    if merged["system_seed"] is not None and not isinstance(merged["system_seed"], str):
        raise ValueError("system_seed must be a string or null")
    if merged["sandbox_submit_url"] is not None:
        if not isinstance(merged["sandbox_submit_url"], str):
            raise ValueError("sandbox_submit_url must be a string or null")
        validate_sandbox_url(merged["sandbox_submit_url"])
    token_env = merged["sandbox_auth_token_env"]
    if token_env is not None and (
            not isinstance(token_env, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env) is None):
        raise ValueError("sandbox_auth_token_env must be a valid environment variable name")
    if not isinstance(merged["llm_endpoint"], str) or not merged["llm_endpoint"]:
        raise ValueError("llm_endpoint must be a non-empty URL")
    if not isinstance(merged["llm_model"], str) or not merged["llm_model"].strip():
        raise ValueError("llm_model must be a non-empty string")
    if merged["llm_enabled"]:
        validate_local_llm_url(merged["llm_endpoint"])
    if (not isinstance(merged["max_session_seconds"], (int, float))
            or isinstance(merged["max_session_seconds"], bool)
            or not 1 <= merged["max_session_seconds"] <= 86400):
        raise ValueError("max_session_seconds must be between 1 and 86400")

    ports = set()
    for name, service in merged["services"].items():
        if not isinstance(service["enabled"], bool):
            raise ValueError(f"services.{name}.enabled must be true or false")
        _validate_integer(service, "port", 1, 65535, f"services.{name}")
        if service["enabled"] and service["port"] in ports:
            raise ValueError(f"Enabled services must use unique ports (duplicate {service['port']})")
        if service["enabled"]:
            ports.add(service["port"])
        for key in ("banner", "server_header"):
            if key in service and service[key] is not None and not isinstance(service[key], str):
                raise ValueError(f"services.{name}.{key} must be a string or null")
        if "server_header" in service and service["server_header"] is not None and any(char in service["server_header"] for char in "\r\n"):
            raise ValueError("services.http.server_header must not contain line breaks")
        if "hostname" in service and service["hostname"] is not None and (not isinstance(service["hostname"], str)
                                       or any(char in service["hostname"] for char in "\r\n")):
            raise ValueError("services.smtp.hostname must be a string or null without line breaks")
        for key in ("api_version", "version", "broker_name"):
            if key in service and service[key] is not None and (
                    not isinstance(service[key], str)
                    or any(char in service[key] for char in "\r\n")):
                raise ValueError(f"services.{name}.{key} must be a string or null without line breaks")
        if name == "modbus":
            _validate_integer(service, "unit_id", 0, 255, f"services.{name}")
        if name == "ssh":
            banner = service["banner"]
            if (not isinstance(banner, str) or not banner
                    or any(ord(char) < 32 or ord(char) > 126 for char in banner)):
                raise ValueError("services.ssh.banner must be non-empty printable ASCII without line breaks")
            if "real_ssh" in service and not isinstance(service["real_ssh"], bool):
                raise ValueError("services.ssh.real_ssh must be true or false")
            if "credential_retention" in service:
                cr = service["credential_retention"]
                if cr not in ("off", "hashed"):
                    raise ValueError("services.ssh.credential_retention must be 'off' or 'hashed'")
            if "host_key_path" in service and service["host_key_path"] is not None:
                if not isinstance(service["host_key_path"], str):
                    raise ValueError("services.ssh.host_key_path must be a path string or null")
    return merged


def _validate_integer(config: dict, key: str, minimum: int, maximum: int, prefix: str = ""):
    value = config.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")


def main():
    parser = argparse.ArgumentParser(description="Custom honeypot with threat intelligence logging")
    parser.add_argument("--config", default=None, help="Path to YAML/JSON config file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    try:
        asyncio.run(Honeypot(load_config(args.config)).start())
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        log.info("Shutting down honeypot.")


if __name__ == "__main__":
    main()
