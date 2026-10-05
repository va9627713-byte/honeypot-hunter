import asyncio
import base64
import json
import random
import signal
import socket
import sqlite3
import tempfile
import unittest
import urllib.request
from collections import defaultdict, deque
from contextlib import closing, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import asyncssh
import yaml

from artifact_analysis import _NoRedirectHandler as SandboxNoRedirectHandler
from artifact_analysis import analyze_sample, submit_to_sandbox
from check_ports import check_port
from dashboard import handle_client, load_summary
from honeypot import DEFAULT_CONFIG, Honeypot, load_config
from local_llm import _NoRedirectHandler as LlmNoRedirectHandler
from local_llm import classify_attack_event, generate_shell_output, validate_local_llm_url
from report import _safe_terminal_text, print_report
from simulate_attacks import PROBES
from simulate_attacks import run as run_simulator
from system_state import reset_system_state
from ti_logger import ALERT_EVENT_TYPES, EVENT_WEIGHTS, ThreatIntelLogger, analyze_risk


class LoggerHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.db_path = root / "events.db"
        self.jsonl_path = root / "events.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_password_is_redacted_and_reports_count_by_username(self):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path)
        logger.log_event("192.0.2.5", "ssh", "auth_attempt",
                         {"username": "admin", "password": "secret-value"})

        serialized = self.jsonl_path.read_text(encoding="utf-8")
        record = json.loads(serialized)
        self.assertNotIn("secret-value", serialized)
        self.assertEqual(record["detail"]["password"], "[REDACTED]")
        self.assertEqual(logger.top_credentials(), [("admin", 1)])

    def test_hash_chain_resumes_and_detects_modification(self):
        ThreatIntelLogger(self.db_path, self.jsonl_path).log_event(
            "192.0.2.5", "ssh", "connection")
        resumed = ThreatIntelLogger(self.db_path, self.jsonl_path)
        resumed.log_event("192.0.2.5", "ssh", "connection")
        self.assertEqual(len(self.jsonl_path.read_text(encoding="utf-8").splitlines()), 2)

        content = self.jsonl_path.read_text(encoding="utf-8")
        self.jsonl_path.write_text(content.replace("connection", "tampered", 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "verification failed"):
            ThreatIntelLogger(self.db_path, self.jsonl_path)

    def test_legacy_database_passwords_are_scrubbed(self):
        ThreatIntelLogger(self.db_path, self.jsonl_path)
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute(
                "INSERT INTO credentials_seen (src_ip, service, username, password, ts) "
                "VALUES (?, ?, ?, ?, ?)",
                ("192.0.2.5", "ssh", "admin", "legacy-secret", "2026-01-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO events (ts, src_ip, service, event_type, detail, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("2026-01-01T00:00:00+00:00", "192.0.2.5", "ssh", "auth_attempt",
                 json.dumps({"username": "admin", "password": "legacy-secret"}), "old-hash"),
            )
            connection.commit()

        ThreatIntelLogger(self.db_path, self.jsonl_path)
        with closing(sqlite3.connect(self.db_path)) as connection:
            password = connection.execute("SELECT password FROM credentials_seen").fetchone()[0]
            detail, record_hash = connection.execute(
                "SELECT detail, hash FROM events WHERE event_type='auth_attempt'"
            ).fetchone()
        self.assertEqual(password, "[REDACTED]")
        self.assertNotIn("legacy-secret", detail)
        self.assertIsNone(record_hash)

    def test_geoip_enrichment_is_persisted(self):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path)
        country = SimpleNamespace(iso_code="US", name="United States")
        city = SimpleNamespace(name="Mountain View")
        location = SimpleNamespace(latitude=37.386, longitude=-122.0838)
        logger._geoip_reader = Mock()
        logger._geoip_reader.city.return_value = SimpleNamespace(
            country=country, city=city, location=location)

        event = logger.log_event("8.8.8.8", "http", "connection")

        self.assertEqual(event["geo"]["country_code"], "US")
        with closing(sqlite3.connect(self.db_path)) as connection:
            row = connection.execute("SELECT country_code, city, latitude FROM events").fetchone()
        self.assertEqual(row, ("US", "Mountain View", 37.386))

    def test_old_event_schema_migrates_geo_columns(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("""
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
                    src_ip TEXT NOT NULL, src_port INTEGER, service TEXT NOT NULL,
                    event_type TEXT NOT NULL, detail TEXT, session_id TEXT, hash TEXT
                )
            """)
            connection.commit()
        ThreatIntelLogger(self.db_path, self.jsonl_path)
        with closing(sqlite3.connect(self.db_path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
        self.assertTrue({"country_code", "country_name", "city", "latitude", "longitude"} <= columns)

    def test_local_blocklist_activates_at_configured_score(self):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path, auto_block_score=3)
        logger.log_event("192.0.2.5", "ssh", "auth_attempt", {"username": "admin"})
        self.assertTrue(logger.is_blocked("192.0.2.5"))
        self.assertEqual(logger.blocked_sources()[0][0], "192.0.2.5")

    def test_ioc_export_excludes_non_global_sources_by_default(self):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path)
        logger.log_event("127.0.0.1", "ssh", "auth_attempt", {"username": "sim-user"})
        logger.log_event("8.8.8.8", "ssh", "auth_attempt", {"username": "admin"})

        self.assertEqual([item["ip"] for item in logger.export_ioc_feed(min_score=0)],
                         ["8.8.8.8"])
        self.assertEqual(
            {item["ip"] for item in logger.export_ioc_feed(min_score=0, include_non_global=True)},
            {"127.0.0.1", "8.8.8.8"},
        )
        self.assertEqual(logger.export_ioc_feed(min_score=0)[0]["risk_level"], "low")

    def test_risk_analyzer_explains_weighted_signals_and_severity(self):
        assessment = analyze_risk({
            "auth_attempt": 2,
            "http_exploit_attempt": 1,
            "connection": 1,
        })

        self.assertEqual(assessment["score"], 14)
        self.assertEqual(assessment["level"], "guarded")
        self.assertEqual(assessment["signals"][0]["event_type"], "http_exploit_attempt")
        self.assertEqual(assessment["signals"][0]["points"], 7)
        self.assertIn("not proof", assessment["caveat"])

    def test_risk_analyzer_bands_and_rejects_invalid_counts(self):
        self.assertEqual(analyze_risk({})["level"], "low")
        self.assertEqual(analyze_risk({"payload_upload": 7})["level"], "high")
        self.assertEqual(analyze_risk({"payload_upload": 13})["level"], "critical")
        with self.assertRaisesRegex(ValueError, "non-negative integers"):
            analyze_risk({"auth_attempt": -1})

    @patch("ti_logger.urllib.request.urlopen")
    def test_eligible_events_are_sent_to_background_alert_worker(self, urlopen):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path,
                                   alert_webhook="https://alerts.example.invalid")
        try:
            logger.log_event("192.0.2.5", "http", "http_exploit_attempt",
                             {"path": "/.env"})
            logger._alert_queue.join()
            urlopen.assert_called_once()
        finally:
            logger.close()

    @patch("ti_logger.urllib.request.urlopen")
    def test_empty_alert_event_list_disables_alerts(self, urlopen):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path,
                                   alert_webhook="https://alerts.example.invalid",
                                   alert_event_types=[])
        try:
            logger.log_event("192.0.2.5", "http", "http_exploit_attempt")
            self.assertEqual(logger._alert_queue.qsize(), 0)
            urlopen.assert_not_called()
        finally:
            logger.close()

    @patch("ti_logger.urllib.request.urlopen")
    def test_slack_webhook_receives_safe_summary(self, urlopen):
        logger = ThreatIntelLogger(
            self.db_path, self.jsonl_path,
            alert_webhook="https://hooks.slack.com/services/test",
        )
        try:
            logger.log_event("192.0.2.5", "http", "http_exploit_attempt",
                             {"path": "/.env"})
            logger._alert_queue.join()
            request = urlopen.call_args.args[0]
            payload = json.loads(request.data)
            self.assertIn("http_exploit_attempt", payload["text"])
            self.assertNotIn("/.env", payload["text"])
        finally:
            logger.close()

    def test_behavior_fingerprints_cluster_across_sources(self):
        logger = ThreatIntelLogger(self.db_path, self.jsonl_path)
        logger.log_event("192.0.2.5", "ssh", "behavior_cluster", {
            "fingerprint": "a" * 20, "behavior": ["discovery", "file-access"],
        })
        logger.log_event("192.0.2.6", "telnet", "behavior_cluster", {
            "fingerprint": "a" * 20, "behavior": ["discovery", "file-access"],
        })

        cluster = logger.top_behavior_clusters()[0]
        self.assertEqual((cluster[0], cluster[2], cluster[3]), ("a" * 20, 2, 2))
        logger.close()


class ConfigHardeningTests(unittest.TestCase):
    def test_repository_configs_load_with_banner_randomization(self):
        for filename in ("config.yaml", "docker-config.yaml"):
            with self.subTest(filename=filename):
                config = load_config(str(Path(__file__).with_name(filename)))
                self.assertTrue(config["randomize_banners"])

    def test_production_example_uses_supported_runtime_schema(self):
        config = load_config(
            str(Path(__file__).with_name("docker-config.prod.example.yaml"))
        )

        self.assertEqual(config["bind_host"], "0.0.0.0")
        self.assertEqual(config["services"]["ssh"]["credential_retention"], "hashed")
        self.assertFalse(config["llm_enabled"])

    def test_production_compose_keeps_dashboard_private(self):
        compose_path = Path(__file__).with_name("docker-compose.prod.yml")
        compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        dashboard = compose["services"]["dashboard"]
        honeypot = compose["services"]["honeypot"]

        self.assertIn("127.0.0.1:8765:8765", dashboard["ports"])
        self.assertNotIn("8765:8765", dashboard["ports"])
        self.assertIn(
            "./config.prod.yaml:/app/docker-config.yaml:ro",
            honeypot["volumes"],
        )
        for ignore_file in (".gitignore", ".dockerignore"):
            with self.subTest(ignore_file=ignore_file):
                ignored = Path(__file__).with_name(ignore_file).read_text(encoding="utf-8")
                self.assertIn("config.prod.yaml", ignored)

    def test_defaults_bind_to_loopback_and_merge_service_options(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(json.dumps({"services": {"ssh": {"port": 2200}}}), encoding="utf-8")
            config = load_config(str(path))

        self.assertEqual(config["bind_host"], "127.0.0.1")
        self.assertEqual(config["services"]["ssh"]["port"], 2200)
        self.assertEqual(config["services"]["ssh"]["banner"], "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        self.assertTrue(config["services"]["ssh"]["real_ssh"])

    def test_ssh_raw_password_retention_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps({"services": {"ssh": {"credential_retention": "full"}}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "off' or 'hashed"):
                load_config(str(path))

    def test_duplicate_enabled_ports_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(json.dumps({"services": {"ssh": {"port": 2323}}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unique ports"):
                load_config(str(path))

    def test_unknown_config_options_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(json.dumps({"bind_adress": "0.0.0.0"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unknown config key"):
                load_config(str(path))

    def test_http_server_header_rejects_line_breaks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(json.dumps({"services": {"http": {
                "server_header": "safe\r\nX-Injected: yes"}}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line breaks"):
                load_config(str(path))

    def test_all_default_service_options_are_configurable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(json.dumps({"services": {
                "docker": {"api_version": "1.44"},
                "kubernetes": {"version": "v1.29.0"},
                "modbus": {"unit_id": 7},
                "mqtt": {"broker_name": "broker-test"},
            }}), encoding="utf-8")
            config = load_config(str(path))

        self.assertEqual(config["services"]["modbus"]["unit_id"], 7)
        self.assertEqual(config["services"]["mqtt"]["broker_name"], "broker-test")

    def test_llm_endpoint_must_be_loopback_or_configured_local_sidecar(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            validate_local_llm_url("https://example.com/api/generate")
        validate_local_llm_url("http://127.0.0.1:11434/api/generate")
        validate_local_llm_url("http://ollama:11434/api/generate")


class ArtifactAnalysisTests(unittest.TestCase):
    def test_sandbox_sends_configured_bearer_token_over_https(self):
        with patch("artifact_analysis.urllib.request.build_opener") as build_opener:
            opener = build_opener.return_value
            opener.open.return_value.__enter__.return_value.status = 202

            status = submit_to_sandbox("https://sandbox.example/upload", b"sample", "secret")

        request = opener.open.call_args.args[0]
        self.assertEqual(status, 202)
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")

    def test_sandbox_rejects_bearer_token_over_http(self):
        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            submit_to_sandbox("http://sandbox.example/upload", b"sample", "secret")

    def test_llm_and_sandbox_adapters_refuse_redirects(self):
        request = urllib.request.Request("http://localhost/")
        for handler_type in (SandboxNoRedirectHandler, LlmNoRedirectHandler):
            with self.subTest(handler=handler_type.__module__):
                handler = handler_type()
                self.assertIsNone(
                    handler.redirect_request(request, None, 302, "Found", {}, "https://outside.invalid/")
                )

    def test_static_triage_identifies_without_retaining_or_executing_sample(self):
        sample = b"\x7fELF" + b"GET https://example.invalid/a 192.0.2.9 curl " + b"A" * 8
        result = analyze_sample(sample)
        self.assertEqual(result["file_type"], "ELF")
        self.assertEqual(result["size"], len(sample))
        self.assertEqual(result["execution_performed"], False)
        self.assertIn("https://example.invalid/a", result["urls"])
        self.assertIn("curl ", result["static_markers"])

    def test_static_triage_enforces_sample_limit(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            analyze_sample(b"x" * (2 * 1024 * 1024 + 1))

    def test_static_triage_bounds_sample_derived_strings(self):
        result = analyze_sample(b"A" * 10000)
        self.assertEqual(len(result["strings"]), 1)
        self.assertLessEqual(len(result["strings"][0]), 200)

    def test_local_llm_response_uses_local_adapter_without_execution(self):
        with patch("local_llm._generate", return_value="simulated output") as generate:
            output = asyncio.run(generate_shell_output(
                "http://127.0.0.1:11434/api/generate",
                "test-model",
                "id",
                "Fictional Linux host",
            ))
        self.assertEqual(output, "simulated output")
        generate.assert_called_once()

    def test_local_event_classifier_returns_validated_advisory(self):
        response = json.dumps({
            "category": "reconnaissance",
            "confidence": 80,
            "rationale": "Service discovery was attempted.",
        })
        with patch("local_llm._generate", return_value=response) as generate:
            result = classify_attack_event(
                "http://127.0.0.1:11434/api/generate",
                "test-model",
                {"service": "http", "event_type": "http_recon", "detail": {}},
            )

        self.assertEqual(result["category"], "reconnaissance")
        self.assertEqual(result["confidence"], 80)
        self.assertIn("triage only", result["caveat"])
        self.assertIn("untrusted attacker-controlled data", generate.call_args.args[2])

    def test_local_event_classifier_rejects_invalid_model_outputs(self):
        invalid_responses = (
            "not json",
            "[]",
            json.dumps({"category": [], "confidence": 50, "rationale": "x"}),
            json.dumps({"category": "other", "confidence": True, "rationale": "x"}),
            json.dumps({"category": "other", "confidence": 50, "rationale": "\n"}),
        )
        for response in invalid_responses:
            with self.subTest(response=response), patch(
                "local_llm._generate", return_value=response
            ), self.assertRaises((TypeError, ValueError)):
                classify_attack_event(
                    "http://127.0.0.1:11434/api/generate",
                    "test-model",
                    {"service": "http", "event_type": "http_recon", "detail": {}},
                )

    def test_local_event_classifier_rejects_non_local_endpoint(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            classify_attack_event(
                "http://example.com/api/generate",
                "test-model",
                {"service": "http", "event_type": "connection", "detail": {}},
            )


class ReportOutputTests(unittest.TestCase):
    def test_attacker_control_characters_are_escaped(self):
        self.assertEqual(_safe_terminal_text("admin\x1b[2J", 20), "admin\\x1b[2J")

    def test_report_formats_timestamps_and_missing_usernames(self):
        report_data = Mock()
        first_seen = "2026-10-04T18:15:07.960325+00:00"
        last_seen = "2026-10-04T18:27:29.442325+00:00"
        report_data.event_counts_by_service.return_value = []
        report_data.top_offenders.return_value = [
            ("127.0.0.1", 10, 2, first_seen, last_seen)
        ]
        report_data.top_behavior_clusters.return_value = []
        report_data.top_credentials.return_value = [("", 1)]
        report_data.export_ioc_feed.return_value = []
        report_data.source_risk_analysis.return_value = {
            "level": "guarded",
            "signals": [{"count": 2, "label": "credential attempts"}],
            "caveat": "Heuristic triage only; not proof of malicious intent.",
        }
        output = StringIO()
        with redirect_stdout(output):
            print_report(report_data)
        self.assertIn(f"{first_seen}  {last_seen}", output.getvalue())
        self.assertIn("(not captured)", output.getvalue())
        self.assertIn("Risk: GUARDED", output.getvalue())

    def test_check_port_reports_closed_local_port(self):
        # Bind a socket and keep it open to hold the port
        reserved = socket.socket()
        reserved.bind(("127.0.0.1", 0))
        reserved.listen(1)
        port = reserved.getsockname()[1]
        try:
            # Port should be in use
            available, _ = check_port("127.0.0.1", port)
            self.assertFalse(available)
        finally:
            reserved.close()
        
        # After closing, port should be available
        available, _ = check_port("127.0.0.1", port)
        self.assertTrue(available)


class ProtocolIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.logger = ThreatIntelLogger(root / "events.db", root / "events.jsonl")
        self.honeypot = object.__new__(Honeypot)
        self.honeypot.config = deepcopy(DEFAULT_CONFIG)
        self.honeypot.ti = self.logger
        self.honeypot.session_counter = 0
        self.honeypot.active_connections = 0
        self.honeypot.source_connections = defaultdict(deque)
        self.honeypot.rate_limited_sources = set()
        self.honeypot._servers = []
        self.honeypot._shutdown = False
        self.honeypot._ssh_host_key = None
        self.honeypot.sys = reset_system_state("test-honeypot")
        self.honeypot._rng = random.Random(1)
        self.honeypot.pollution_counts = defaultdict(deque)
        self.honeypot.pollution_reported = set()

    async def asyncTearDown(self):
        self.logger.close()
        self.temp_dir.cleanup()

    async def connect_handler(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return server, reader, writer

    async def test_mysql_sends_greeting_and_rejects_fake_auth(self):
        server, reader, writer = await self.connect_handler(self.honeypot.handle_mysql)
        greeting_header = await reader.readexactly(4)
        greeting = await reader.readexactly(int.from_bytes(greeting_header[:3], "little"))
        self.assertEqual(greeting[0], 10)
        payload = b"\x00" * 32 + b"sim-user\x00\x00mysql_native_password\x00"
        writer.write(len(payload).to_bytes(3, "little") + b"\x01" + payload)
        await writer.drain()
        response_header = await reader.readexactly(4)
        response = await reader.readexactly(int.from_bytes(response_header[:3], "little"))
        self.assertEqual(response[0], 0xff)
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

    async def test_redis_ping_and_smtp_auth_flow(self):
        server, reader, writer = await self.connect_handler(self.honeypot.handle_redis)
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        self.assertEqual(await reader.readline(), b"+PONG\r\n")
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

        server, reader, writer = await self.connect_handler(self.honeypot.handle_smtp)
        self.assertTrue((await reader.readline()).startswith(b"220 "))
        writer.write(b"EHLO local-test\r\n")
        await writer.drain()
        while (await reader.readline()).startswith(b"250-"):
            pass
        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        self.assertTrue((await reader.readline()).startswith(b"334 "))
        writer.write(base64.b64encode(b"sim-user") + b"\r\n")
        await writer.drain()
        self.assertTrue((await reader.readline()).startswith(b"334 "))
        writer.write(base64.b64encode(b"not-a-real-password") + b"\r\n")
        await writer.drain()
        self.assertTrue((await reader.readline()).startswith(b"535 "))
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

    async def test_dashboard_summary_reads_events_and_blocks(self):
        self.logger.log_event("192.0.2.5", "http", "http_exploit_attempt", {"path": "/.env"})
        result = load_summary(self.logger.db_path)
        self.assertEqual(result["total_events"], 1)
        self.assertEqual(result["services"][0], {"service": "http", "count": 1})
        self.assertEqual(result["recent"][0]["detail"]["path"], "/.env")
        self.assertEqual(result["clusters"], [])

    async def test_real_ssh_handshake_auth_and_fake_command(self):
        ssh_config = deepcopy(DEFAULT_CONFIG["services"]["ssh"])
        ssh_config["port"] = 0
        server = await self.honeypot._start_ssh_server(ssh_config)
        try:
            async with await asyncssh.connect(
                "127.0.0.1",
                server.get_port(),
                username="sim-user",
                password="disposable-password",
                known_hosts=None,
                client_keys=[],
                agent_path=None,
            ) as connection:
                result = await connection.run("hostname", check=True)
                process = await connection.create_process()
                await asyncio.wait_for(process.stdout.readuntil("$ "), timeout=3)
                process.stdin.write("hostname\n")
                await process.stdin.drain()
                shell_output = await asyncio.wait_for(process.stdout.readline(), timeout=3)
                process.stdin.write("exit\n")
                await process.stdin.drain()
                await asyncio.wait_for(process.wait_closed(), timeout=3)
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(result.stdout.strip(), self.honeypot.sys.identity["fqdn"])
        self.assertEqual(shell_output.strip(), self.honeypot.sys.identity["fqdn"])
        with closing(sqlite3.connect(self.logger.db_path)) as connection:
            events = {
                event_type: json.loads(detail or "{}")
                for event_type, detail in connection.execute(
                    "SELECT event_type, detail FROM events WHERE service='ssh'"
                )
            }
        self.assertIn("auth_attempt", events)
        self.assertIn("auth_success_fake", events)
        self.assertEqual(events["auth_attempt"]["username"], "sim-user")
        self.assertIn("password_hash", events["auth_attempt"])
        self.assertNotIn("disposable-password", self.logger.jsonl_path.read_text(encoding="utf-8"))
        self.assertIn("command", events)

    async def test_start_serves_real_ssh_and_signal_closes_listener(self):
        for service in self.honeypot.config["services"].values():
            service["enabled"] = False
        ssh_config = self.honeypot.config["services"]["ssh"]
        ssh_config["enabled"] = True
        ssh_config["port"] = 0
        task = asyncio.create_task(self.honeypot.start())
        try:
            for _ in range(100):
                if self.honeypot._servers:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(len(self.honeypot._servers), 1)
            port = self.honeypot._servers[0].get_port()
            async with await asyncssh.connect(
                "127.0.0.1",
                port,
                username="sim-user",
                password="disposable-password",
                known_hosts=None,
                client_keys=[],
                agent_path=None,
            ) as connection:
                result = await connection.run("hostname", check=True)
            self.assertEqual(result.stdout.strip(), self.honeypot.sys.identity["fqdn"])
        finally:
            self.honeypot._signal_handler(signal.SIGTERM)
            await asyncio.wait_for(task, timeout=2)
        self.assertTrue(self.honeypot._shutdown)

    async def test_http_routine_probes_are_low_weight_non_alerting_recon(self):
        paths = (
            "/health",
            "/metrics",
            "/ready",
            "/actuator/health",
            "/api/status?next=/health",
        )
        for path in paths:
            server, reader, writer = await self.connect_handler(self.honeypot.handle_http)
            writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            await writer.drain()
            await reader.read()
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()

        server, reader, writer = await self.connect_handler(self.honeypot.handle_http)
        writer.write(b"GET /search?next=/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

        server, reader, writer = await self.connect_handler(self.honeypot.handle_http)
        writer.write(b"GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

        with closing(sqlite3.connect(self.logger.db_path)) as connection:
            event_counts = dict(connection.execute(
                "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
            ))
            event_details = {
                event_type: json.loads(detail)
                for event_type, detail in connection.execute(
                    "SELECT event_type, detail FROM events "
                    "WHERE event_type IN ('http_recon', 'http_exploit_attempt')"
                )
            }
            source_score = connection.execute(
                "SELECT score FROM source_scores WHERE src_ip='127.0.0.1'"
            ).fetchone()[0]
        self.assertEqual(event_counts["http_recon"], len(paths))
        self.assertEqual(event_counts["command"], 1)
        self.assertEqual(event_counts["http_exploit_attempt"], 1)
        self.assertEqual(EVENT_WEIGHTS["http_recon"], 1)
        self.assertNotIn("http_recon", ALERT_EVENT_TYPES)
        self.assertIn("http_exploit_attempt", ALERT_EVENT_TYPES)
        self.assertEqual(source_score, (len(paths) * 2) + 13)
        self.assertEqual(event_details["http_recon"]["mitre_techniques"], ["T1595"])
        self.assertEqual(
            event_details["http_exploit_attempt"]["mitre_techniques"],
            ["T1190", "T1505.003"],
        )

    async def test_pollution_suppresses_repeated_events_after_one_marker(self):
        self.honeypot.config["pollution_threshold"] = 2
        for _ in range(8):
            self.honeypot._log_event("192.0.2.99", "http", "command", {"path": "/"})
        with closing(sqlite3.connect(self.logger.db_path)) as connection:
            counts = dict(connection.execute(
                "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
            ))
        self.assertEqual(counts, {"command": 2, "pollution_detected": 1})

    async def test_virtual_shell_changes_are_session_local(self):
        first_session = {
            "cwd": "/root", "files": {}, "directories": set(), "deleted": set(), "mtimes": {},
        }
        second_session = {
            "cwd": "/root", "files": {}, "directories": set(), "deleted": set(), "mtimes": {},
        }
        self.honeypot._fake_command_output("touch temporary-marker", first_session)
        self.assertIn(
            b"temporary-marker",
            self.honeypot._fake_command_output("ls", first_session),
        )
        self.assertNotIn(
            b"temporary-marker",
            self.honeypot._fake_command_output("ls", second_session),
        )

    async def test_fake_shell_reads_synthetic_runtime_state(self):
        uptime = self.honeypot._fake_command_output("uptime")
        processes = self.honeypot._fake_command_output("ps aux")
        network = self.honeypot._fake_command_output("ip a")
        self.assertIn(b" up ", uptime)
        self.assertEqual(
            self.honeypot._fake_command_output("hostname"),
            self.honeypot.sys.identity["fqdn"].encode(),
        )
        self.assertIn(b"nginx", processes)
        self.assertIn(self.honeypot.sys.network["interfaces"][0]["ipv4"].encode(), network)

    async def test_fake_shell_logs_escape_attempt_indicators(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"nsenter --target 1 --mount /bin/sh\nexit\n")
        reader.feed_eof()
        writer = Mock()
        writer.drain = AsyncMock()

        await self.honeypot._fake_shell(reader, writer, "192.0.2.55", "ssh", "ssh-test")

        with closing(sqlite3.connect(self.logger.db_path)) as connection:
            detail = connection.execute(
                "SELECT detail FROM events WHERE event_type='escape_attempt'"
            ).fetchone()
        self.assertIsNotNone(detail)
        self.assertIn("namespace-entry", json.loads(detail[0])["indicators"])

    async def test_dashboard_reads_original_database_schema(self):
        old_db = Path(self.temp_dir.name) / "legacy.db"
        with closing(sqlite3.connect(old_db)) as connection:
            connection.executescript("""
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY, ts TEXT, src_ip TEXT, src_port INTEGER,
                    service TEXT, event_type TEXT, detail TEXT, session_id TEXT, hash TEXT
                );
                CREATE TABLE source_scores (
                    src_ip TEXT PRIMARY KEY, score INTEGER, first_seen TEXT,
                    last_seen TEXT, event_count INTEGER
                );
                INSERT INTO events VALUES (1, '2026-01-01T00:00:00+00:00',
                    '192.0.2.8', 1234, 'http', 'connection', '{}', NULL, NULL);
            """)
            connection.commit()
        result = load_summary(old_db)
        self.assertEqual(result["total_events"], 1)
        self.assertEqual(result["blocked_sources"], 0)
        self.assertIsNone(result["recent"][0]["city"])

    async def test_dashboard_serves_favicon(self):
        server = await asyncio.start_server(
            lambda reader, writer: handle_client(reader, writer, self.logger.db_path),
            "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

        headers, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(b"HTTP/1.1 200 OK", headers)
        self.assertIn(b"Content-Type: image/svg+xml", headers)
        self.assertIn(b"<svg", body)

    async def test_simulator_completes_against_all_protocol_handlers(self):
        handlers = {
            "ssh": self.honeypot.handle_ssh,
            "telnet": self.honeypot.handle_telnet,
            "ftp": self.honeypot.handle_ftp,
            "http": self.honeypot.handle_http,
            "mysql": self.honeypot.handle_mysql,
            "redis": self.honeypot.handle_redis,
            "smtp": self.honeypot.handle_smtp,
            "docker": self.honeypot.handle_docker,
            "kubernetes": self.honeypot.handle_kubernetes,
            "modbus": self.honeypot.handle_modbus,
            "mqtt": self.honeypot.handle_mqtt,
        }
        servers = []
        ports = {}
        for service, handler in handlers.items():
            if service == "ssh":
                continue
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            servers.append(server)
            ports[service] = server.sockets[0].getsockname()[1]
        ssh_config = deepcopy(DEFAULT_CONFIG["services"]["ssh"])
        ssh_config["port"] = 0
        ssh_server = await self.honeypot._start_ssh_server(ssh_config)
        ports["ssh"] = ssh_server.get_port()
        try:
            self.assertTrue(await run_simulator("127.0.0.1", list(PROBES), ports))
            services = {service for service, _ in self.logger.event_counts_by_service()}
            self.assertEqual(services, set(PROBES))
            self.assertNotIn("disposable-password",
                             (self.logger.jsonl_path).read_text(encoding="utf-8"))
        finally:
            ssh_server.close()
            await ssh_server.wait_closed()
            for server in servers:
                server.close()
            await asyncio.gather(*(server.wait_closed() for server in servers))

    async def test_simulator_supports_legacy_plaintext_ssh_mode(self):
        server = await asyncio.start_server(self.honeypot.handle_ssh, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            self.assertTrue(
                await run_simulator(
                    "127.0.0.1", ["ssh"], {"ssh": port}, real_ssh=False
                )
            )
        finally:
            server.close()
            await server.wait_closed()

    async def test_http_sample_is_triaged_without_persisting_raw_bytes(self):
        server, reader, writer = await self.connect_handler(self.honeypot.handle_http)
        sample = b"\x7fELF" + b"GET https://example.invalid/dropper curl " + b"z" * 32
        self.honeypot.config["sandbox_submit_url"] = "https://sandbox.example.invalid/submit"
        with patch("honeypot.submit_to_sandbox", return_value=202) as submit:
            writer.write(
                f"POST /upload HTTP/1.1\r\nHost: localhost\r\n"
                f"Content-Length: {len(sample)}\r\nConnection: close\r\n\r\n".encode()
                + sample
            )
            await writer.drain()
            response = await reader.read()
            submit.assert_called_once_with(
                "https://sandbox.example.invalid/submit", sample, None
            )
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

        self.assertIn(b"202 Accepted", response)
        with closing(sqlite3.connect(self.logger.db_path)) as connection:
            row = connection.execute(
                "SELECT detail FROM events WHERE event_type='sample_triage'"
            ).fetchone()
        self.assertIsNotNone(row)
        triage = json.loads(row[0])
        self.assertEqual(triage["file_type"], "ELF")
        self.assertNotIn(sample, self.logger.jsonl_path.read_bytes())
        with closing(sqlite3.connect(self.logger.db_path)) as connection:
            submitted = connection.execute(
                "SELECT 1 FROM events WHERE event_type='sandbox_submission'"
            ).fetchone()
        self.assertIsNotNone(submitted)


if __name__ == "__main__":
    unittest.main()
