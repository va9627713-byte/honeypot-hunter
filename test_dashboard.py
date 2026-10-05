import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dashboard
from dashboard import handle_client
from ti_logger import ThreatIntelLogger


class DashboardIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logger = ThreatIntelLogger(
            Path(self.temp_dir.name) / "events.db",
            Path(self.temp_dir.name) / "events.jsonl",
        )
        self.logger.log_event("192.0.2.5", "http", "connection")
        self.server = await asyncio.start_server(
            lambda reader, writer: handle_client(reader, writer, self.logger.db_path),
            "127.0.0.1",
            0,
            limit=16384,
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.logger.close()
        self.temp_dir.cleanup()

    async def request(self, path):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        return response.split(b"\r\n\r\n", 1)

    async def test_summary_api_and_dashboard_page(self):
        headers, body = await self.request("/api/summary")
        self.assertIn(b"HTTP/1.1 200 OK", headers)
        summary = json.loads(body)
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["recent"][0]["src_ip"], "192.0.2.5")

        headers, body = await self.request("/")
        self.assertIn(b"HTTP/1.1 200 OK", headers)
        self.assertIn(b'href="/favicon.svg"', body)
        self.assertIn(b'<script src="/dashboard.js" defer></script>', body)
        self.assertIn(b"script-src 'self'", headers)
        self.assertIn(b"script-src 'self';", headers)

    async def test_favicon_svg_is_served(self):
        headers, body = await self.request("/favicon.svg")
        self.assertIn(b"HTTP/1.1 200 OK", headers)
        self.assertIn(b"Content-Type: image/svg+xml", headers)
        self.assertIn(b"<svg", body)

    async def test_summary_filters_by_service_and_time_window(self):
        headers, body = await self.request("/api/summary?service=http&window=24h")
        summary = json.loads(body)
        self.assertIn(b"HTTP/1.1 200 OK", headers)
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["total_sources"], 1)
        self.assertEqual(summary["services"], [{"service": "http", "count": 1}])
        self.assertEqual(summary["service_options"], ["http"])
        self.assertEqual(summary["offenders"][0]["risk_level"], "low")
        self.assertEqual(summary["offenders"][0]["risk_signals"][0]["label"], "connection")
        self.assertIn("not proof", summary["offenders"][0]["risk_caveat"])

        _, body = await self.request("/api/summary?service=ssh")
        self.assertEqual(json.loads(body)["total_events"], 0)

    async def test_summary_rejects_invalid_filters(self):
        headers, body = await self.request("/api/summary?window=forever")
        self.assertIn(b"HTTP/1.1 400 Bad Request", headers)
        self.assertIn(b"window must be one of", body)

    async def test_rate_limit_only_applies_to_summary_api(self):
        dashboard._rate_limiter.clear()
        try:
            with patch("dashboard._RATE_LIMIT", 1):
                first_headers, _ = await self.request("/api/summary")
                limited_headers, _ = await self.request("/api/summary")
                page_headers, _ = await self.request("/")
            self.assertIn(b"HTTP/1.1 200 OK", first_headers)
            self.assertIn(b"HTTP/1.1 429 Too Many Requests", limited_headers)
            self.assertIn(b"Retry-After: 60", limited_headers)
            self.assertIn(b"HTTP/1.1 200 OK", page_headers)
        finally:
            dashboard._rate_limiter.clear()

    async def test_dashboard_javascript_is_served_with_safe_dom_rendering(self):
        headers, body = await self.request("/dashboard.js")
        self.assertIn(b"HTTP/1.1 200 OK", headers)
        self.assertIn(b"Content-Type: text/javascript", headers)
        self.assertIn(b"textContent", body)
        self.assertIn(b"replaceChildren", body)
        self.assertIn(b"Refreshing", body)
        self.assertIn(b"refreshInFlight", body)
        self.assertNotIn(b"innerHTML", body)


if __name__ == "__main__":
    unittest.main()
