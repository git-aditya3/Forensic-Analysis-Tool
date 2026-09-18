from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from forensic_tool.server import SentinelApp, SentinelHandler


class ApiWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = SentinelApp(Path(self.temp.name) / "data", static_dir=Path(__file__).parents[1] / "static")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), SentinelHandler)
        self.server.sentinel_app = self.app
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, path: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.headers, response.read()

    def test_browser_workflow_acquire_identify_recover_and_export(self):
        status, _headers, body = self.request(
            "/api/cases",
            "POST",
            json.dumps({"title": "API workflow"}).encode(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)
        case_id = json.loads(body)["id"]
        source = (
            b"HIKVISION@HANGZHOU"
            b"\x00\x00\x01\x67sps"
            b"\x00\x00\x01\x68pps"
            b"\x00\x00\x01\x65idr"
        )
        status, _headers, body = self.request(
            f"/api/cases/{case_id}/evidence",
            "POST",
            source,
            {"Content-Type": "application/octet-stream", "X-Filename": "camera.img"},
        )
        self.assertEqual(status, 201)
        evidence_id = json.loads(body)["id"]

        status, _headers, body = self.request(f"/api/evidence/{evidence_id}/identify", "POST", b"")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["primary_vendor"], "hikvision")

        status, _headers, body = self.request(
            f"/api/evidence/{evidence_id}/recover",
            "POST",
            json.dumps({"mode": "normal"}).encode(),
            {"Content-Type": "application/json"},
        )
        recovery = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(recovery["segment_count"], 1)
        segment_id = recovery["segments"][0]["id"]

        status, headers, body = self.request(f"/api/segments/{segment_id}/export?format=native")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "video/h264")
        self.assertEqual(body, source[source.index(b"\x00\x00\x01\x67"):])

        status, _headers, body = self.request(f"/api/cases/{case_id}")
        bundle = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(bundle["chain"]["valid"])
        self.assertEqual(len(bundle["evidence"][0]["segments"]), 1)


if __name__ == "__main__":
    unittest.main()
