"""Dependency-free local web workstation and JSON API."""

from __future__ import annotations

import json
import mimetypes
import os
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import __version__
from .analysis.engine import AnalysisEngine
from .exporter import ExportError, export_segment
from .reporting import build_report, write_report
from .storage import EvidenceStore


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


class SentinelHandler(BaseHTTPRequestHandler):
    server_version = "Sentinel/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> "SentinelApp":
        return self.server.sentinel_app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the console useful during a forensic run without logging raw
        # evidence paths or request bodies.
        print(f"[{self.log_date_time_string()}] {format % args}")

    def _json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 2 * 1024 * 1024:
            raise ApiError("JSON request is too large", 413)
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(f"Invalid JSON: {exc}", 400) from exc
        if not isinstance(value, dict):
            raise ApiError("JSON body must be an object", 400)
        return value

    def _send_json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_bytes(self, payload: bytes, content_type: str, status: int = 200, disposition: Optional[str] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path: Path, content_type: str, disposition: Optional[str] = None) -> None:
        if not path.is_file():
            raise ApiError("Artifact not found", 404)
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        with path.open("rb") as stream:
            while True:
                block = stream.read(4 * 1024 * 1024)
                if not block:
                    break
                self.wfile.write(block)

    def _error(self, error: Exception) -> None:
        if isinstance(error, ApiError):
            status, message = error.status, error.message
        elif isinstance(error, KeyError):
            status, message = 404, str(error).strip("'")
        elif isinstance(error, (ValueError, ExportError)):
            status, message = 400, str(error)
        else:
            status, message = 500, "Internal server error"
            print(f"[server error] {type(error).__name__}: {error}")
        try:
            self._send_json({"error": message, "status": status}, status)
        except BrokenPipeError:
            pass

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._get()
        except Exception as error:  # pragma: no cover - safety boundary
            self._error(error)

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._post()
        except Exception as error:  # pragma: no cover - safety boundary
            self._error(error)

    def _get(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path.startswith("/static/"):
            return self._static(path.removeprefix("/static/"))
        parts = [urllib.parse.unquote(part) for part in path.strip("/").split("/") if part]
        if parts == ["api", "health"]:
            return self._send_json({"ok": True, "service": "sentinel", "version": __version__})
        if parts == ["api", "cases"]:
            return self._send_json({"cases": self.app.store.list_cases()})
        if len(parts) == 3 and parts[:2] == ["api", "cases"]:
            case = self.app.store.get_case(parts[2])
            if not case:
                raise ApiError("Case not found", 404)
            return self._send_json(self.app.store.case_bundle(parts[2]))
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "evidence" and parts[3] == "timeline":
            return self._send_json(self.app.engine.timeline(parts[2]))
        if len(parts) == 3 and parts[:2] == ["api", "evidence"]:
            evidence = self.app.store.get_evidence(parts[2])
            if not evidence:
                raise ApiError("Evidence not found", 404)
            evidence["identification"] = self.app.store.latest_identification(parts[2])
            evidence["segments"] = self.app.store.list_segments(parts[2])
            return self._send_json(evidence)
        if len(parts) == 3 and parts[:2] == ["api", "cases"] and parts[2].endswith((".html", ".pdf")):
            # Kept for compatibility with simple clients; the more specific
            # report route below handles normal case identifiers.
            raise ApiError("Use /api/cases/{case_id}/report.html or /report.pdf", 400)
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] in {"report.html", "report.pdf", "report.json"}:
            case_id = parts[2]
            self.app.store.require_case(case_id)
            report = write_report(self.app.store, case_id)
            suffix = ".html" if parts[3].endswith("html") else ".pdf" if parts[3].endswith("pdf") else ".json"
            path_value = Path(report["html" if suffix == ".html" else "pdf" if suffix == ".pdf" else "json"])
            content_type = {".html": "text/html; charset=utf-8", ".pdf": "application/pdf", ".json": "application/json"}[suffix]
            return self._send_file(path_value, content_type, f'attachment; filename="{path_value.name}"' if suffix != ".html" else None)
        if len(parts) == 4 and parts[:2] == ["api", "segments"] and parts[3] == "export":
            query = urllib.parse.parse_qs(parsed.query)
            output_format = query.get("format", ["native"])[0]
            exported = export_segment(self.app.store, parts[2], output_format)
            return self._send_file(Path(str(exported["path"])), str(exported["content_type"]), f'attachment; filename="{exported["filename"]}"')
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "cases" and parts[3] == "audit":
            self.app.store.require_case(parts[2])
            return self._send_json({"chain": self.app.store.verify_chain(parts[2]), "events": self.app.store.audit_events(parts[2])})
        raise ApiError("Route not found", 404)

    def _post(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        parts = [urllib.parse.unquote(part) for part in path.strip("/").split("/") if part]
        if parts == ["api", "cases"]:
            body = self._json_body()
            return self._send_json(
                self.app.store.create_case(body.get("title", "Untitled examination"), body.get("investigator", ""), body.get("notes", "")),
                201,
            )
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "cases" and parts[3] == "evidence":
            case_id = parts[2]
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                raise ApiError("Evidence upload is empty or missing Content-Length", 400)
            if length > self.app.max_upload_bytes:
                raise ApiError(f"Upload exceeds configured limit ({self.app.max_upload_bytes:,} bytes)", 413)
            name = self.headers.get("X-Filename", "evidence.img")
            evidence = self.app.store.ingest_stream(case_id, _LimitedReader(self.rfile, length), name)
            return self._send_json(evidence, 201)
        if len(parts) == 4 and parts[:2] == ["api", "evidence"] and parts[3] == "identify":
            return self._send_json(self.app.engine.identify(parts[2]))
        if len(parts) == 4 and parts[:2] == ["api", "evidence"] and parts[3] == "recover":
            body = self._json_body()
            return self._send_json(self.app.engine.recover(parts[2], body.get("mode", "normal")))
        if len(parts) == 4 and parts[:2] == ["api", "segments"] and parts[3] == "export":
            body = self._json_body()
            exported = export_segment(self.app.store, parts[2], body.get("format", "native"))
            return self._send_json(exported)
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "report":
            return self._send_json(write_report(self.app.store, parts[2]))
        raise ApiError("Route not found", 404)

    def _static(self, relative: str) -> None:
        root = self.app.static_dir.resolve()
        candidate = (root / relative).resolve()
        if root not in candidate.parents and candidate != root:
            raise ApiError("Invalid static path", 400)
        if not candidate.is_file():
            raise ApiError("Static asset not found", 404)
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if candidate.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif candidate.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif candidate.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        self._send_file(candidate, content_type)


class _LimitedReader:
    def __init__(self, stream, remaining: int):
        self.stream = stream
        self.remaining = remaining

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        if size is None or size < 0:
            size = self.remaining
        size = min(size, self.remaining)
        block = self.stream.read(size)
        self.remaining -= len(block)
        return block


class SentinelApp:
    def __init__(self, data_dir: str | Path = "data", static_dir: str | Path | None = None, max_upload_bytes: int = 8 * 1024**4):
        self.store = EvidenceStore(data_dir)
        self.engine = AnalysisEngine(self.store)
        self.static_dir = Path(static_dir or Path(__file__).resolve().parent.parent / "static")
        self.max_upload_bytes = max_upload_bytes


def serve(host: str = "0.0.0.0", port: int = 8000, data_dir: str | Path = "data") -> None:
    app = SentinelApp(data_dir=data_dir)
    server = ThreadingHTTPServer((host, port), SentinelHandler)
    server.sentinel_app = app  # type: ignore[attr-defined]
    print(f"Sentinel workstation listening on http://{host}:{port}")
    print(f"Evidence store: {app.store.root}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel")
    finally:
        server.server_close()
