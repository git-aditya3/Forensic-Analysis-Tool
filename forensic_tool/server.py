"""Dependency-free local web workstation and JSON API."""

from __future__ import annotations

import ipaddress
import json
import math
import mimetypes
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .analysis.engine import AnalysisEngine
from .exporter import ExportError, export_segment
from .reporting import write_report
from .security import new_token, token_matches
from .storage import EvidenceStore


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
}
_AUTH_COOKIE = "sentinel_auth"
_CSRF_COOKIE = "sentinel_csrf"
_MAX_JSON_BYTES = 1 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


class SentinelHandler(BaseHTTPRequestHandler):
    server_version = "Sentinel"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> "SentinelApp":
        return self.server.sentinel_app  # type: ignore[attr-defined]

    @staticmethod
    def _public_evidence(value: Dict[str, Any]) -> Dict[str, Any]:
        """Do not disclose host filesystem paths through the HTTP API."""

        return {key: item for key, item in value.items() if key != "absolute_path"}

    def _cookies(self) -> Dict[str, str]:
        values: Dict[str, str] = {}
        raw = self.headers.get("Cookie", "")
        for item in raw.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name:
                values[name] = value
        return values

    def _bearer_token(self) -> Optional[str]:
        value = self.headers.get("Authorization", "")
        scheme, separator, token = value.partition(" ")
        if separator and scheme.lower() == "bearer":
            return token.strip()
        return None

    def _authorize(self, method: str, path: str) -> None:
        """Require a bearer token or same-origin bootstrap cookie for every API route."""

        if not path.startswith("/api/"):
            return
        cookies = self._cookies()
        bearer_ok = token_matches(self.app.auth_token, self._bearer_token())
        self._bearer_authenticated = bearer_ok
        cookie_ok = token_matches(self.app.auth_token, cookies.get(_AUTH_COOKIE))
        if not bearer_ok and not cookie_ok:
            raise ApiError("Authentication required", 401)
        if cookie_ok and not bearer_ok and method not in {"GET", "HEAD"}:
            csrf = cookies.get(_CSRF_COOKIE, "")
            supplied = self.headers.get("X-Sentinel-CSRF", "")
            if not csrf or not token_matches(csrf, supplied):
                raise ApiError("CSRF validation failed", 403)

    def _send_security_headers(self) -> None:
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)

    def _set_local_session_cookies(self, extra_headers: Optional[list[tuple[str, str]]] = None) -> list[tuple[str, str]]:
        headers = list(extra_headers or [])
        try:
            address = ipaddress.ip_address(self.client_address[0])
            local = address.is_loopback
        except (ValueError, IndexError):
            local = False
        if local or getattr(self, "_bearer_authenticated", False):
            headers.extend([
                ("Set-Cookie", f"{_AUTH_COOKIE}={self.app.auth_token}; Path=/; HttpOnly; SameSite=Strict"),
                ("Set-Cookie", f"{_CSRF_COOKIE}={self.app.csrf_token}; Path=/; SameSite=Strict"),
            ])
        return headers

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.app.request_timeout)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the console useful during a forensic run without logging raw
        # evidence paths or request bodies.
        print(f"[{self.log_date_time_string()}] {format % args}")

    def _content_length(self, *, required: bool = False) -> int:
        transfer_values = self.headers.get_all("Transfer-Encoding") or []
        transfer_encoding = ",".join(transfer_values).strip().lower()
        if transfer_encoding and transfer_encoding != "identity":
            raise ApiError("Chunked request bodies are not supported", 411)
        length_values = self.headers.get_all("Content-Length") or []
        if len(length_values) > 1 or any("," in item for item in length_values):
            raise ApiError("Ambiguous Content-Length is not accepted", 400)
        raw = length_values[0] if length_values else None
        if raw is None or not raw.strip():
            if required:
                raise ApiError("Content-Length is required", 411)
            return 0
        try:
            length = int(raw, 10)
        except ValueError as exc:
            raise ApiError("Content-Length must be a non-negative integer", 400) from exc
        if length < 0:
            raise ApiError("Content-Length must be non-negative", 400)
        return length

    def _json_body(self) -> Dict[str, Any]:
        length = self._content_length()
        if length > _MAX_JSON_BYTES:
            raise ApiError("JSON request is too large", 413)
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if length and content_type not in {"application/json", "application/json-patch+json"}:
            raise ApiError("JSON endpoints require Content-Type: application/json", 415)
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError("Invalid JSON request", 400)
        if not isinstance(value, dict):
            raise ApiError("JSON body must be an object", 400)
        return value

    @staticmethod
    def _query_tolerance(parsed: urllib.parse.ParseResult) -> float:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        raw = query.get("tolerance", ["2"])[0]
        try:
            tolerance = float(raw)
        except ValueError as exc:
            raise ApiError("tolerance must be a finite number", 400) from exc
        if not math.isfinite(tolerance) or tolerance < 0 or tolerance > 3600:
            raise ApiError("tolerance must be between 0 and 3600 seconds", 400)
        return tolerance

    def _send_json(self, value: Any, status: int = 200, extra_headers: Optional[list[tuple[str, str]]] = None) -> None:
        payload = json.dumps(value, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self._send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        headers = list(extra_headers or [])
        if getattr(self, "_bearer_authenticated", False):
            headers = self._set_local_session_cookies(headers)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _send_bytes(self, payload: bytes, content_type: str, status: int = 200, disposition: Optional[str] = None) -> None:
        self.send_response(status)
        self._send_security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path: Path, content_type: str, disposition: Optional[str] = None, extra_headers: Optional[list[tuple[str, str]]] = None) -> None:
        if not path.is_file() or path.is_symlink():
            raise ApiError("Artifact not found", 404)
        size = path.stat().st_size
        self.send_response(200)
        self._send_security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        headers = list(extra_headers or [])
        if getattr(self, "_bearer_authenticated", False):
            headers = self._set_local_session_cookies(headers)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
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
            print(f"[server error] {type(error).__name__}")
        message = message.replace(str(self.app.store.root), "<case-data>")
        # Never keep an HTTP/1.1 connection alive after a rejected request;
        # otherwise an unread body could be interpreted as a second request.
        self.close_connection = True
        headers = [("WWW-Authenticate", 'Bearer realm="sentinel"')] if status == 401 else None
        try:
            self._send_json({"error": message, "status": status}, status, headers)
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

    def _method_not_allowed(self) -> None:
        self._send_json({"error": "Method not allowed", "status": 405}, 405, [("Allow", "GET, POST")])

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_TRACE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _get(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        self._authorize("GET", path)
        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path.startswith("/static/"):
            return self._static(path.removeprefix("/static/"))
        parts = [urllib.parse.unquote(part) for part in path.strip("/").split("/") if part]
        if parts == ["api", "health"]:
            return self._send_json({"ok": True, "service": "sentinel", "version": __version__, "capabilities": self.app.engine.capabilities()})
        if parts == ["api", "capabilities"]:
            return self._send_json(self.app.engine.capabilities())
        if parts == ["api", "cases"]:
            return self._send_json({"cases": self.app.store.list_cases()})
        if len(parts) == 3 and parts[:2] == ["api", "cases"]:
            case = self.app.store.get_case(parts[2])
            if not case:
                raise ApiError("Case not found", 404)
            return self._send_json(self.app.store.case_bundle(parts[2]))
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "evidence" and parts[3] == "timeline":
            return self._send_json(self.app.engine.timeline(parts[2], self._query_tolerance(parsed)))
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "cases" and parts[3] == "timeline":
            return self._send_json(self.app.engine.correlate_case(parts[2], self._query_tolerance(parsed)))
        if len(parts) == 4 and parts[:2] == ["api", "evidence"] and parts[3] == "integrity":
            return self._send_json(self.app.store.verify_evidence(parts[2]))
        if len(parts) == 4 and parts[:2] == ["api", "segments"] and parts[3] == "analytics":
            return self._send_json({"segment_id": parts[2], "findings": self.app.store.list_analytics(parts[2])})
        if len(parts) == 3 and parts[:2] == ["api", "evidence"]:
            evidence = self.app.store.get_evidence(parts[2])
            if not evidence:
                raise ApiError("Evidence not found", 404)
            evidence["identification"] = self.app.store.latest_identification(parts[2])
            evidence["segments"] = self.app.store.list_segments(parts[2])
            for segment in evidence["segments"]:
                segment["analytics"] = self.app.store.list_analytics(segment["id"])
            return self._send_json(self._public_evidence(evidence))
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
        self._authorize("POST", path)
        parts = [urllib.parse.unquote(part) for part in path.strip("/").split("/") if part]
        if parts == ["api", "cases"]:
            body = self._json_body()
            return self._send_json(
                self.app.store.create_case(body.get("title", "Untitled examination"), body.get("investigator", ""), body.get("notes", "")),
                201,
            )
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "cases" and parts[3] == "evidence":
            case_id = parts[2]
            length = self._content_length(required=True)
            if length <= 0:
                raise ApiError("Evidence upload is empty", 400)
            if length > self.app.max_upload_bytes:
                raise ApiError(f"Upload exceeds configured limit ({self.app.max_upload_bytes:,} bytes)", 413)
            name = self.headers.get("X-Filename", "evidence.img")
            query = urllib.parse.parse_qs(parsed.query)
            source_kind = query.get("source_kind", [self.headers.get("X-Source-Kind", "disk-image")])[0]
            method = query.get("acquisition_method", [self.headers.get("X-Acquisition-Method", "streaming-bitstream-copy")])[0]
            try:
                sector_size = int(query.get("sector_size", [self.headers.get("X-Sector-Size", "512")])[0])
            except ValueError as exc:
                raise ApiError("sector_size must be an integer", 400) from exc
            # Uploads are one request per connection so trailing bytes cannot
            # be reinterpreted as a pipelined command.
            self.close_connection = True
            evidence = self.app.store.ingest_stream(
                case_id,
                _LimitedReader(self.rfile, length),
                name,
                source_kind=source_kind,
                sector_size=sector_size,
                acquisition_method=method,
            )
            return self._send_json(self._public_evidence(evidence), 201)
        if len(parts) == 4 and parts[:2] == ["api", "evidence"] and parts[3] == "identify":
            return self._send_json(self.app.engine.identify(parts[2]))
        if len(parts) == 4 and parts[:2] == ["api", "evidence"] and parts[3] == "recover":
            body = self._json_body()
            return self._send_json(self.app.engine.recover(parts[2], body.get("mode", "normal")))
        if len(parts) == 4 and parts[:2] == ["api", "evidence"] and parts[3] == "verify":
            return self._send_json(self.app.store.verify_evidence(parts[2]))
        if len(parts) == 4 and parts[:2] == ["api", "segments"] and parts[3] == "analytics":
            body = self._json_body()
            return self._send_json(self.app.engine.analytics(parts[2], body.get("kind", "motion"), body.get("model", "")))
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
        if not candidate.is_file() or candidate.is_symlink():
            raise ApiError("Static asset not found", 404)
        if candidate.suffix.lower() not in {".html", ".js", ".css"}:
            raise ApiError("Static asset type is not allowed", 404)
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if candidate.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif candidate.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif candidate.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        self._send_file(candidate, content_type, extra_headers=self._set_local_session_cookies())


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
    def __init__(
        self,
        data_dir: str | Path = "data",
        static_dir: str | Path | None = None,
        max_upload_bytes: int = 8 * 1024**4,
        auth_token: Optional[str] = None,
    ):
        if max_upload_bytes <= 0:
            raise ValueError("max_upload_bytes must be positive")
        self.store = EvidenceStore(data_dir)
        self.engine = AnalysisEngine(self.store)
        self.static_dir = Path(static_dir or Path(__file__).resolve().parent.parent / "static")
        if not self.static_dir.is_dir():
            raise ValueError("static_dir must be an existing directory")
        if auth_token is not None and (not isinstance(auth_token, str) or len(auth_token) < 32):
            raise ValueError("auth_token must contain at least 32 characters")
        self.max_upload_bytes = max_upload_bytes
        self.auth_token = auth_token or new_token()
        self.csrf_token = new_token(24)
        self.request_timeout = 120


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound concurrent connections so slow clients cannot exhaust the host."""

    daemon_threads = True
    request_queue_size = 32

    def __init__(self, server_address, request_handler_class, *, max_connections: int = 32):
        if max_connections <= 0 or max_connections > 256:
            raise ValueError("max_connections must be between 1 and 256")
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, request_handler_class)

    def process_request_thread(self, request, client_address):  # type: ignore[no-untyped-def]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def process_request(self, request, client_address):  # type: ignore[no-untyped-def]
        if not self._connection_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise


def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    data_dir: str | Path = "data",
    *,
    auth_token: Optional[str] = None,
    max_upload_bytes: int = 8 * 1024**4,
    max_connections: int = 32,
    allow_insecure_network: bool = False,
) -> None:
    try:
        address = ipaddress.ip_address(host)
        network_bind = not address.is_loopback
    except ValueError:
        network_bind = host not in {"localhost", "127.0.0.1", "::1"}
    if network_bind and not allow_insecure_network:
        raise ValueError("Refusing non-loopback HTTP binding; use a TLS reverse proxy or explicitly pass --allow-insecure-network")
    app = SentinelApp(data_dir=data_dir, max_upload_bytes=max_upload_bytes, auth_token=auth_token)
    server = LimitedThreadingHTTPServer((host, port), SentinelHandler, max_connections=max_connections)
    server.sentinel_app = app  # type: ignore[attr-defined]
    print(f"Sentinel workstation listening on http://{host}:{port}")
    print(f"Evidence store: {app.store.root}")
    print(f"API token (keep private): {app.auth_token}")
    print("API access is bearer-token protected; local browsers receive a SameSite session cookie.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel")
    finally:
        server.server_close()
