"""SQLite-backed case, evidence, result, and custody storage.

The database stores metadata only.  Acquired bytes live under the data
folder, are never opened for writing after ingest, and are addressed by a
case/evidence identifier rather than a user-supplied path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Iterator, List, Optional

from .hashing import hash_file, hash_stream
from .imaging import AcquisitionPlan, open_source_read_only
from .models import AuditEvent, Case, Evidence, Identification, Segment, VendorHit


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    investigator TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'disk-image',
    read_only INTEGER NOT NULL DEFAULT 1,
    source_kind TEXT NOT NULL DEFAULT 'disk-image',
    acquisition_method TEXT NOT NULL DEFAULT 'streaming-bitstream-copy',
    sector_size INTEGER NOT NULL DEFAULT 512
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE TABLE IF NOT EXISTS identifications (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    primary_vendor TEXT NOT NULL,
    confidence REAL NOT NULL,
    hits_json TEXT NOT NULL,
    device_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identifications_evidence ON identifications(evidence_id, created_at);
CREATE TABLE IF NOT EXISTS segments (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    vendor TEXT NOT NULL,
    source TEXT NOT NULL,
    recovery_mode TEXT NOT NULL,
    state TEXT NOT NULL,
    channel INTEGER,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    codec TEXT NOT NULL,
    confidence REAL NOT NULL,
    start_time TEXT,
    end_time TEXT,
    source_sha256 TEXT,
    artifact_path TEXT,
    payload_start_offset INTEGER,
    payload_end_offset INTEGER,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_segments_evidence ON segments(evidence_id, start_offset);
CREATE TABLE IF NOT EXISTS analytics_findings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    segment_id TEXT NOT NULL REFERENCES segments(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_analytics_segment ON analytics_findings(segment_id, completed_at);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id, id);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_name(value: str) -> str:
    value = Path(value or "evidence.img").name
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (value or "evidence.img")[:180]


def _row_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(row) if row is not None else None


class EvidenceStore:
    """Owns the case database and immutable evidence/artifact directories."""

    def __init__(self, root: str | Path = "data"):
        self.root = Path(root).expanduser().resolve()
        self.evidence_dir = self.root / "evidence"
        self.exports_dir = self.root / "exports"
        self.reports_dir = self.root / "reports"
        self.db_path = self.root / "sentinel.sqlite3"
        self._lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            self._ensure_columns(
                connection,
                "evidence",
                {
                    "source_kind": "TEXT NOT NULL DEFAULT 'disk-image'",
                    "acquisition_method": "TEXT NOT NULL DEFAULT 'streaming-bitstream-copy'",
                    "sector_size": "INTEGER NOT NULL DEFAULT 512",
                },
            )
            self._ensure_columns(connection, "identifications", {"device_json": "TEXT NOT NULL DEFAULT '{}'"})
            self._ensure_columns(
                connection,
                "segments",
                {
                    "payload_start_offset": "INTEGER",
                    "payload_end_offset": "INTEGER",
                },
            )

    @staticmethod
    def _ensure_columns(connection: sqlite3.Connection, table: str, columns: Dict[str, str]) -> None:
        existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    # ---- cases ---------------------------------------------------------
    def create_case(self, title: str, investigator: str = "", notes: str = "") -> Dict[str, Any]:
        title = (title or "Untitled examination").strip()[:240]
        case = Case(
            id=f"CASE-{uuid.uuid4().hex[:10].upper()}",
            title=title,
            investigator=(investigator or "").strip()[:160],
            notes=(notes or "").strip()[:4000],
            created_at=utc_now(),
        )
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO cases(id,title,investigator,notes,created_at,status) VALUES(?,?,?,?,?,?)",
                (case.id, case.title, case.investigator, case.notes, case.created_at, case.status),
            )
            self._audit_in_transaction(
                connection,
                case.id,
                "case_created",
                {"title": case.title, "investigator": case.investigator},
            )
        return case.to_dict()

    def list_cases(self) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT c.*, COUNT(DISTINCT e.id) AS evidence_count,
                   COUNT(DISTINCT s.id) AS segment_count
                   FROM cases c
                   LEFT JOIN evidence e ON e.case_id = c.id
                   LEFT JOIN segments s ON s.evidence_id = e.id
                   GROUP BY c.id ORDER BY c.created_at DESC"""
            ).fetchall()
        return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return _row_dict(row)

    def require_case(self, case_id: str) -> Dict[str, Any]:
        case = self.get_case(case_id)
        if not case:
            raise KeyError(f"Unknown case: {case_id}")
        return case

    # ---- acquisition ---------------------------------------------------
    def ingest_file(
        self,
        case_id: str,
        source_path: str | Path,
        original_name: Optional[str] = None,
        source: str = "disk-image",
        source_kind: str = "disk-image",
        sector_size: int = 512,
        acquisition_method: str = "streaming-bitstream-copy",
    ) -> Dict[str, Any]:
        self.require_case(case_id)
        plan = AcquisitionPlan(source_kind, sector_size, acquisition_method)
        plan.validate()
        source_path = Path(source_path).expanduser().resolve()
        with open_source_read_only(source_path) as stream:
            return self._ingest_stream(case_id, stream, original_name or source_path.name, source, plan)

    def ingest_stream(
        self,
        case_id: str,
        stream: BinaryIO,
        original_name: str,
        source: str = "disk-image",
        source_kind: str = "disk-image",
        sector_size: int = 512,
        acquisition_method: str = "streaming-bitstream-copy",
    ) -> Dict[str, Any]:
        self.require_case(case_id)
        plan = AcquisitionPlan(source_kind, sector_size, acquisition_method)
        plan.validate()
        return self._ingest_stream(case_id, stream, original_name, source, plan)

    def _ingest_stream(
        self, case_id: str, stream: BinaryIO, original_name: str, source: str, plan: AcquisitionPlan
    ) -> Dict[str, Any]:
        evidence_id = f"EVD-{uuid.uuid4().hex[:12].upper()}"
        safe_name = _safe_name(original_name)
        case_dir = self.evidence_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        destination = case_dir / f"{evidence_id}_{safe_name}"
        try:
            with destination.open("wb") as output:
                digest = hash_stream(_TeeReader(stream, output))
                output.flush()
                os.fsync(output.fileno())
            # HTTP uploads are wrapped in a length-limited reader.  Refuse a
            # truncated body before creating the metadata row; otherwise a
            # network interruption could be mistaken for a complete image.
            remaining = getattr(stream, "remaining", 0)
            if remaining:
                raise ValueError(f"Evidence stream ended {remaining:,} bytes before the declared length")
            # The acquired copy is intentionally read-only.  It remains readable
            # by the current process while protecting it from accidental writes.
            try:
                os.chmod(destination, 0o440)
            except OSError:
                pass
            acquired_at = utc_now()
            relative_path = str(destination.relative_to(self.root))
            with self._transaction() as connection:
                connection.execute(
                    """INSERT INTO evidence(id,case_id,original_name,storage_path,size,md5,sha256,acquired_at,source,read_only,source_kind,acquisition_method,sector_size)
                       VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?)""",
                    (
                        evidence_id,
                        case_id,
                        safe_name,
                        relative_path,
                        int(digest["size"]),
                        str(digest["md5"]),
                        str(digest["sha256"]),
                        acquired_at,
                        source,
                        plan.source_kind,
                        plan.method,
                        plan.sector_size,
                    ),
                )
                self._audit_in_transaction(
                    connection,
                    case_id,
                    "evidence_acquired",
                    {
                        "evidence_id": evidence_id,
                        "name": safe_name,
                        "size": int(digest["size"]),
                        "md5": digest["md5"],
                        "sha256": digest["sha256"],
                        "source": source,
                        "source_kind": plan.source_kind,
                        "acquisition_method": plan.method,
                        "sector_size": plan.sector_size,
                    },
                )
        except Exception:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
        return self.get_evidence(evidence_id) or {}

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        result = _row_dict(row)
        if result:
            result["read_only"] = bool(result["read_only"])
            result["absolute_path"] = str((self.root / result["storage_path"]).resolve())
        return result

    def list_evidence(self, case_id: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY acquired_at DESC", (case_id,)
            ).fetchall()
        return [dict(row, read_only=bool(row["read_only"])) for row in rows]

    def evidence_reader(self, evidence_id: str):
        from .reader import EvidenceReader

        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        return EvidenceReader(evidence["absolute_path"])

    def verify_evidence(self, evidence_id: str, record: bool = True) -> Dict[str, Any]:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        try:
            actual = hash_file(Path(evidence["absolute_path"]))
            hash_error = None
        except OSError as error:
            actual = {"size": None, "md5": None, "sha256": None}
            hash_error = str(error)
        result = {
            "evidence_id": evidence_id,
            "expected": {"size": evidence["size"], "md5": evidence["md5"], "sha256": evidence["sha256"]},
            "actual": actual,
            "valid": (
                actual["size"] is not None
                and int(actual["size"]) == int(evidence["size"])
                and str(actual["md5"]) == str(evidence["md5"])
                and str(actual["sha256"]) == str(evidence["sha256"])
            ),
            "read_only": bool(evidence["read_only"]),
            "verified_at": utc_now(),
            "error": hash_error,
        }
        if record:
            self.record_audit(evidence["case_id"], "evidence_integrity_verified", result)
        return result

    # ---- analysis result persistence ----------------------------------
    def save_identification(
        self,
        evidence_id: str,
        primary_vendor: str,
        confidence: float,
        hits: List[VendorHit],
        device_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        identification_id = f"ID-{uuid.uuid4().hex[:12].upper()}"
        created_at = utc_now()
        hit_values = [hit.to_dict() for hit in hits]
        device_info = device_info or {}
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO identifications(id,evidence_id,primary_vendor,confidence,hits_json,device_json,created_at) VALUES(?,?,?,?,?,?,?)",
                (identification_id, evidence_id, primary_vendor, confidence, json.dumps(hit_values, sort_keys=True), json.dumps(device_info, sort_keys=True), created_at),
            )
            self._audit_in_transaction(
                connection,
                evidence["case_id"],
                "evidence_identified",
                {
                    "evidence_id": evidence_id,
                    "identification_id": identification_id,
                    "primary_vendor": primary_vendor,
                    "confidence": confidence,
                    "hit_count": len(hit_values),
                    "device_models": device_info.get("models", []),
                    "firmware_candidates": device_info.get("firmware", []),
                },
            )
        return {
            "id": identification_id,
            "evidence_id": evidence_id,
            "primary_vendor": primary_vendor,
            "confidence": confidence,
            "hits": hit_values,
            "device": device_info,
            "created_at": created_at,
        }

    def latest_identification(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM identifications WHERE evidence_id=? ORDER BY created_at DESC LIMIT 1",
                (evidence_id,),
            ).fetchone()
        if not row:
            return None
        value = dict(row)
        value["hits"] = json.loads(value.pop("hits_json"))
        value["device"] = json.loads(value.pop("device_json", "{}") or "{}")
        return value

    def save_segments(self, evidence_id: str, segments: Iterable[Segment], mode: str) -> List[Dict[str, Any]]:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        values = list(segments)
        for segment in values:
            if segment.start_offset < 0 or segment.end_offset <= segment.start_offset or segment.end_offset > int(evidence["size"]):
                raise ValueError("segment physical range is outside the acquired evidence")
            payload_start = segment.payload_start_offset
            payload_end = segment.payload_end_offset
            if payload_start is not None or payload_end is not None:
                if payload_start is None or payload_end is None or not (segment.start_offset <= payload_start < payload_end <= segment.end_offset):
                    raise ValueError("segment payload range must be bounded by the physical segment range")
        persisted: List[Dict[str, Any]] = []
        with self._transaction() as connection:
            existing_rows = connection.execute(
                """SELECT * FROM segments
                   WHERE evidence_id=? AND recovery_mode=?""",
                (evidence_id, mode),
            ).fetchall()
            existing = {
                (row["start_offset"], row["end_offset"], row["codec"], row["source"]): row
                for row in existing_rows
            }
            inserted_count = 0
            for segment in values:
                key = (segment.start_offset, segment.end_offset, segment.codec, segment.source)
                previous = existing.get(key)
                if previous is not None:
                    value = dict(previous)
                    value["size"] = max(0, value["end_offset"] - value["start_offset"])
                    persisted.append(value)
                    continue
                created_at = segment.created_at or utc_now()
                connection.execute(
                    """INSERT INTO segments(id,evidence_id,vendor,source,recovery_mode,state,channel,start_offset,end_offset,codec,confidence,start_time,end_time,source_sha256,artifact_path,payload_start_offset,payload_end_offset,notes,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        segment.id,
                        evidence_id,
                        segment.vendor,
                        segment.source,
                        segment.recovery_mode,
                        segment.state,
                        segment.channel,
                        segment.start_offset,
                        segment.end_offset,
                        segment.codec,
                        segment.confidence,
                        segment.start_time,
                        segment.end_time,
                        segment.source_sha256,
                        segment.artifact_path,
                        segment.payload_start_offset,
                        segment.payload_end_offset,
                        segment.notes,
                        created_at,
                    ),
                )
                value = segment.to_dict()
                value["created_at"] = created_at
                persisted.append(value)
                existing[key] = value
                inserted_count += 1
            self._audit_in_transaction(
                connection,
                evidence["case_id"],
                "recovery_completed",
                {
                    "evidence_id": evidence_id,
                    "mode": mode,
                    "segment_count": len(persisted),
                    "inserted_count": inserted_count,
                    "segment_ids": [value["id"] for value in persisted],
                },
            )
        return persisted

    def save_analytics(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Persist an analytics run and append it to the custody chain."""
        evidence = self.get_evidence(result["evidence_id"])
        if not evidence:
            raise KeyError(f"Unknown evidence: {result['evidence_id']}")
        finding_id = result.get("id") or f"AN-{uuid.uuid4().hex[:12].upper()}"
        findings_json = json.dumps(result.get("findings", {}), sort_keys=True)
        findings_sha256 = hashlib.sha256(findings_json.encode("utf-8")).hexdigest()
        result = dict(result, id=finding_id, case_id=evidence["case_id"], findings_sha256=findings_sha256)
        with self._transaction() as connection:
            connection.execute(
                """INSERT INTO analytics_findings(id,case_id,evidence_id,segment_id,kind,status,model,started_at,completed_at,findings_json,notes)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding_id,
                    evidence["case_id"],
                    result["evidence_id"],
                    result["segment_id"],
                    result["kind"],
                    result["status"],
                    result.get("model", ""),
                    result["started_at"],
                    result["completed_at"],
                    findings_json,
                    result.get("notes", ""),
                ),
            )
            self._audit_in_transaction(
                connection,
                evidence["case_id"],
                "analytics_completed",
                {
                    "finding_id": finding_id,
                    "evidence_id": result["evidence_id"],
                    "segment_id": result["segment_id"],
                    "kind": result["kind"],
                    "status": result["status"],
                    "model": result.get("model", ""),
                    "findings_sha256": findings_sha256,
                    "source_sha256": result.get("findings", {}).get("source_range", {}).get("sha256"),
                    "media_sha256": result.get("findings", {}).get("media_artifact", {}).get("sha256"),
                },
            )
        return result

    def list_analytics(self, segment_id: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM analytics_findings WHERE segment_id=? ORDER BY completed_at DESC",
                (segment_id,),
            ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            findings_json = value.pop("findings_json")
            value["findings"] = json.loads(findings_json)
            value["findings_sha256"] = hashlib.sha256(findings_json.encode("utf-8")).hexdigest()
            values.append(value)
        return values

    def list_case_analytics(self, case_id: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM analytics_findings WHERE case_id=? ORDER BY completed_at DESC",
                (case_id,),
            ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            findings_json = value.pop("findings_json")
            value["findings"] = json.loads(findings_json)
            value["findings_sha256"] = hashlib.sha256(findings_json.encode("utf-8")).hexdigest()
            values.append(value)
        return values

    def list_segments(self, evidence_id: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM segments WHERE evidence_id=? ORDER BY start_offset, created_at",
                (evidence_id,),
            ).fetchall()
        values: List[Dict[str, Any]] = []
        for row in rows:
            value = dict(row)
            value["size"] = max(0, value["end_offset"] - value["start_offset"])
            values.append(value)
        return values

    def get_segment(self, segment_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM segments WHERE id=?", (segment_id,)).fetchone()
        if not row:
            return None
        value = dict(row)
        value["size"] = max(0, value["end_offset"] - value["start_offset"])
        return value

    # ---- chain of custody ---------------------------------------------
    def _audit_in_transaction(
        self, connection: sqlite3.Connection, case_id: str, action: str, details: Dict[str, Any], actor: str = "examiner"
    ) -> AuditEvent:
        occurred_at = utc_now()
        payload = {"case_id": case_id, "action": action, "actor": actor, "details": details}
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        row = connection.execute(
            "SELECT event_hash FROM audit_log WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)
        ).fetchone()
        previous_hash = row["event_hash"] if row else "GENESIS"
        event_hash = hashlib.sha256((previous_hash + payload_json).encode("utf-8")).hexdigest()
        cursor = connection.execute(
            """INSERT INTO audit_log(case_id,action,actor,occurred_at,payload_json,previous_hash,event_hash)
               VALUES(?,?,?,?,?,?,?)""",
            (case_id, action, actor, occurred_at, payload_json, previous_hash, event_hash),
        )
        return AuditEvent(
            id=int(cursor.lastrowid),
            case_id=case_id,
            action=action,
            actor=actor,
            occurred_at=occurred_at,
            payload=payload,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def record_audit(self, case_id: str, action: str, details: Dict[str, Any], actor: str = "examiner") -> Dict[str, Any]:
        """Append an externally visible action to the custody chain."""
        self.require_case(case_id)
        with self._transaction() as connection:
            event = self._audit_in_transaction(connection, case_id, action, details, actor)
        return event.to_dict()

    def audit_events(self, case_id: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["payload"] = json.loads(value.pop("payload_json"))
            result.append(value)
        return result

    def verify_chain(self, case_id: str) -> Dict[str, Any]:
        events = self.audit_events(case_id)
        previous = "GENESIS"
        for event in events:
            expected = hashlib.sha256(
                (previous + json.dumps(event["payload"], sort_keys=True, separators=(",", ":"))).encode("utf-8")
            ).hexdigest()
            if event["previous_hash"] != previous or event["event_hash"] != expected:
                return {"valid": False, "event_count": len(events), "broken_event_id": event["id"]}
            previous = event["event_hash"]
        return {"valid": True, "event_count": len(events), "head": previous}

    # ---- reports and export paths -------------------------------------
    def case_bundle(self, case_id: str) -> Dict[str, Any]:
        case = self.require_case(case_id)
        evidence = self.list_evidence(case_id)
        analytics = self.list_case_analytics(case_id)
        for item in evidence:
            item["identification"] = self.latest_identification(item["id"])
            item["segments"] = self.list_segments(item["id"])
            for segment in item["segments"]:
                segment["analytics"] = self.list_analytics(segment["id"])
            item["analytics"] = [finding for finding in analytics if finding["evidence_id"] == item["id"]]
        return {"case": case, "evidence": evidence, "audit": self.audit_events(case_id), "chain": self.verify_chain(case_id)}

    def export_path(self, case_id: str, segment_id: str, suffix: str) -> Path:
        directory = self.exports_dir / case_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{segment_id}{suffix}"

    def report_path(self, case_id: str, suffix: str) -> Path:
        directory = self.reports_dir / case_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"forensic-report{suffix}"


class _TeeReader:
    """Copy bytes while exposing a read method to ``hash_stream``."""

    def __init__(self, source: BinaryIO, destination: BinaryIO):
        self.source = source
        self.destination = destination

    def read(self, size: int = -1) -> bytes:
        block = self.source.read(size)
        if block:
            self.destination.write(block)
        return block
