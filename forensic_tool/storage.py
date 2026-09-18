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
    read_only INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE TABLE IF NOT EXISTS identifications (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    primary_vendor TEXT NOT NULL,
    confidence REAL NOT NULL,
    hits_json TEXT NOT NULL,
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
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_segments_evidence ON segments(evidence_id, start_offset);
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
    ) -> Dict[str, Any]:
        self.require_case(case_id)
        source_path = Path(source_path).expanduser().resolve()
        if not source_path.is_file():
            raise FileNotFoundError(f"Source file not found: {source_path}")
        with source_path.open("rb") as stream:
            return self._ingest_stream(case_id, stream, original_name or source_path.name, source)

    def ingest_stream(
        self,
        case_id: str,
        stream: BinaryIO,
        original_name: str,
        source: str = "disk-image",
    ) -> Dict[str, Any]:
        self.require_case(case_id)
        return self._ingest_stream(case_id, stream, original_name, source)

    def _ingest_stream(
        self, case_id: str, stream: BinaryIO, original_name: str, source: str
    ) -> Dict[str, Any]:
        evidence_id = f"EVD-{uuid.uuid4().hex[:12].upper()}"
        safe_name = _safe_name(original_name)
        case_dir = self.evidence_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        destination = case_dir / f"{evidence_id}_{safe_name}"
        try:
            with destination.open("wb") as output:
                digest = hash_stream(_TeeReader(stream, output))
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
                    """INSERT INTO evidence(id,case_id,original_name,storage_path,size,md5,sha256,acquired_at,source,read_only)
                       VALUES(?,?,?,?,?,?,?,?,?,1)""",
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

    # ---- analysis result persistence ----------------------------------
    def save_identification(self, evidence_id: str, primary_vendor: str, confidence: float, hits: List[VendorHit]) -> Dict[str, Any]:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        identification_id = f"ID-{uuid.uuid4().hex[:12].upper()}"
        created_at = utc_now()
        hit_values = [hit.to_dict() for hit in hits]
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO identifications(id,evidence_id,primary_vendor,confidence,hits_json,created_at) VALUES(?,?,?,?,?,?)",
                (identification_id, evidence_id, primary_vendor, confidence, json.dumps(hit_values, sort_keys=True), created_at),
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
                },
            )
        return {
            "id": identification_id,
            "evidence_id": evidence_id,
            "primary_vendor": primary_vendor,
            "confidence": confidence,
            "hits": hit_values,
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
        return value

    def save_segments(self, evidence_id: str, segments: Iterable[Segment], mode: str) -> List[Dict[str, Any]]:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        values = list(segments)
        with self._transaction() as connection:
            for segment in values:
                connection.execute(
                    """INSERT INTO segments(id,evidence_id,vendor,source,recovery_mode,state,channel,start_offset,end_offset,codec,confidence,start_time,end_time,source_sha256,artifact_path,notes,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                        segment.notes,
                        segment.created_at or utc_now(),
                    ),
                )
            self._audit_in_transaction(
                connection,
                evidence["case_id"],
                "recovery_completed",
                {
                    "evidence_id": evidence_id,
                    "mode": mode,
                    "segment_count": len(values),
                    "segment_ids": [segment.id for segment in values],
                },
            )
        return [segment.to_dict() for segment in values]

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
        for item in evidence:
            item["identification"] = self.latest_identification(item["id"])
            item["segments"] = self.list_segments(item["id"])
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
