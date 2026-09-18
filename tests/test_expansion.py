from __future__ import annotations

import io
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from forensic_tool.analysis.analytics import run_analytics
from forensic_tool.analysis.device import identify_device
from forensic_tool.analysis.engine import AnalysisEngine
from forensic_tool.analysis.timeline import build_timeline, normalize_timestamp
from forensic_tool.exporter import export_segment
from forensic_tool.models import Segment
from forensic_tool.reader import EvidenceReader
from forensic_tool.reporting import build_report
from forensic_tool.storage import EvidenceStore, utc_now


class ExpansionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "data"
        self.store = EvidenceStore(self.root)
        self.case = self.store.create_case("Expansion workflow", "Examiner")
        self.engine = AnalysisEngine(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_acquisition_metadata_and_integrity_event(self):
        evidence = self.store.ingest_stream(
            self.case["id"],
            io.BytesIO(b"sector evidence"),
            "disk.dd",
            source_kind="physical-disk",
            sector_size=4096,
            acquisition_method="sector-copy",
        )
        self.assertEqual(evidence["source_kind"], "physical-disk")
        self.assertEqual(evidence["sector_size"], 4096)
        self.assertEqual(evidence["acquisition_method"], "sector-copy")
        verification = self.store.verify_evidence(evidence["id"])
        self.assertTrue(verification["valid"])
        self.assertTrue(any(event["action"] == "evidence_integrity_verified" for event in self.store.audit_events(self.case["id"])))

    def test_device_candidates_are_bounded_and_do_not_promote_magic(self):
        raw = b"model: NVR-5216-4KS2 firmware: V4.003.0000000.1.R\x00" + "Model: IPC-2CD2043".encode("utf-16le")
        path = Path(self.temp.name) / "metadata.bin"
        path.write_bytes(raw)
        result = identify_device(EvidenceReader(path))
        self.assertIn("NVR-5216-4KS2", result["models"])
        self.assertTrue(any("4.003" in item for item in result["firmware"]))
        self.assertNotIn("DHAV", result["models"])
        self.assertLessEqual(len(result["markers"]), 64)

    def test_dhav_payload_export_retains_native_source_range(self):
        payload = b"\x00\x00\x01\x67SPS\x00\x00\x01\x65FRAME"
        packed_date = ((2024 - 2000) << 26) | (1 << 22) | (5 << 17) | (10 << 12) | (11 << 6) | 12
        frame_size = 24 + len(payload) + 8
        frame = (
            b"DHAV" + bytes([0xFD, 0, 2, 0]) + struct.pack("<I", 9) + struct.pack("<I", frame_size)
            + struct.pack("<I", packed_date) + struct.pack("<H", 42) + b"\0\0" + payload + b"dhav" + struct.pack("<I", frame_size)
        )
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(b"prefix" + frame + b"tail"), "camera.dav")
        result = self.engine.recover(evidence["id"])
        segment = result["segments"][0]
        media = export_segment(self.store, segment["id"], "media")
        self.assertEqual(Path(media["path"]).read_bytes(), payload)
        self.assertEqual(media["payload_range"], {"start_offset": segment["payload_start_offset"], "end_offset": segment["payload_end_offset"], "exact": True})
        native = export_segment(self.store, segment["id"], "native")
        source = Path(evidence["absolute_path"]).read_bytes()
        self.assertEqual(Path(native["path"]).read_bytes(), source[segment["start_offset"]:segment["end_offset"]])
        self.assertNotEqual(native["sha256"], media["sha256"])

    def test_timestamp_normalization_and_cross_camera_correlation(self):
        self.assertEqual(normalize_timestamp("2024-01-01T00:00:00")["assumption"], "timezone_not_present_assumed_utc")
        segments = [
            {"id": "A", "evidence_id": "E1", "channel": 1, "state": "indexed", "codec": "H.264", "start_offset": 10, "end_offset": 20, "size": 10, "source_sha256": "a" , "start_time": "2024-01-01T00:00:00Z", "end_time": None},
            {"id": "B", "evidence_id": "E2", "channel": 2, "state": "indexed", "codec": "H.264", "start_offset": 30, "end_offset": 40, "size": 10, "source_sha256": "b" , "start_time": "2024-01-01T00:00:01Z", "end_time": None},
            {"id": "C", "evidence_id": "E3", "channel": 3, "state": "fragment", "codec": "H.264", "start_offset": 50, "end_offset": 60, "size": 10, "source_sha256": "c" , "start_time": None, "end_time": None},
        ]
        timeline = build_timeline(segments, tolerance_seconds=2)
        self.assertEqual(len(timeline["correlations"]), 1)
        self.assertEqual(timeline["correlations"][0]["channels"], [1, 2])
        self.assertIsNone(next(item for item in timeline["events"] if item["event_id"] == "C")["correlation_id"])

    def test_analytics_never_fabricates_without_object_model(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(b"not a video\x00\x00\x01\x65frame"), "raw.bin")
        recovered = self.engine.recover(evidence["id"])
        self.assertTrue(recovered["segments"])
        result = run_analytics(self.store, recovered["segments"][0]["id"], "object")
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["findings"]["items"], [])
        self.assertEqual(self.store.list_analytics(recovered["segments"][0]["id"])[0]["id"], result["id"])

    def test_recovery_modes_keep_deleted_overwritten_fragmented_and_unallocated_labels(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(b"\x00\x00\x01\x65frame"), "raw.bin")
        for mode, expected in (("deleted", "deleted_candidate"), ("overwritten", "overwritten_candidate"), ("fragmented", "fragment"), ("unallocated", "unallocated_candidate")):
            result = self.engine.recover(evidence["id"], mode)
            self.assertTrue(result["segments"])
            self.assertEqual(result["segments"][0]["state"], expected)

    def test_report_contains_review_checklist_and_analytics_limitations(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(b"\x00\x00\x01\x65frame"), "raw.bin")
        result = self.engine.recover(evidence["id"])
        run_analytics(self.store, result["segments"][0]["id"], "face")
        report = build_report(self.store, self.case["id"])
        self.assertTrue(any(item["status"] == "not_determined_by_tool" for item in report["admissibility_review_checklist"]))
        self.assertIn("analytics", report)
        self.assertTrue(any("not_configured" == item["status"] or "unsupported" == item["status"] for item in report["analytics"]))
        self.assertIn("physical byte ranges", " ".join(report["interpretation"]))

    def test_existing_database_migration_adds_new_columns_and_table(self):
        legacy_root = Path(self.temp.name) / "legacy"
        legacy_root.mkdir()
        db = legacy_root / "sentinel.sqlite3"
        connection = sqlite3.connect(db)
        connection.executescript(
            """
            CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT NOT NULL, investigator TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open');
            CREATE TABLE evidence (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, original_name TEXT NOT NULL, storage_path TEXT NOT NULL, size INTEGER NOT NULL, md5 TEXT NOT NULL, sha256 TEXT NOT NULL, acquired_at TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'disk-image', read_only INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE identifications (id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, primary_vendor TEXT NOT NULL, confidence REAL NOT NULL, hits_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE segments (id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, vendor TEXT NOT NULL, source TEXT NOT NULL, recovery_mode TEXT NOT NULL, state TEXT NOT NULL, channel INTEGER, start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, codec TEXT NOT NULL, confidence REAL NOT NULL, start_time TEXT, end_time TEXT, source_sha256 TEXT, artifact_path TEXT, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
            CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
            """
        )
        connection.commit()
        connection.close()
        migrated = EvidenceStore(legacy_root)
        with migrated._connect() as check:
            evidence_columns = {row[1] for row in check.execute("PRAGMA table_info(evidence)")}
            identification_columns = {row[1] for row in check.execute("PRAGMA table_info(identifications)")}
            segment_columns = {row[1] for row in check.execute("PRAGMA table_info(segments)")}
            tables = {row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"source_kind", "acquisition_method", "sector_size"} <= evidence_columns)
        self.assertIn("device_json", identification_columns)
        self.assertTrue({"payload_start_offset", "payload_end_offset"} <= segment_columns)
        self.assertIn("analytics_findings", tables)


if __name__ == "__main__":
    unittest.main()
