from __future__ import annotations

import io
import struct
import tempfile
import unittest
from pathlib import Path

from forensic_tool.analysis.detector import detect
from forensic_tool.analysis.engine import AnalysisEngine
from forensic_tool.exporter import export_segment
from forensic_tool.reader import EvidenceReader
from forensic_tool.reporting import build_report, render_pdf, write_report
from forensic_tool.storage import EvidenceStore


def annex_b_stream() -> bytes:
    return (
        b"\x00\x00\x00\x01\x67\x42\x00\x1eSPS"
        b"\x00\x00\x01\x68\xce\x3cPPS"
        b"\x00\x00\x00\x01\x65\x88IDRFRAME"
        b"\x00\x00\x01\x61\x9aPFRAME"
    )


def h265_annex_b_stream() -> bytes:
    return (
        b"\x00\x00\x01\x40VPS"
        b"\x00\x00\x01\x42SPS"
        b"\x00\x00\x01\x44PPS"
        b"\x00\x00\x01\x26IDRFRAME"
        b"\x00\x00\x01\x02PFRAME"
    )


class CoreSystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.temp.name) / "data")
        self.case = self.store.create_case("Station road incident", "A. Examiner")
        self.engine = AnalysisEngine(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_acquisition_hashes_and_read_only_metadata(self):
        source = b"raw-recorder-image" + annex_b_stream()
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(source), "drive 01.img")
        self.assertEqual(evidence["size"], len(source))
        self.assertEqual(evidence["read_only"], True)
        self.assertEqual(Path(evidence["absolute_path"]).read_bytes(), source)
        self.assertEqual(len(evidence["md5"]), 32)
        self.assertEqual(len(evidence["sha256"]), 64)
        self.assertTrue(self.store.verify_chain(self.case["id"])["valid"])

    def test_hikvision_identification_and_raw_recovery(self):
        source = b"prefix" + b"HIKVISION@HANGZHOU" + b"HIKBTREE" + annex_b_stream()
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(source), "hikvision.raw")
        identity = self.engine.identify(evidence["id"])
        self.assertEqual(identity["primary_vendor"], "hikvision")
        self.assertGreaterEqual(identity["confidence"], 0.9)
        result = self.engine.recover(evidence["id"], "normal")
        self.assertGreaterEqual(result["segment_count"], 1)
        segment = result["segments"][0]
        self.assertEqual(segment["codec"], "H.264")
        self.assertGreater(segment["size"], 10)
        self.assertEqual(len(segment["source_sha256"]), 64)
        self.assertIn("wall-clock", segment["notes"])

    def test_h265_is_not_reported_as_duplicate_h264(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(h265_annex_b_stream()), "camera.h265")
        result = self.engine.recover(evidence["id"], "normal")
        self.assertEqual(result["segment_count"], 1)
        self.assertEqual(result["segments"][0]["codec"], "H.265")

    def test_dahua_bounded_block_parser(self):
        payload = annex_b_stream()
        timestamp_ms = 1700000000000
        block_size = 32 + len(payload)
        header = b"DHAV" + struct.pack("<I", block_size) + struct.pack("<I", 3) + struct.pack("<Q", timestamp_ms) + b"\0" * 12
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(b"DHFS4.1" + header + payload), "dahua.dav")
        identity = self.engine.identify(evidence["id"])
        self.assertEqual(identity["primary_vendor"], "dahua")
        result = self.engine.recover(evidence["id"], "normal")
        self.assertGreaterEqual(result["segment_count"], 1)
        parsed = result["segments"][0]
        self.assertEqual(parsed["source"], "dhav_parser")
        self.assertEqual(parsed["channel"], 3)
        self.assertTrue(parsed["start_time"].startswith("2023-11"))

    def test_deleted_and_lost_modes_are_recorded(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(annex_b_stream()), "unknown.bin")
        deleted = self.engine.recover(evidence["id"], "deleted")
        lost = self.engine.recover(evidence["id"], "lost_corrupted")
        self.assertTrue(deleted["segment_count"])
        self.assertTrue(lost["segment_count"])
        states = {item["state"] for item in self.store.list_segments(evidence["id"])}
        self.assertIn("deleted_candidate", states)
        self.assertIn("fragment", states)

    def test_repeated_recovery_does_not_duplicate_ranges(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(annex_b_stream()), "repeat.bin")
        first = self.engine.recover(evidence["id"], "normal")
        second = self.engine.recover(evidence["id"], "normal")
        self.assertEqual(first["segment_count"], second["segment_count"])
        self.assertEqual(len(self.store.list_segments(evidence["id"])), first["segment_count"])
        self.assertEqual(first["segments"][0]["id"], second["segments"][0]["id"])

    def test_native_export_is_exact_source_range(self):
        source = b"padding" + annex_b_stream() + b"tail"
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(source), "sample.bin")
        result = self.engine.recover(evidence["id"])
        segment = result["segments"][0]
        exported = export_segment(self.store, segment["id"], "native")
        self.assertEqual(Path(exported["path"]).read_bytes(), source[segment["start_offset"]:segment["end_offset"]])
        self.assertEqual(exported["sha256"], segment["source_sha256"])

    def test_report_has_a_valid_pdf_and_chain(self):
        evidence = self.store.ingest_stream(self.case["id"], io.BytesIO(b"HONEYWELL" + annex_b_stream()), "honeywell.bin")
        self.engine.identify(evidence["id"])
        self.engine.recover(evidence["id"], "deleted")
        report = write_report(self.store, self.case["id"])
        pdf = Path(report["pdf"]).read_bytes()
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertTrue(self.store.verify_chain(self.case["id"])["valid"])
        self.assertIn("SENTINEL", render_pdf(build_report(self.store, self.case["id"])).decode("latin-1"))

    def test_cross_chunk_signature_search(self):
        source_path = Path(self.temp.name) / "boundary.img"
        source_path.write_bytes(b"A" * (4 * 1024 * 1024 - 3) + b"HIKBTREE" + b"B")
        reader = EvidenceReader(source_path)
        self.assertEqual(reader.find_all(b"HIKBTREE"), [4 * 1024 * 1024 - 3])
        self.assertEqual(reader.find_signatures({"hik": b"HIKBTREE", "annex": b"\x00\x00\x01"})["hik"], [4 * 1024 * 1024 - 3])
        result = detect(reader)
        self.assertEqual(result.primary.vendor, "hikvision")

    def test_chain_detects_tampering(self):
        self.store.ingest_stream(self.case["id"], io.BytesIO(b"one"), "one.img")
        with self.store._connect() as connection:
            connection.execute("UPDATE audit_log SET payload_json='{}' WHERE id=1")
        self.assertFalse(self.store.verify_chain(self.case["id"])["valid"])


if __name__ == "__main__":
    unittest.main()
