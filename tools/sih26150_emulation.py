"""Run a reproducible SIH26150 end-to-end validation corpus.

This is a controlled recorder-image emulator, not a claim that a synthetic
file is an authorized field image. It uses a compact Annex-B H.264 SPS/PPS/IDR
sequence inside structurally validated DHAV frames, interleaves channels,
adds damaged/raw candidates, and runs acquisition, identification, recovery,
export, timeline, analytics-status, and reporting checks.

Run from the repository root:

    python3 tools/sih26150_emulation.py
"""

from __future__ import annotations

import argparse
import io
import json
import struct
import sys
import tempfile
from pathlib import Path
from typing import Dict, Tuple

# Allow ``python3 tools/sih26150_emulation.py`` from a source checkout without
# requiring the package to be installed first.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forensic_tool.analysis.engine import AnalysisEngine
from forensic_tool.exporter import export_segment
from forensic_tool.storage import EvidenceStore


# Compact Annex-B H.264 SPS/PPS/IDR NAL sequence. It is kept as bytes rather
# than a text marker so exports can be compared byte-for-byte with the source.
H264_SAMPLE = bytes.fromhex(
    "000000016742c01fda014016ec0440000003004000000f03c58b65"
    "0000000168ce3c80"
    "00000001658884000af26280"
)


def _packed_timestamp(year: int, month: int, day: int, hour: int, minute: int, second: int) -> int:
    return ((year - 2000) << 26) | (month << 22) | (day << 17) | (hour << 12) | (minute << 6) | second


def _dhav_frame(frame_number: int, channel: int, timestamp: Tuple[int, int, int, int, int, int], footer: bool = True) -> bytes:
    payload = H264_SAMPLE
    frame_size = 24 + len(payload) + (8 if footer else 0)
    header = (
        b"DHAV"
        + bytes([0xFD, 0x00, channel, 0x00])
        + struct.pack("<I", frame_number)
        + struct.pack("<I", frame_size)
        + struct.pack("<I", _packed_timestamp(*timestamp))
        + struct.pack("<H", 120)
        + b"\x00\x00"
    )
    return header + payload + (b"dhav" + struct.pack("<I", frame_size) if footer else b"")


def build_controlled_image() -> bytes:
    return (
        b"DAHUA\x00DHFS\x00model: NVR-5216-4KS2 firmware: V4.003.0000000.1.R\x00"
        + b"noise-before"
        + _dhav_frame(1, 1, (2024, 1, 2, 10, 20, 30))
        + b"corruption\x00\xff\x00"
        + _dhav_frame(2, 2, (2024, 1, 2, 10, 20, 31))
        + _dhav_frame(3, 1, (2024, 1, 2, 10, 20, 32), footer=False)
        + b"\x99\x88"
        + b"\x00\x00\x01\x67SPS-DELETED\x00\x00\x01\x65IDR-DELETED"
    )


def run(data_dir: str | Path | None = None) -> Dict[str, object]:
    temporary = tempfile.TemporaryDirectory(prefix="sih26150-") if data_dir is None else None
    root = Path(data_dir or temporary.name)  # type: ignore[union-attr]
    try:
        store = EvidenceStore(root / "data")
        case = store.create_case("SIH26150 controlled recorder emulation", "validation")
        source = build_controlled_image()
        evidence = store.ingest_stream(
            case["id"],
            io.BytesIO(source),
            "dahua-emulated.dd",
            source_kind="disk-image",
            sector_size=512,
            acquisition_method="streaming-bitstream-copy",
        )
        assert Path(evidence["absolute_path"]).read_bytes() == source
        assert store.verify_evidence(evidence["id"])["valid"]

        engine = AnalysisEngine(store)
        identity = engine.identify(evidence["id"])
        assert identity["primary_vendor"] == "dahua", identity
        assert "NVR-5216-4KS2" in identity["device"]["models"], identity["device"]
        assert any("4.003" in item for item in identity["device"]["firmware"]), identity["device"]

        normal = engine.recover(evidence["id"], "normal")
        assert len(normal["segments"]) == 3, normal
        assert [item["channel"] for item in normal["segments"]] == [1, 2, 1]
        assert all(0 <= item["start_offset"] < item["end_offset"] <= len(source) for item in normal["segments"])

        first = normal["segments"][0]
        native = export_segment(store, first["id"], "native")
        media = export_segment(store, first["id"], "media")
        assert Path(native["path"]).read_bytes() == source[first["start_offset"] : first["end_offset"]]
        assert Path(media["path"]).read_bytes() == H264_SAMPLE
        assert native["sha256"] == first["source_sha256"]
        assert media["payload_range"]["exact"] is True

        for mode in ("deleted", "overwritten", "fragmented", "unallocated"):
            result = engine.recover(evidence["id"], mode)
            assert result["segments"], mode
            assert all(0 <= item["start_offset"] < item["end_offset"] <= len(source) for item in result["segments"])

        timeline = engine.timeline(evidence["id"])
        assert len(timeline["events"]) >= 3
        assert timeline["events"][0]["start"]["utc"].startswith("2024-01-02T10:20:30")

        analytics_status = engine.analytics(first["id"], "object")["status"]
        assert analytics_status in {"not_configured", "unsupported"}
        bundle = store.case_bundle(case["id"])
        assert bundle["chain"]["valid"], bundle["chain"]
        return {
            "case_id": case["id"],
            "image_bytes": len(source),
            "sha256": evidence["sha256"],
            "vendor": identity["primary_vendor"],
            "model_candidates": identity["device"]["models"],
            "firmware_candidates": identity["device"]["firmware"],
            "normal_segments": len(normal["segments"]),
            "payload_bytes": media["size"],
            "analytics_object_status": analytics_status,
            "chain_events": bundle["chain"]["event_count"],
            "chain_valid": bundle["chain"]["valid"],
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", help="retain the emulation case under this directory")
    args = parser.parse_args()
    print(json.dumps(run(args.data_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
