"""Evidence-preserving segment export.

Native export is always available and copies the exact source range.  MP4
conversion is optional and only attempted through an installed ffmpeg binary;
the source range remains the primary artifact and is never overwritten.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional

from .storage import EvidenceStore, utc_now


class ExportError(RuntimeError):
    pass


def _suffix_for(codec: str) -> str:
    return {"H.264": ".h264", "H.265": ".h265", "MPEG-PS": ".mpg", "DHAV": ".dav"}.get(codec, ".bin")


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def export_segment(store: EvidenceStore, segment_id: str, output_format: str = "native") -> Dict[str, object]:
    segment = store.get_segment(segment_id)
    if not segment:
        raise KeyError(f"Unknown segment: {segment_id}")
    evidence = store.get_evidence(segment["evidence_id"])
    if not evidence:
        raise KeyError(f"Unknown evidence: {segment['evidence_id']}")
    if output_format not in {"native", "mp4"}:
        raise ValueError("output_format must be native or mp4")

    native_path = store.export_path(evidence["case_id"], segment_id, _suffix_for(segment["codec"]))
    if not native_path.exists() or native_path.stat().st_size != segment["size"]:
        reader = store.evidence_reader(evidence["id"])
        with native_path.open("wb") as output:
            copied = reader.read_range_to(segment["start_offset"], segment["size"], output)
        if copied != segment["size"]:
            raise ExportError("Source ended before the complete segment range was copied")
        try:
            native_path.chmod(0o440)
        except OSError:
            pass
    native_hash = _hash_path(native_path)
    if output_format == "native":
        return {
            "segment_id": segment_id,
            "format": "native",
            "path": str(native_path),
            "filename": native_path.name,
            "sha256": native_hash,
            "content_type": _content_type(native_path.suffix),
            "size": native_path.stat().st_size,
            "note": "Exact physical source range copied without transcoding.",
        }

    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise ExportError("MP4 export requires ffmpeg; exact native export is available")
    mp4_path = store.export_path(evidence["case_id"], segment_id, ".mp4")
    command = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-i", str(native_path), "-map", "0", "-c", "copy", str(mp4_path)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0 or not mp4_path.exists():
        raise ExportError(completed.stderr.strip() or "ffmpeg could not remux this native stream")
    try:
        mp4_path.chmod(0o440)
    except OSError:
        pass
    return {
        "segment_id": segment_id,
        "format": "mp4",
        "path": str(mp4_path),
        "filename": mp4_path.name,
        "sha256": _hash_path(mp4_path),
        "content_type": "video/mp4",
        "size": mp4_path.stat().st_size,
        "native_sha256": native_hash,
        "note": "Container remuxed with ffmpeg; native source-range artifact is retained beside it.",
    }


def _content_type(suffix: str) -> str:
    return {
        ".h264": "video/h264",
        ".h265": "video/h265",
        ".mpg": "video/mpeg",
        ".dav": "application/octet-stream",
    }.get(suffix, "application/octet-stream")
