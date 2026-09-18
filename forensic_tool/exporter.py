"""Evidence-preserving native, demuxed-payload, and optional MP4 export."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Dict

from .storage import EvidenceStore


class ExportError(RuntimeError):
    pass


def _suffix_for(codec: str) -> str:
    return {
        "H.264": ".h264",
        "H.265": ".h265",
        "MPEG-PS": ".mpg",
        "DHAV": ".dav",
        "DHAV-audio": ".audio",
    }.get(codec, ".bin")


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ffmpeg_executable() -> tuple[str | None, str | None]:
    """Return a system FFmpeg or the packaged imageio-ffmpeg executable."""
    system = shutil.which("ffmpeg")
    if system:
        return system, "system-ffmpeg"
    try:
        import imageio_ffmpeg  # type: ignore

        executable = imageio_ffmpeg.get_ffmpeg_exe()
        return executable, "imageio-ffmpeg"
    except Exception:
        return None, None


def _atomic_copy_range(store: EvidenceStore, evidence_id: str, start: int, length: int, destination: Path) -> int:
    reader = store.evidence_reader(evidence_id)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    copied = 0
    try:
        with temporary.open("wb") as output:
            copied = reader.read_range_to(start, length, output)
            output.flush()
            os.fsync(output.fileno())
        try:
            temporary.chmod(0o440)
        except OSError:
            pass
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass
    return copied


def _ensure_native(store: EvidenceStore, evidence: Dict[str, object], segment: Dict[str, object]) -> Dict[str, object]:
    suffix = _suffix_for(str(segment["codec"]))
    path = store.export_path(str(evidence["case_id"]), str(segment["id"]), suffix)
    size = int(segment["size"])
    if not path.exists() or path.stat().st_size != size:
        copied = _atomic_copy_range(store, str(evidence["id"]), int(segment["start_offset"]), size, path)
        if copied != size:
            raise ExportError("Source ended before the complete segment range was copied")
    native_hash = _hash_path(path)
    expected_hash = segment.get("source_sha256")
    if expected_hash and native_hash != expected_hash:
        raise ExportError("Native export hash does not match the recorded source-range hash")
    return {
        "path": path,
        "sha256": native_hash,
        "size": path.stat().st_size,
        "filename": path.name,
        "content_type": _content_type(path.suffix),
    }


def _ensure_media(store: EvidenceStore, evidence: Dict[str, object], segment: Dict[str, object], native: Dict[str, object]) -> Dict[str, object]:
    start = segment.get("payload_start_offset")
    end = segment.get("payload_end_offset")
    exact_payload = isinstance(start, int) and isinstance(end, int) and int(end) > int(start)
    if not exact_payload:
        start, end = int(segment["start_offset"]), int(segment["end_offset"])
    suffix = _suffix_for(str(segment["codec"]))
    path = store.export_path(str(evidence["case_id"]), str(segment["id"]), f".payload{suffix}")
    size = int(end) - int(start)
    if not path.exists() or path.stat().st_size != size:
        copied = _atomic_copy_range(store, str(evidence["id"]), int(start), size, path)
        if copied != size:
            raise ExportError("Source ended before the complete media payload was copied")
    return {
        "path": path,
        "sha256": _hash_path(path),
        "size": path.stat().st_size,
        "filename": path.name,
        "content_type": _content_type(path.suffix),
        "payload_range": {"start_offset": int(start), "end_offset": int(end), "exact": exact_payload},
        "native_sha256": native["sha256"],
    }


def export_segment(store: EvidenceStore, segment_id: str, output_format: str = "native") -> Dict[str, object]:
    """Export one recovered range without changing the source evidence.

    ``native`` is the exact physical range. ``media`` strips a known container
    header/footer when the parser supplied payload offsets. ``mp4`` remuxes the
    media payload only when ffmpeg is available; native and payload artifacts
    remain available independently.
    """

    segment = store.get_segment(segment_id)
    if not segment:
        raise KeyError(f"Unknown segment: {segment_id}")
    evidence = store.get_evidence(segment["evidence_id"])
    if not evidence:
        raise KeyError(f"Unknown evidence: {segment['evidence_id']}")
    if not isinstance(output_format, str) or output_format not in {"native", "media", "mp4"}:
        raise ValueError("output_format must be native, media, or mp4")

    native = _ensure_native(store, evidence, segment)
    if output_format == "native":
        result = {
            "segment_id": segment_id,
            "format": "native",
            "path": str(native["path"]),
            "filename": native["filename"],
            "sha256": native["sha256"],
            "content_type": native["content_type"],
            "size": native["size"],
            "note": "Exact physical source range copied without transcoding.",
        }
        return _record_export(store, evidence, result)

    media = _ensure_media(store, evidence, segment, native)
    if output_format == "media":
        result = {
            "segment_id": segment_id,
            "format": "media",
            "path": str(media["path"]),
            "filename": media["filename"],
            "sha256": media["sha256"],
            "content_type": media["content_type"],
            "size": media["size"],
            "native_sha256": media["native_sha256"],
            "payload_range": media["payload_range"],
            "note": (
                "Parser-bounded container payload copied without transcoding; exact native range is retained separately."
                if media["payload_range"]["exact"]
                else "No parser payload boundary was available; the full bounded candidate was copied as media bytes. Exact native range is retained separately."
            ),
        }
        return _record_export(store, evidence, result)

    ffmpeg, ffmpeg_runtime = _ffmpeg_executable()
    if not ffmpeg:
        raise ExportError("MP4 export requires a system or packaged FFmpeg runtime; exact native and media exports are available")
    mp4_path = store.export_path(str(evidence["case_id"]), segment_id, ".mp4")
    # Keep an .mp4 suffix so ffmpeg selects a container for the temporary
    # output; it is atomically renamed to the final artifact afterwards.
    temporary = mp4_path.with_name(f".{mp4_path.stem}.{uuid.uuid4().hex}.mp4")
    command = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-i", str(media["path"]), "-map", "0", "-c", "copy", str(temporary)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if completed.returncode != 0 or not temporary.exists():
            raise ExportError(completed.stderr.strip() or "ffmpeg could not remux this media payload")
        try:
            temporary.chmod(0o440)
        except OSError:
            pass
        os.replace(temporary, mp4_path)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass
    return _record_export(store, evidence, {
        "segment_id": segment_id,
        "format": "mp4",
        "path": str(mp4_path),
        "filename": mp4_path.name,
        "sha256": _hash_path(mp4_path),
        "content_type": "video/mp4",
        "size": mp4_path.stat().st_size,
        "native_sha256": native["sha256"],
        "media_sha256": media["sha256"],
        "note": f"Container remuxed with {ffmpeg_runtime or 'FFmpeg'}; native and demuxed source artifacts are retained.",
    })


def _record_export(store: EvidenceStore, evidence: Dict[str, object], result: Dict[str, object]) -> Dict[str, object]:
    """Record derived-artifact creation even when the library is used directly."""
    store.record_audit(str(evidence["case_id"]), "segment_exported", {
        "segment_id": result["segment_id"],
        "format": result["format"],
        "filename": result["filename"],
        "sha256": result["sha256"],
        "size": result["size"],
        "native_sha256": result.get("native_sha256"),
        "media_sha256": result.get("media_sha256"),
        "payload_range": result.get("payload_range"),
    })
    return result


def _content_type(suffix: str) -> str:
    return {
        ".h264": "video/h264",
        ".h265": "video/h265",
        ".mpg": "video/mpeg",
        ".dav": "application/octet-stream",
        ".audio": "application/octet-stream",
    }.get(suffix, "application/octet-stream")
