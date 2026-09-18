"""Vendor adapters and safe fallback routes.

These adapters are intentionally explicit about validation level.  A marker
match is not promoted to a courtroom conclusion; it is a route into a parser
and every recovered segment retains its physical provenance.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional, Sequence

from ..reader import EvidenceReader
from .carving import CarvedRange, carve_annex_b, detect_codec


@dataclass
class Candidate:
    start_offset: int
    end_offset: int
    source: str
    state: str
    codec: str
    confidence: float
    channel: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    notes: str = ""

    @property
    def size(self) -> int:
        return max(0, self.end_offset - self.start_offset)


def _iso_timestamp(value: int, milliseconds: bool = True) -> Optional[str]:
    if value <= 0:
        return None
    seconds = value / 1000 if milliseconds else value
    # Recorder metadata that is outside a sane forensic date range is almost
    # certainly a length or reserved field, not a timestamp.
    if seconds < 63072000 or seconds > 4102444800:  # 1972 .. 2100
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _dhav_date_to_iso(date_value: int, milliseconds: int = 0) -> Optional[str]:
    """Decode the packed 32-bit DHAV date used by FFmpeg's demuxer."""

    second = date_value & 0x3F
    minute = (date_value >> 6) & 0x3F
    hour = (date_value >> 12) & 0x1F
    day = (date_value >> 17) & 0x1F
    month = (date_value >> 22) & 0x0F
    year = ((date_value >> 26) & 0x3F) + 2000
    if not (2000 <= year <= 2063 and 1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60):
        return None
    try:
        value = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        # DHAV's 16-bit timestamp is a sub-second counter on common variants;
        # preserve it only when it is a plausible millisecond value.
        if 0 <= milliseconds < 1000:
            value = value.replace(microsecond=milliseconds * 1000)
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except ValueError:
        return None


def _next_marker(reader: EvidenceReader, markers: Sequence[int], current: int, default_tail: int = 4 * 1024 * 1024) -> int:
    for offset in markers:
        if offset > current:
            return offset
    return min(reader.size, current + default_tail)


def _dedupe_candidates(candidates: Iterable[Candidate]) -> List[Candidate]:
    result: List[Candidate] = []
    seen = set()
    for candidate in sorted(candidates, key=lambda value: (value.start_offset, -value.confidence, value.end_offset)):
        key = (candidate.start_offset, candidate.end_offset, candidate.codec)
        if key in seen or candidate.end_offset <= candidate.start_offset:
            continue
        seen.add(key)
        result.append(candidate)
    return result


def _carve_candidates(reader: EvidenceReader, mode: str) -> List[Candidate]:
    suffix = {
        "normal": "The bytes are not indexed by a recognised parser.",
        "deleted": "Carved candidate from raw bytes; deletion state is a hypothesis until corroborated by recorder metadata.",
        "lost_corrupted": "Fragment candidate from raw bytes; physical continuity and wall-clock time are not established.",
    }.get(mode, "Raw bytes carved without an index.")
    candidates: List[Candidate] = []
    for item in carve_annex_b(reader):
        candidates.append(
            Candidate(
                start_offset=item.start_offset,
                end_offset=item.end_offset,
                source="annexb_carve",
                state={"normal": "unindexed", "deleted": "deleted_candidate", "lost_corrupted": "fragment"}.get(mode, "unindexed"),
                codec=item.codec,
                confidence=item.confidence,
                notes=f"{item.notes} {suffix}",
            )
        )
    return candidates


class BaseParser:
    route = "generic_tier2"

    def parse(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        return _carve_candidates(reader, mode)


class DahuaParser(BaseParser):
    route = "dahua_dhav"

    def parse(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        blocks = self._parse_dhav_blocks(reader, mode)
        # A deep/deleted pass still scans gaps because circular recording can
        # leave valid frames after an index block has been reused.
        carved = _carve_candidates(reader, mode)
        if blocks and mode == "normal":
            return _dedupe_candidates(blocks)
        return _dedupe_candidates([*blocks, *carved])

    def _parse_dhav_blocks(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        found = reader.find_signatures(
            {"upper": b"DHAV", "lower": b"dhav"},
            max_hits=100_000,
        )
        offsets = sorted(found["upper"])
        headers = reader.read_many(offsets, 64)
        # Resolve all footer checks with one open/read pass instead of opening
        # the evidence file once per DHAV frame.
        footer_offsets: List[int] = []
        for index, offset in enumerate(offsets):
            header = headers.get(offset, b"")
            if len(header) < 24:
                continue
            frame_length = struct.unpack_from("<I", header, 12)[0]
            next_magic = offsets[index + 1] if index + 1 < len(offsets) else reader.size
            declared_end = offset + frame_length
            if 32 <= frame_length <= min(256 * 1024 * 1024, reader.size - offset) and next_magic >= declared_end:
                footer_offsets.append(declared_end - 8)
        footers = reader.read_many(footer_offsets, 4)
        candidates: List[Candidate] = []
        for index, offset in enumerate(offsets):
            header = headers.get(offset, b"")
            if len(header) < 24:
                continue

            frame_type = header[4]
            channel = int(header[6])
            frame_length = struct.unpack_from("<I", header, 12)[0]
            packed_date = struct.unpack_from("<I", header, 16)[0]
            timestamp_ms = struct.unpack_from("<H", header, 20)[0]
            extension_length = header[22]
            next_magic = offsets[index + 1] if index + 1 < len(offsets) else reader.size

            # DHAV's current/common frame layout is:
            # magic, type/subtype, channel/subchannel, frame number, total
            # frame length, packed date, 16-bit sub-second timestamp, extension
            # length/checksum, payload, and an eight-byte footer beginning with
            # lowercase ``dhav``.  Validate both the declared range and footer
            # when present; a damaged/deleted frame may still be returned as a
            # bounded candidate without the footer.
            declared_end = offset + frame_length
            length_valid = 32 <= frame_length <= min(256 * 1024 * 1024, reader.size - offset)
            # A subsequent DHAV header before the declared end is strong
            # evidence that the length field was damaged or belongs to a
            # different firmware layout.  Do not let that frame consume its
            # neighbours.
            length_conflict = length_valid and next_magic < declared_end
            length_valid = length_valid and not length_conflict
            end = declared_end if length_valid else min(next_magic, offset + 4 * 1024 * 1024)
            footer_valid = False
            if length_valid and end - offset >= 8:
                footer_valid = footers.get(end - 8, b"") == b"dhav"
            if not length_valid:
                confidence = 0.48
                state = "container_candidate"
                note = "DHAV marker found without a trusted frame length; bounded to the next marker."
            elif footer_valid:
                confidence = 0.96
                state = "indexed"
                note = "DHAV frame length and lowercase footer validated."
            else:
                confidence = 0.78
                state = "container_candidate"
                note = "DHAV frame length is plausible but the validation footer is missing or damaged."
            if end <= offset + 24:
                continue

            payload_offset = min(end, offset + 24 + extension_length)
            codec = detect_codec(reader, payload_offset, min(64 * 1024, end - payload_offset))
            if codec == "unknown":
                codec = "DHAV-audio" if frame_type in {0xF0, 0xF1} else "DHAV"
            timestamp = _dhav_date_to_iso(packed_date, timestamp_ms)
            candidates.append(
                Candidate(
                    start_offset=offset,
                    end_offset=end,
                    source="dhav_parser",
                    state=state,
                    codec=codec,
                    confidence=confidence,
                    channel=channel if channel < 256 else None,
                    start_time=timestamp,
                    notes=(
                        f"DHAV type 0x{frame_type:02X}; channel {channel}. "
                        + note
                        + " Frame metadata is preserved as found; firmware-specific extensions are not decoded."
                    ),
                )
            )
        return candidates


class HikvisionParser(BaseParser):
    route = "hikvision"

    def parse(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        candidates = self._parse_mpeg_program_streams(reader, mode)
        candidates.extend(_carve_candidates(reader, mode))
        return _dedupe_candidates(candidates)

    def _parse_mpeg_program_streams(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        offsets = reader.find_all(b"\x00\x00\x01\xBA", max_hits=100_000)
        if not offsets:
            return []
        candidates: List[Candidate] = []
        group: List[int] = []
        max_gap = 4 * 1024 * 1024
        max_tail = 4 * 1024 * 1024

        def flush(next_offset: Optional[int] = None) -> None:
            if not group:
                return
            start = group[0]
            last = group[-1]
            end = min(reader.size, last + max_tail)
            if next_offset is not None:
                end = min(end, next_offset)
            if end - start >= 16:
                candidates.append(
                    Candidate(
                        start_offset=start,
                        end_offset=end,
                        source="mpeg_ps_carve",
                        state="indexed_candidate" if mode == "normal" else "deleted_candidate",
                        codec="MPEG-PS",
                        confidence=0.62,
                        notes=(
                            "Contiguous MPEG program-stream packs found near a Hikvision signature. "
                            "HIKBTREE geometry is recorded as a detection lead; no timestamp is inferred from a raw pack."
                        ),
                    )
                )
            group.clear()

        for offset in offsets:
            if group and offset - group[-1] > max_gap:
                flush(offset)
            group.append(offset)
        flush()
        return candidates


class HoneywellParser(BaseParser):
    route = "honeywell"

    def parse(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        candidates = _carve_candidates(reader, mode)
        # Expired index markers are useful evidence even when they don't expose
        # a complete recording.  We only add a carve when media bytes are near
        # it; a bare HONEYWELL string is not reported as a video segment.
        for offset in reader.find_all(b"HONEYWELL", max_hits=64):
            nearby = reader.read_at(offset, min(1024 * 1024, reader.size - offset))
            if b"\x00\x00\x01" in nearby:
                end = min(reader.size, offset + len(nearby))
                candidates.append(
                    Candidate(
                        start_offset=offset,
                        end_offset=end,
                        source="honeywell_index_lead",
                        state="expired_index_candidate",
                        codec=detect_codec(reader, offset),
                        confidence=0.48,
                        notes="Honeywell marker is adjacent to media bytes; expiration/deletion semantics require device-specific validation.",
                    )
                )
        return _dedupe_candidates(candidates)


class GenericParser(BaseParser):
    route = "generic_tier2"


PARSERS = {
    "dahua": DahuaParser(),
    "hikvision": HikvisionParser(),
    "honeywell": HoneywellParser(),
    "cp_plus": GenericParser(),
    "uniview": GenericParser(),
    "tp_link": GenericParser(),
    "godrej": GenericParser(),
    "matrix": GenericParser(),
    "unknown": GenericParser(),
}


def parser_for(vendor: str) -> BaseParser:
    return PARSERS.get(vendor, GenericParser())
