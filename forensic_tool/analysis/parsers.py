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
    payload_start_offset: Optional[int] = None
    payload_end_offset: Optional[int] = None
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


def _unix_microseconds_to_iso(value: int) -> Optional[str]:
    """Decode Honeywell's eight-byte Unix-microsecond frame timestamp."""
    if value <= 0:
        return None
    seconds, microseconds = divmod(value, 1_000_000)
    if seconds < 63072000 or seconds > 4102444800:  # 1972 .. 2100
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=microseconds).isoformat(timespec="microseconds").replace("+00:00", "Z")
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
        "overwritten": "Candidate found in a region that may have been reused; overwritten status is a hypothesis until recorder allocation metadata is available.",
        "fragmented": "Fragment candidate from raw bytes; physical continuity and wall-clock time are not established.",
        "lost_corrupted": "Fragment candidate from raw bytes; physical continuity and wall-clock time are not established.",
        "unallocated": "Candidate from a requested unallocated-space sweep; filesystem allocation state is not independently reconstructed.",
    }.get(mode, "Raw bytes carved without an index.")
    state_for_mode = {
        "normal": "unindexed",
        "deleted": "deleted_candidate",
        "overwritten": "overwritten_candidate",
        "fragmented": "fragment",
        "lost_corrupted": "fragment",
        "unallocated": "unallocated_candidate",
    }.get(mode, "unindexed")
    candidates: List[Candidate] = []
    for item in carve_annex_b(reader):
        candidates.append(
            Candidate(
                start_offset=item.start_offset,
                end_offset=item.end_offset,
                source="annexb_carve",
                state=state_for_mode,
                codec=item.codec,
                confidence=item.confidence,
                payload_start_offset=item.start_offset,
                payload_end_offset=item.end_offset,
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
            if mode != "normal":
                state = {
                    "deleted": "deleted_candidate",
                    "overwritten": "overwritten_candidate",
                    "fragmented": "fragment",
                    "lost_corrupted": "fragment",
                    "unallocated": "unallocated_candidate",
                }.get(mode, state)
                note += " Recovery mode labels this as a candidate, not a proven storage-history state."
            if end <= offset + 24:
                continue

            payload_offset = min(end, offset + 24 + extension_length)
            codec = detect_codec(reader, payload_offset, min(64 * 1024, end - payload_offset))
            if codec == "unknown":
                codec = "DHAV-audio" if frame_type in {0xF0, 0xF1} else "DHAV"
            timestamp = _dhav_date_to_iso(packed_date, timestamp_ms)
            payload_end = max(payload_offset, end - 8 if footer_valid else end)
            payload_start_value = payload_offset if payload_end > payload_offset else None
            payload_end_value = payload_end if payload_end > payload_offset else None
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
                    payload_start_offset=payload_start_value,
                    payload_end_offset=payload_end_value,
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
        custom = self._parse_custom_headers(reader, mode)
        carves = _carve_candidates(reader, mode)
        candidates = [*custom, *carves]
        # Expired index markers are useful evidence even when they don't expose
        # a complete recording. We only add a bounded lead when media bytes are
        # near it; a bare HONEYWELL string is not reported as a video segment.
        for offset in reader.find_all(b"HONEYWELL", max_hits=64):
            if any(item.start_offset <= offset < item.end_offset for item in custom):
                continue
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
        if custom and mode == "normal":
            return _dedupe_candidates(custom)
        return _dedupe_candidates(candidates)

    def _parse_custom_headers(self, reader: EvidenceReader, mode: str) -> List[Candidate]:
        """Parse Honeywell's documented 20-byte custom H.264 frame header.

        The real format uses a frame type byte (0x82 IDR / 0x02 non-IDR),
        ``80 01 00``, two little-endian resolution values, a four-byte NAL
        length, and an eight-byte Unix-microsecond timestamp. A six-byte Annex-B
        prefix/header follows. This parser accepts only bounded, structurally
        validated records and never treats a marker alone as a frame.
        """
        markers = sorted(set(
            reader.find_all(b"\x82\x80\x01\x00", max_hits=100_000)
            + reader.find_all(b"\x02\x80\x01\x00", max_hits=100_000)
        ))
        state = {
            "normal": "indexed",
            "deleted": "deleted_candidate",
            "overwritten": "overwritten_candidate",
            "fragmented": "fragment",
            "lost_corrupted": "fragment",
            "unallocated": "unallocated_candidate",
        }.get(mode, "indexed")
        candidates: List[Candidate] = []
        for offset in markers:
            header = reader.read_at(offset, 20)
            if len(header) < 20:
                continue
            frame_type = header[0]
            width, height = struct.unpack_from("<HH", header, 4)
            nal_length = struct.unpack_from("<I", header, 8)[0]
            timestamp = struct.unpack_from("<Q", header, 12)[0]
            payload_offset = offset + 20
            prefix = reader.read_at(payload_offset, 6)
            if not (prefix.startswith(b"\x00\x00\x00\x01") or prefix.startswith(b"\x00\x00\x01")):
                continue
            if not (16 <= width <= 16384 and 16 <= height <= 16384):
                continue
            if not (1 <= nal_length <= min(256 * 1024 * 1024, reader.size - payload_offset)):
                continue
            end = payload_offset + nal_length
            if end > reader.size:
                continue
            # If the declared record ends before the next custom header, keep
            # the exact declared range. Any inter-record delimiter belongs to
            # the container, not this media payload.
            timestamp_value = _unix_microseconds_to_iso(timestamp)
            candidates.append(
                Candidate(
                    start_offset=offset,
                    end_offset=end,
                    source="honeywell_custom_header",
                    state=state,
                    codec="H.264",
                    confidence=0.94 if timestamp_value else 0.84,
                    channel=None,
                    start_time=timestamp_value,
                    payload_start_offset=payload_offset,
                    payload_end_offset=end,
                    notes=(
                        f"Honeywell custom H.264 header validated: frame type 0x{frame_type:02X}, "
                        f"{width}x{height}, declared NAL length {nal_length}. "
                        "Channel assignment requires a corroborating Video Channel List entry."
                    ),
                )
            )
        return candidates


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
