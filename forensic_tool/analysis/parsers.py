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
        offsets = sorted(set(found["upper"] + found["lower"]))
        headers = reader.read_many(offsets, 64)
        candidates: List[Candidate] = []
        for index, offset in enumerate(offsets):
            header = headers.get(offset, b"")
            if len(header) < 16:
                continue
            # The common DHAV family stores a bounded block length near the
            # magic.  Firmware variants move it, so evaluate little and big
            # endian candidates at offsets 4, 8, and 12 and choose the first
            # physically plausible one.
            length = None
            for field_offset in (4, 8, 12, 16):
                if field_offset + 4 > len(header):
                    continue
                for endian in ("<", ">"):
                    value = struct.unpack_from(f"{endian}I", header, field_offset)[0]
                    if 32 <= value <= min(256 * 1024 * 1024, reader.size - offset):
                        # A length at offset 4 is strongly preferred; other
                        # fields are accepted only when the next magic agrees.
                        if length is None or field_offset < length[1]:
                            length = (value, field_offset)
            next_magic = offsets[index + 1] if index + 1 < len(offsets) else reader.size
            if length:
                end = min(reader.size, offset + length[0])
                confidence = 0.90 if length[1] == 4 else 0.78
                note = "Bounded DHAV-family block with a plausible length field."
            else:
                end = min(next_magic, offset + 4 * 1024 * 1024)
                confidence = 0.55
                note = "DHAV marker found but no trusted length field; bounded to the next marker."
            if end <= offset + 32:
                continue
            payload_offset = min(end, offset + 32)
            codec = detect_codec(reader, payload_offset, min(64 * 1024, end - payload_offset))
            if codec == "unknown":
                codec = "DHAV"
            channel = None
            timestamp = None
            # This is the most common compact testable layout: channel at 8,
            # Unix milliseconds at 12.  Sanity checks prevent random bytes
            # from becoming a camera number or a date.
            if len(header) >= 12:
                possible_channel = struct.unpack_from("<I", header, 8)[0]
                if possible_channel < 256:
                    channel = int(possible_channel)
            if len(header) >= 20:
                raw_timestamp = struct.unpack_from("<Q", header, 12)[0]
                timestamp = _iso_timestamp(raw_timestamp, milliseconds=True) or _iso_timestamp(raw_timestamp, milliseconds=False)
            candidates.append(
                Candidate(
                    start_offset=offset,
                    end_offset=end,
                    source="dhav_parser",
                    state="indexed" if length else "container_candidate",
                    codec=codec,
                    confidence=confidence,
                    channel=channel,
                    start_time=timestamp,
                    notes=note
                    + " Container metadata is preserved as found; the parser does not claim to decode every firmware variant.",
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
