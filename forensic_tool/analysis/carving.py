"""Bounded raw video carving for Annex-B H.264/H.265 evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from ..reader import EvidenceReader


@dataclass
class CarvedRange:
    start_offset: int
    end_offset: int
    codec: str
    confidence: float
    notes: str

    @property
    def size(self) -> int:
        return max(0, self.end_offset - self.start_offset)


@dataclass(frozen=True)
class NalMarker:
    offset: int
    code_length: int
    codec: str
    nal_type: int


def _start_codes(reader: EvidenceReader, max_markers: int = 200_000) -> List[Tuple[int, int]]:
    """Return unique Annex-B start codes, including chunk-boundary matches."""

    three = reader.find_all(b"\x00\x00\x01", max_hits=max_markers)
    four = reader.find_all(b"\x00\x00\x00\x01", max_hits=max_markers)
    starts: Dict[int, int] = {}
    for offset in three:
        starts[offset] = 3
    for offset in four:
        # A four-byte marker is more precise than the overlapping three-byte
        # match at offset + 1.
        starts[offset] = 4
        starts.pop(offset + 1, None)
    return sorted(starts.items())[:max_markers]


def scan_nals(reader: EvidenceReader, max_markers: int = 200_000) -> List[NalMarker]:
    markers: List[NalMarker] = []
    for offset, code_length in _start_codes(reader, max_markers=max_markers):
        header = reader.read_at(offset + code_length, 1)
        if not header:
            continue
        value = header[0]
        h264_type = value & 0x1F
        h265_type = (value >> 1) & 0x3F
        # H.264 parameter sets/keyframes are the most reliable signature.  A
        # valid H.265 VPS/SPS/PPS has types 32/33/34 and is otherwise ignored
        # by the H.264 branch.
        if h264_type in {1, 5, 6, 7, 8, 9}:
            markers.append(NalMarker(offset, code_length, "H.264", h264_type))
        elif h265_type in {1, 19, 20, 21, 32, 33, 34, 35, 39, 40}:
            markers.append(NalMarker(offset, code_length, "H.265", h265_type))
    return markers


def _group_markers(
    markers: Iterable[NalMarker], file_size: int, max_gap: int = 4 * 1024 * 1024
) -> List[CarvedRange]:
    by_codec: Dict[str, List[NalMarker]] = {"H.264": [], "H.265": []}
    for marker in markers:
        by_codec.setdefault(marker.codec, []).append(marker)

    ranges: List[CarvedRange] = []
    for codec, values in by_codec.items():
        if not values:
            continue
        values.sort(key=lambda item: item.offset)
        group: List[NalMarker] = []

        def flush(next_offset: Optional[int] = None) -> None:
            if not group:
                return
            meaningful = sum(1 for item in group if item.nal_type in ({5, 7, 8} if codec == "H.264" else {19, 20, 32, 33, 34}))
            if len(group) < 2 and meaningful == 0:
                group.clear()
                return
            start = group[0].offset
            last = group[-1].offset
            if next_offset is not None and next_offset > last:
                end = next_offset
            else:
                # No container length exists in raw Annex-B.  Keep a bounded
                # tail so carving a false marker can never copy the whole disk.
                end = min(file_size, last + 4 * 1024 * 1024)
            end = max(start + group[-1].code_length + 1, min(file_size, end))
            base = 0.66 if codec == "H.264" else 0.60
            if meaningful:
                base += 0.12
            if len(group) >= 4:
                base += 0.08
            ranges.append(
                CarvedRange(
                    start_offset=start,
                    end_offset=end,
                    codec=codec,
                    confidence=round(min(0.93, base), 3),
                    notes=(
                        "Annex-B stream carved from physical bytes; no recorder index or wall-clock timestamp was recovered."
                    ),
                )
            )
            group.clear()

        for marker in values:
            if group and marker.offset - group[-1].offset > max_gap:
                flush(marker.offset)
            group.append(marker)
        flush()
    ranges.sort(key=lambda item: item.start_offset)
    return ranges


def carve_annex_b(reader: EvidenceReader) -> List[CarvedRange]:
    return _group_markers(scan_nals(reader), reader.size)


def detect_codec(reader: EvidenceReader, offset: int, length: int = 64 * 1024) -> str:
    """Best-effort codec label for a container payload."""

    data = reader.read_at(offset, length)
    if not data:
        return "unknown"
    # Search payload-local markers, avoiding a second full-disk scan.
    if b"\x00\x00\x01\x67" in data or b"\x00\x00\x00\x01\x67" in data:
        return "H.264"
    if b"\x00\x00\x01\x40" in data or b"\x00\x00\x00\x01\x40" in data:
        return "H.265"
    if b"\x00\x00\x01\xBA" in data:
        return "MPEG-PS"
    return "unknown"
