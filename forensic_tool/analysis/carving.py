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

    signatures = reader.find_signatures(
        {"three": b"\x00\x00\x01", "four": b"\x00\x00\x00\x01"},
        max_hits=max_markers,
    )
    three = signatures["three"]
    four = signatures["four"]
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
    """Scan Annex-B markers and disambiguate H.264 from H.265.

    Several H.265 headers are also numerically valid H.264 NAL types.  For
    example, an H.265 IDR header can look like H.264 SEI.  We first collect
    the one-byte headers, then use the presence of the distinctive H.265
    VPS/SPS/PPS types (32/33/34) to classify the ambiguous headers correctly.
    """

    starts = _start_codes(reader, max_markers=max_markers)
    headers = reader.read_many((offset + code_length for offset, code_length in starts))
    raw: List[Tuple[int, int, int, int]] = []
    for offset, code_length in starts:
        header = headers.get(offset + code_length, b"")
        if not header:
            continue
        value = header[0]
        raw.append((offset, code_length, value & 0x1F, (value >> 1) & 0x3F))

    h265_types = {1, 19, 20, 21, 32, 33, 34, 35, 39, 40}
    h264_types = {1, 5, 6, 7, 8, 9}
    has_h265_parameter_sets = any(h265_type in {32, 33, 34} for _offset, _length, _h264, h265_type in raw)
    markers: List[NalMarker] = []
    for offset, code_length, h264_type, h265_type in raw:
        # H.265 random-access types 19/20/21 have header bytes that can look
        # like H.264 SEI/PPS.  Prefer that interpretation even in a fragment
        # where the VPS/SPS/PPS were overwritten, while leaving ordinary H.264
        # slice headers untouched.
        h265_random_access = h265_type in {19, 20, 21} and h264_type not in {5, 7, 9}
        if (has_h265_parameter_sets or h265_random_access) and h265_type in h265_types:
            markers.append(NalMarker(offset, code_length, "H.265", h265_type))
        elif h264_type in h264_types:
            markers.append(NalMarker(offset, code_length, "H.264", h264_type))
        elif h265_type in h265_types:
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
            # No container length exists in raw Annex-B.  Keep the range
            # bounded even when the next marker is many gigabytes away; a
            # sparse disk image must never turn one false marker into a
            # whole-disk export.
            max_tail = 4 * 1024 * 1024
            if next_offset is not None and next_offset > last:
                end = min(next_offset, last + max_tail)
            else:
                end = min(file_size, last + max_tail)
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
