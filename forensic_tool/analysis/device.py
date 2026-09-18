"""Best-effort recorder model and firmware extraction.

A vendor signature can route parsing, but it rarely names the exact recorder.
This module extracts explicit model/firmware strings from bounded metadata
windows and labels the result as a candidate. It never invents a model from a
brand-only hit.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

from ..reader import EvidenceReader


MODEL_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:DS|DS-?7|DS-?8|DH|DH-|IPC-|NVR|DVR|XVR|HVR|TVT|UNV)[A-Z0-9._/-]{2,32}\b", re.I),
    re.compile(r"\b(?:model|device|product)\s*[:=#-]?\s*([A-Z][A-Z0-9._/-]{2,40})\b", re.I),
)
_NON_MODEL_MARKERS = {"DHAV", "DHFS", "HIKBTREE", "WFS", "CPFS", "TPFS", "MATRIXFS", "GODREJFS", "HONEYWELL"}

FIRMWARE_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:firmware|version|ver|build)\s*[:=#-]?\s*(v?\d+(?:\.\d+){1,5}(?:[-._a-z0-9]+)?)\b", re.I),
    re.compile(r"\bv?\d+\.\d+\.\d+(?:[-._a-z0-9]+)?\b", re.I),
    re.compile(r"\b20\d{2}[-_.]\d{2}[-_.]\d{2}\b"),
)


def _windows(reader: EvidenceReader, window: int = 8 * 1024 * 1024) -> Iterable[Tuple[int, bytes]]:
    yield 0, reader.read_at(0, min(window, reader.size))
    if reader.size > window:
        start = max(0, reader.size - window)
        yield start, reader.read_at(start, window)


def identify_device(reader: EvidenceReader) -> Dict[str, Any]:
    models: List[str] = []
    firmware: List[str] = []
    markers: List[Dict[str, Any]] = []
    for base, raw in _windows(reader):
        decoded = [("ascii", raw.decode("ascii", errors="ignore"))]
        if len(raw) >= 2:
            decoded.append(("utf16le", raw.decode("utf-16le", errors="ignore")))
        for encoding, text in decoded:
            for pattern in MODEL_PATTERNS:
                for match in pattern.finditer(text):
                    value = (match.group(1) if match.lastindex else match.group(0)).strip(" .:_-")
                    if 3 <= len(value) <= 48 and value.upper() not in _NON_MODEL_MARKERS and value.upper() not in {item.upper() for item in models}:
                        models.append(value)
                        byte_offset = base + (match.start() * 2 if encoding == "utf16le" else match.start())
                        markers.append({"kind": "model", "value": value, "encoding": encoding, "offset": byte_offset})
            for pattern in FIRMWARE_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group(1) if match.lastindex else match.group(0)
                    if value not in firmware:
                        firmware.append(value)
                        byte_offset = base + (match.start() * 2 if encoding == "utf16le" else match.start())
                        markers.append({"kind": "firmware", "value": value, "encoding": encoding, "offset": byte_offset})
    return {
        "models": models[:32],
        "firmware": firmware[:32],
        "markers": markers[:64],
        "confidence": 0.85 if models and firmware else 0.65 if models or firmware else 0.0,
        "limitations": [
            "Model and firmware strings are candidates extracted from evidence metadata; they are not hardware attestation.",
            "A blank result means no explicit model or firmware string survived in the sampled metadata windows.",
        ],
    }
