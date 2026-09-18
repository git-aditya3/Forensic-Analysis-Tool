"""Conservative DVR/NVR vendor and filesystem signature detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..models import VendorHit
from ..reader import EvidenceReader


@dataclass(frozen=True)
class VendorProfile:
    code: str
    display_name: str
    filesystem: str
    route: str
    signatures: Tuple[Tuple[str, bytes, float], ...]
    validation: str
    limitations: Tuple[str, ...]


PROFILES: Tuple[VendorProfile, ...] = (
    VendorProfile(
        "hikvision",
        "Hikvision",
        "WFS / Hikvision proprietary",
        "hikvision",
        (
            ("HIKVISION@HANGZHOU", b"HIKVISION@HANGZHOU", 0.98),
            ("HIKBTREE", b"HIKBTREE", 0.90),
            ("WFS", b"WFS", 0.62),
        ),
        "experimental",
        (
            "A signature identifies a recorder family, not a complete recovered recording.",
            "Index interpretation is bounded and raw carve timestamps are not wall-clock evidence.",
        ),
    ),
    VendorProfile(
        "dahua",
        "Dahua",
        "DHFS / DHAV",
        "dahua_dhav",
        (
            ("DAHUA", b"DAHUA", 0.95),
            ("DHFS", b"DHFS", 0.97),
            ("DHAV", b"DHAV", 0.91),
            ("dhav", b"dhav", 0.82),
        ),
        "experimental",
        (
            "DHAV block variants differ by firmware; unrecognised headers are carved as candidates.",
            "Native streams are preserved; transcoding is never used to improve an evidentiary result.",
        ),
    ),
    VendorProfile(
        "honeywell",
        "Honeywell",
        "Honeywell proprietary",
        "honeywell",
        (
            ("HONEYWELL", b"HONEYWELL", 0.96),
            ("HNW", b"HNW", 0.60),
        ),
        "experimental",
        (
            "Expiration and overwrite semantics vary by recorder and firmware.",
            "Expired-index hits are leads until independently validated against the source device.",
        ),
    ),
    VendorProfile(
        "cp_plus",
        "CP Plus",
        "CPFS / OEM family",
        "generic_tier2",
        (("CP PLUS", b"CP PLUS", 0.88), ("CPPLUS", b"CPPLUS", 0.86), ("CPFS", b"CPFS", 0.78)),
        "signature-only",
        ("This release routes CP Plus matches to generic carving; no CP Plus parser is claimed.",),
    ),
    VendorProfile(
        "uniview",
        "Uniview",
        "Uniview / OEM family",
        "generic_tier2",
        (("UNIVIEW", b"UNIVIEW", 0.88), ("UNV", b"UNV", 0.64)),
        "signature-only",
        ("This release routes Uniview matches to generic carving; no Uniview parser is claimed.",),
    ),
    VendorProfile(
        "tp_link",
        "TP-Link",
        "TPFS / OEM family",
        "generic_tier2",
        (("TP-LINK", b"TP-LINK", 0.88), ("TPLINK", b"TPLINK", 0.84), ("TPFS", b"TPFS", 0.74)),
        "signature-only",
        ("Generic raw-video carving is a recovery lead and does not reconstruct vendor metadata.",),
    ),
    VendorProfile(
        "godrej",
        "Godrej",
        "Godrej / OEM family",
        "generic_tier2",
        (("GODREJ", b"GODREJ", 0.90), ("GODREJFS", b"GODREJFS", 0.94)),
        "signature-only",
        ("This release provides signature detection and generic carving only.",),
    ),
    VendorProfile(
        "matrix",
        "Matrix",
        "Matrix / OEM family",
        "generic_tier2",
        (("MATRIX", b"MATRIX", 0.88), ("MATRIXFS", b"MATRIXFS", 0.94)),
        "signature-only",
        ("This release provides signature detection and generic carving only.",),
    ),
)

_PROFILE_BY_CODE = {profile.code: profile for profile in PROFILES}


@dataclass
class DetectionResult:
    primary: VendorHit
    hits: List[VendorHit]

    def to_dict(self) -> Dict[str, object]:
        return {"primary": self.primary.to_dict(), "hits": [hit.to_dict() for hit in self.hits]}


def _hit(profile: VendorProfile, matched: List[Tuple[str, int, float]]) -> VendorHit:
    names = [name for name, _offset, _weight in matched]
    offsets: Dict[str, List[int]] = {}
    for name, offset, _weight in matched:
        offsets.setdefault(name, []).append(offset)
    strongest = max(weight for _name, _offset, weight in matched)
    # A second independent marker raises confidence, but never makes an
    # experimental adapter look more certain than a validated identification.
    confidence = min(0.995, strongest + 0.025 * max(0, len(set(names)) - 1))
    return VendorHit(
        vendor=profile.code,
        display_name=profile.display_name,
        filesystem=profile.filesystem,
        confidence=round(confidence, 3),
        route=profile.route,
        signatures=sorted(set(names)),
        offsets=offsets,
        limitations=list(profile.limitations),
        validation=profile.validation,
    )


def detect(reader: EvidenceReader) -> DetectionResult:
    hits: List[VendorHit] = []
    signature_queries = {
        f"{profile.code}:{name}": signature
        for profile in PROFILES
        for name, signature, _weight in profile.signatures
    }
    signature_queries["__annex_three"] = b"\x00\x00\x01"
    signature_queries["__annex_four"] = b"\x00\x00\x00\x01"
    signature_hits = reader.find_signatures(signature_queries, max_hits=16)
    for profile in PROFILES:
        matches: List[Tuple[str, int, float]] = []
        for name, _signature, weight in profile.signatures:
            offsets = signature_hits.get(f"{profile.code}:{name}", [])
            matches.extend((name, offset, weight) for offset in offsets)
        if matches:
            hits.append(_hit(profile, matches))

    # Higher-specificity matches win.  If a file has only raw stream markers,
    # report that honestly as an unknown/generic route rather than inventing a
    # manufacturer identity.
    if not hits:
        # Both three- and four-byte Annex-B start codes are common in raw
        # recorder streams.  Keep the reported offsets unique and point to the
        # actual marker start for the generic evidence lead.
        three_byte = signature_hits.get("__annex_three", [])
        four_byte = signature_hits.get("__annex_four", [])
        four_starts = set(four_byte)
        annexb = sorted(four_starts | {offset for offset in three_byte if offset - 1 not in four_starts})
        generic = VendorHit(
            vendor="unknown",
            display_name="Unknown / generic media",
            filesystem="unidentified",
            confidence=0.25 if annexb else 0.10,
            route="generic_tier2",
            signatures=["Annex-B start code"] if annexb else [],
            offsets={"Annex-B start code": annexb} if annexb else {},
            limitations=[
                "No supported recorder signature was found.",
                "Raw video markers do not prove vendor, camera, or wall-clock time.",
            ],
            validation="unknown",
        )
        return DetectionResult(primary=generic, hits=[generic])

    hits.sort(key=lambda item: (item.confidence, len(item.signatures)), reverse=True)
    return DetectionResult(primary=hits[0], hits=hits)


def profile_for(code: str) -> VendorProfile | None:
    return _PROFILE_BY_CODE.get(code)
