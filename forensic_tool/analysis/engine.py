"""Orchestration between detection, vendor adapters, and SQLite results."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterable, List, Optional

from ..models import Segment
from ..storage import EvidenceStore, utc_now
from .detector import DetectionResult, detect
from .parsers import Candidate, parser_for


class AnalysisEngine:
    def __init__(self, store: EvidenceStore):
        self.store = store

    def identify(self, evidence_id: str) -> Dict[str, Any]:
        reader = self.store.evidence_reader(evidence_id)
        result = detect(reader)
        saved = self.store.save_identification(
            evidence_id,
            result.primary.vendor,
            result.primary.confidence,
            result.hits,
        )
        saved["primary"] = result.primary.to_dict()
        return saved

    def _identity(self, evidence_id: str) -> Dict[str, Any]:
        identity = self.store.latest_identification(evidence_id)
        if identity is None:
            return self.identify(evidence_id)
        return identity

    @staticmethod
    def _overlap(left: Candidate, right: Candidate) -> int:
        return max(0, min(left.end_offset, right.end_offset) - max(left.start_offset, right.start_offset))

    def _dedupe(self, candidates: Iterable[Candidate]) -> List[Candidate]:
        """Prefer parser-backed ranges over generic carves with same bytes."""

        priority = {"dhav_parser": 3, "mpeg_ps_carve": 2, "honeywell_index_lead": 2, "annexb_carve": 1}
        ordered = sorted(candidates, key=lambda item: (priority.get(item.source, 0), item.confidence), reverse=True)
        kept: List[Candidate] = []
        for candidate in ordered:
            if any(
                self._overlap(candidate, existing) > min(candidate.size, existing.size) * 0.85
                and candidate.codec == existing.codec
                for existing in kept
            ):
                continue
            kept.append(candidate)
        return sorted(kept, key=lambda item: item.start_offset)

    def recover(self, evidence_id: str, mode: str = "normal") -> Dict[str, Any]:
        if mode not in {"normal", "deleted", "lost_corrupted"}:
            raise ValueError("mode must be normal, deleted, or lost_corrupted")
        evidence = self.store.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        identity = self._identity(evidence_id)
        vendor = identity["primary_vendor"]
        reader = self.store.evidence_reader(evidence_id)
        candidates = self._dedupe(parser_for(vendor).parse(reader, mode))
        segments: List[Segment] = []
        for candidate in candidates:
            if candidate.start_offset < 0 or candidate.end_offset > reader.size:
                continue
            segment = Segment(
                id=f"SEG-{uuid.uuid4().hex[:12].upper()}",
                evidence_id=evidence_id,
                vendor=vendor,
                source=candidate.source,
                recovery_mode=mode,
                state=candidate.state,
                channel=candidate.channel,
                start_offset=candidate.start_offset,
                end_offset=candidate.end_offset,
                codec=candidate.codec,
                confidence=candidate.confidence,
                start_time=candidate.start_time,
                end_time=candidate.end_time,
                source_sha256=reader.hash_range(candidate.start_offset, candidate.size),
                notes=candidate.notes,
                created_at=utc_now(),
            )
            segments.append(segment)
        saved = self.store.save_segments(evidence_id, segments, mode)
        return {
            "evidence_id": evidence_id,
            "vendor": vendor,
            "mode": mode,
            "segment_count": len(saved),
            "segments": saved,
            "limitations": [
                "Physical byte ranges and hashes are recorded for every result.",
                "A carved candidate is not proof of deletion, identity, or wall-clock time without corroborating metadata.",
            ],
        }

    def timeline(self, evidence_id: str) -> Dict[str, Any]:
        evidence = self.store.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        segments = self.store.list_segments(evidence_id)
        # Indexed timestamps sort first; physical offsets provide a deterministic
        # order for raw candidates with no clock.
        segments.sort(key=lambda item: (item.get("start_time") is None, item.get("start_time") or "", item["start_offset"]))
        return {
            "evidence_id": evidence_id,
            "segments": segments,
            "clock_note": "Missing times mean the segment is ordered by physical offset, not assigned a wall-clock timestamp.",
        }
