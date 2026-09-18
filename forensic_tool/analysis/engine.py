"""Orchestration between detection, vendor adapters, and SQLite results."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterable, List, Optional

from ..models import Segment
from ..storage import EvidenceStore, utc_now
from .detector import DetectionResult, detect
from .analytics import capabilities, run_analytics
from .device import identify_device
from .parsers import Candidate, parser_for
from .timeline import build_timeline


class AnalysisEngine:
    def __init__(self, store: EvidenceStore):
        self.store = store

    def identify(self, evidence_id: str) -> Dict[str, Any]:
        reader = self.store.evidence_reader(evidence_id)
        result = detect(reader)
        device_info = identify_device(reader)
        saved = self.store.save_identification(
            evidence_id,
            result.primary.vendor,
            result.primary.confidence,
            result.hits,
            device_info=device_info,
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

        priority = {"dhav_parser": 3, "honeywell_custom_header": 3, "mpeg_ps_carve": 2, "honeywell_index_lead": 2, "annexb_carve": 1}
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
        if not isinstance(mode, str) or mode not in {"normal", "deleted", "overwritten", "fragmented", "unallocated", "lost_corrupted"}:
            raise ValueError("mode must be normal, deleted, overwritten, fragmented, unallocated, or lost_corrupted")
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
                payload_start_offset=candidate.payload_start_offset,
                payload_end_offset=candidate.payload_end_offset,
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
                "Deleted, overwritten, fragmented, and unallocated labels describe the requested recovery posture; they are not proof of storage history without corroborating filesystem or recorder metadata.",
                "A carved candidate is not proof of deletion, identity, or wall-clock time without corroborating metadata.",
            ],
        }

    def timeline(self, evidence_id: str, tolerance_seconds: float = 2.0) -> Dict[str, Any]:
        evidence = self.store.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        result = {
            "evidence_id": evidence_id,
            **build_timeline(self.store.list_segments(evidence_id), tolerance_seconds),
        }
        self.store.record_audit(evidence["case_id"], "timeline_normalized", {
            "evidence_id": evidence_id,
            "tolerance_seconds": tolerance_seconds,
            "event_count": len(result["events"]),
            "correlation_count": len(result["correlations"]),
        })
        return result

    def correlate_case(self, case_id: str, tolerance_seconds: float = 2.0) -> Dict[str, Any]:
        self.store.require_case(case_id)
        segments = []
        for evidence in self.store.list_evidence(case_id):
            segments.extend(self.store.list_segments(evidence["id"]))
        result = {
            "case_id": case_id,
            **build_timeline(segments, tolerance_seconds),
        }
        self.store.record_audit(case_id, "cross_camera_correlation", {
            "tolerance_seconds": tolerance_seconds,
            "event_count": len(result["events"]),
            "correlation_count": len(result["correlations"]),
        })
        return result

    def analytics(self, segment_id: str, kind: str, model: str = "") -> Dict[str, Any]:
        return run_analytics(self.store, segment_id, kind, model)

    @staticmethod
    def capabilities() -> Dict[str, Any]:
        return capabilities()
