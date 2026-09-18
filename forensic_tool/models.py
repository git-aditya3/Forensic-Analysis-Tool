"""Domain models shared by storage, analysis, CLI, and the web layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Case:
    id: str
    title: str
    investigator: str
    notes: str
    created_at: str
    status: str = "open"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    id: str
    case_id: str
    original_name: str
    storage_path: str
    size: int
    md5: str
    sha256: str
    acquired_at: str
    source: str = "disk-image"
    read_only: bool = True
    source_kind: str = "disk-image"
    acquisition_method: str = "streaming-bitstream-copy"
    sector_size: int = 512

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VendorHit:
    vendor: str
    display_name: str
    filesystem: str
    confidence: float
    route: str
    signatures: List[str] = field(default_factory=list)
    offsets: Dict[str, List[int]] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    validation: str = "experimental"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Identification:
    id: str
    evidence_id: str
    primary_vendor: str
    confidence: float
    hits: List[VendorHit]
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["hits"] = [hit.to_dict() for hit in self.hits]
        return value


@dataclass
class Segment:
    id: str
    evidence_id: str
    vendor: str
    source: str
    recovery_mode: str
    state: str
    channel: Optional[int]
    start_offset: int
    end_offset: int
    codec: str
    confidence: float
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    source_sha256: Optional[str] = None
    artifact_path: Optional[str] = None
    payload_start_offset: Optional[int] = None
    payload_end_offset: Optional[int] = None
    notes: str = ""
    created_at: str = ""

    @property
    def size(self) -> int:
        return max(0, self.end_offset - self.start_offset)

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["size"] = self.size
        return value


@dataclass
class AuditEvent:
    id: int
    case_id: str
    action: str
    actor: str
    occurred_at: str
    payload: Dict[str, Any]
    previous_hash: str
    event_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
