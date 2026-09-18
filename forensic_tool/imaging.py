"""Forensic bit-stream acquisition metadata and copy policy.

The standard library cannot repair a failing disk or guarantee a hardware
write-blocker.  This module provides the software side of the acquisition
contract: open the source read-only, copy every byte in order, fsync the
acquired copy, and record the sector geometry and hash inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from stat import S_ISBLK, S_ISREG
from typing import BinaryIO


@dataclass(frozen=True)
class AcquisitionPlan:
    source_kind: str = "disk-image"
    sector_size: int = 512
    method: str = "streaming-bitstream-copy"
    read_only: bool = True

    def validate(self) -> None:
        if self.source_kind not in {"disk-image", "physical-disk", "partition", "file", "stream"}:
            raise ValueError("source_kind must be disk-image, physical-disk, partition, file, or stream")
        if self.method not in {"streaming-bitstream-copy", "sector-copy", "file-copy", "logical-export"}:
            raise ValueError("unsupported acquisition method")
        if self.sector_size <= 0 or self.sector_size > 1024 * 1024:
            raise ValueError("sector_size must be between 1 and 1048576 bytes")
        if self.sector_size & (self.sector_size - 1):
            raise ValueError("sector_size must be a power of two")
        if not self.read_only:
            raise ValueError("forensic acquisition requires read_only=True")


def open_source_read_only(path: str | Path) -> BinaryIO:
    """Open an image/device without requesting write access."""

    source = Path(path).expanduser()
    if not source.exists() or not (S_ISREG(source.stat().st_mode) or S_ISBLK(source.stat().st_mode)):
        raise FileNotFoundError(f"Source file or block device not found: {source}")
    return source.open("rb")
