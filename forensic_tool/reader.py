"""Safe, bounded readers for acquired evidence.

The reader only opens a regular file for reading.  There is intentionally no
filesystem mounting, partition writing, or automatic repair in this module.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Mapping, Tuple, Union


PathLike = Union[str, Path]


class EvidenceReader:
    """Random-access and streaming reads over a regular evidence file."""

    def __init__(self, path: PathLike):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {self.path}")
        self.size = self.path.stat().st_size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        with self.path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length)

    def iter_chunks(
        self, chunk_size: int = 4 * 1024 * 1024
    ) -> Generator[Tuple[int, bytes], None, None]:
        """Yield ``(absolute_offset, bytes)`` without loading the image."""

        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        with self.path.open("rb") as handle:
            offset = 0
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                yield offset, chunk
                offset += len(chunk)

    def find_all(
        self, needle: bytes, max_hits: int = 256, chunk_size: int = 4 * 1024 * 1024
    ) -> List[int]:
        """Find a byte signature across chunk boundaries.

        Results are capped because a damaged multi-terabyte image can contain
        millions of low-specificity signatures.  The cap protects the UI and
        keeps detection a bounded operation.
        """

        if not needle:
            return []
        hits: List[int] = []
        carry = b""
        carry_len = len(needle) - 1
        for offset, chunk in self.iter_chunks(chunk_size):
            data = carry + chunk
            base = offset - len(carry)
            cursor = 0
            while len(hits) < max_hits:
                found = data.find(needle, cursor)
                if found < 0:
                    break
                hits.append(base + found)
                cursor = found + 1
            if len(hits) >= max_hits:
                break
            carry = data[-carry_len:] if carry_len else b""
        return hits

    def find_signatures(
        self,
        signatures: Mapping[str, bytes],
        max_hits: int = 256,
        chunk_size: int = 4 * 1024 * 1024,
    ) -> Dict[str, List[int]]:
        """Find several byte signatures in one streaming pass.

        Vendor identification previously reopened and rescanned a multi-GB
        image once per signature.  This method keeps a small overlap buffer and
        evaluates all requested signatures while each chunk is already in
        memory.  Matches wholly contained in the overlap are discarded so a
        boundary match is not reported twice.
        """

        queries = {name: bytes(needle) for name, needle in signatures.items() if needle}
        result: Dict[str, List[int]] = {name: [] for name in queries}
        if not queries:
            return result
        overlap = max(len(needle) for needle in queries.values()) - 1
        carry = b""
        for offset, chunk in self.iter_chunks(chunk_size):
            data = carry + chunk
            base = offset - len(carry)
            for name, needle in queries.items():
                if len(result[name]) >= max_hits:
                    continue
                cursor = 0
                while len(result[name]) < max_hits:
                    found = data.find(needle, cursor)
                    if found < 0:
                        break
                    # A match ending inside the overlap was already visible in
                    # the preceding chunk.  A match crossing the boundary is
                    # retained.
                    if found + len(needle) > len(carry):
                        result[name].append(base + found)
                    cursor = found + 1
            carry = data[-overlap:] if overlap else b""
            if all(len(hits) >= max_hits for hits in result.values()):
                break
        return result

    def read_many(self, offsets: Iterable[int], length: int = 1) -> Dict[int, bytes]:
        """Read small values at many offsets while opening the source once."""

        if length <= 0:
            return {offset: b"" for offset in offsets}
        requested = sorted({offset for offset in offsets if 0 <= offset < self.size})
        values: Dict[int, bytes] = {}
        with self.path.open("rb") as handle:
            for offset in requested:
                handle.seek(offset)
                values[offset] = handle.read(min(length, self.size - offset))
        return values

    def hash_range(self, offset: int, length: int, chunk_size: int = 4 * 1024 * 1024) -> str:
        """SHA-256 a physical byte range without changing the source."""

        if offset < 0 or length < 0 or offset > self.size:
            raise ValueError("invalid range")
        remaining = min(length, self.size - offset)
        digest = hashlib.sha256()
        with self.path.open("rb") as handle:
            handle.seek(offset)
            while remaining:
                block = handle.read(min(chunk_size, remaining))
                if not block:
                    break
                digest.update(block)
                remaining -= len(block)
        return digest.hexdigest()

    def read_range_to(self, offset: int, length: int, destination, chunk_size: int = 4 * 1024 * 1024) -> int:
        """Copy a range to a writable binary stream and return bytes copied."""

        if offset < 0 or length < 0 or offset > self.size:
            raise ValueError("invalid range")
        remaining = min(length, self.size - offset)
        copied = 0
        with self.path.open("rb") as handle:
            handle.seek(offset)
            while remaining:
                block = handle.read(min(chunk_size, remaining))
                if not block:
                    break
                destination.write(block)
                copied += len(block)
                remaining -= len(block)
        return copied


def find_pattern_offsets(data: bytes, pattern: bytes, max_hits: int = 4096) -> List[int]:
    """Small in-memory equivalent useful for parser buffers and tests."""

    if not pattern:
        return []
    result: List[int] = []
    cursor = 0
    while len(result) < max_hits:
        found = data.find(pattern, cursor)
        if found < 0:
            break
        result.append(found)
        cursor = found + 1
    return result
