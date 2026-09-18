"""Streaming cryptographic hashes used at acquisition and export."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Dict


def hash_stream(stream: BinaryIO, chunk_size: int = 4 * 1024 * 1024) -> Dict[str, str | int]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(chunk_size)
        if not block:
            break
        size += len(block)
        md5.update(block)
        sha256.update(block)
    return {"size": size, "md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def hash_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> Dict[str, str | int]:
    with path.open("rb") as stream:
        return hash_stream(stream, chunk_size=chunk_size)
