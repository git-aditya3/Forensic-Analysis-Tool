"""Security primitives used by the local workstation and evidence store.

The application cannot make a host or an operator literally unhackable.  These
helpers make the safe behavior the default: private case-data permissions,
constant-time token checks, path containment, and no-follow exclusive file
creation for artifacts that must not be redirected through a symlink.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import BinaryIO


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def new_token(byte_length: int = 32) -> str:
    """Return a high-entropy URL-safe token suitable for a local session."""

    return secrets.token_urlsafe(byte_length)


def token_matches(expected: str, supplied: str | None) -> bool:
    """Compare authentication material without a timing oracle."""

    if not supplied:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def ensure_private_dir(path: Path) -> Path:
    """Create a directory and remove group/other access where supported."""

    if path.is_symlink():
        raise ValueError(f"refusing symlinked security directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, PRIVATE_DIR_MODE)
    except OSError:
        # Windows and some mounted filesystems do not implement POSIX modes.
        pass
    return path


def harden_file(path: Path, mode: int = PRIVATE_FILE_MODE) -> None:
    """Apply a private mode to an existing file without changing its contents."""

    try:
        os.chmod(path, mode)
    except OSError:
        pass


def open_exclusive(path: Path, mode: int = PRIVATE_FILE_MODE) -> BinaryIO:
    """Create a new file without following a pre-existing symlink.

    ``O_NOFOLLOW`` is used where available.  The exclusive create is retained
    on platforms without it, so an attacker cannot replace an existing target
    through this function.
    """

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    descriptor = os.open(path, flags, mode)
    return os.fdopen(descriptor, "wb")


def atomic_write(path: Path, payload: bytes, mode: int = PRIVATE_FILE_MODE) -> None:
    """Atomically write private bytes using a no-follow temporary file."""

    ensure_private_dir(path.parent)
    temporary = path.with_name(f".{path.name}.{new_token(16)}.tmp")
    try:
        with open_exclusive(temporary, mode) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        harden_file(path, mode)
        try:
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
        except (AttributeError, OSError):
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def contained_path(root: Path, relative_or_absolute: str | Path) -> Path:
    """Resolve a stored path and reject traversal or symlink escape."""

    root = root.resolve()
    candidate = Path(relative_or_absolute)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("stored path escapes the private case-data directory")
    return resolved
