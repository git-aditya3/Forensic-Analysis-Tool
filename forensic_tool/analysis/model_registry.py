"""Verified model assets used by the default post-acquisition analytics.

Models live below the configured case-data directory rather than inside an
acquired evidence directory.  They are downloaded lazily, hash-checked before
use, and their provenance is returned with every analytics result.  A forensic
case can therefore be run offline with the deterministic OpenCV fallbacks,
while a normal connected installation automatically provisions the stronger
COCO/YuNet detectors on first use.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ModelSpec:
    key: str
    filename: str
    url: str
    sha256: str
    size: int
    license: str
    description: str


# OpenCV Zoo assets.  The expected hashes are the Git LFS object hashes and
# are also the SHA-256 hashes of the downloaded model bytes.
OBJECT_MODEL = ModelSpec(
    key="opencv-zoo-nanodet-coco",
    filename="object_detection_nanodet_2022nov.onnx",
    url="https://raw.githubusercontent.com/opencv/opencv_zoo/main/models/object_detection_nanodet/object_detection_nanodet_2022nov.onnx",
    sha256="4b82da9944b88577175ee23a459dce2e26e6e4be573def65b1055dc2d9720186",
    size=3_800_954,
    license="Apache-2.0",
    description="OpenCV Zoo NanoDet-M-plus COCO object detector",
)

FACE_MODEL = ModelSpec(
    key="opencv-zoo-yunet-face",
    filename="face_detection_yunet_2023mar.onnx",
    url="https://raw.githubusercontent.com/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
    sha256="8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
    size=232_589,
    license="MIT",
    description="OpenCV Zoo YuNet face detector",
)

COCO_LABELS = (
    "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat",
    "traffic light", "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat",
    "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe", "backpack",
    "umbrella", "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball",
    "kite", "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket",
    "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
    "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair",
    "couch", "potted plant", "bed", "dining table", "toilet", "tv", "laptop", "mouse", "remote",
    "keyboard", "cell phone", "microwave", "oven", "toaster", "sink", "refrigerator", "book",
    "clock", "vase", "scissors", "teddy bear", "hair drier", "toothbrush",
)


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def model_directory(store_root: str | Path) -> Path:
    override = os.environ.get("SENTINEL_MODEL_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(store_root).expanduser().resolve() / "models"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _metadata(spec: ModelSpec, path: Optional[Path], status: str, **extra: Any) -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "key": spec.key,
        "filename": spec.filename,
        "description": spec.description,
        "license": spec.license,
        "source": spec.url,
        "expected_sha256": spec.sha256,
        "expected_size": spec.size,
        "status": status,
    }
    if path is not None:
        value["path"] = str(path)
    value.update(extra)
    return value


def describe_model(spec: ModelSpec, *, auto_download: bool = True) -> Dict[str, Any]:
    """Expose model provenance without touching the filesystem or network."""
    return _metadata(spec, None, "auto_download_on_use" if auto_download else "offline_fallback")


def resolve_model(spec: ModelSpec, store_root: str | Path, *, auto_download: Optional[bool] = None) -> tuple[Optional[Path], Dict[str, Any]]:
    """Return a verified model path, lazily downloading it when permitted."""
    root = model_directory(store_root)
    path = root / spec.filename
    if auto_download is None:
        auto_download = _env_flag("SENTINEL_AUTO_DOWNLOAD_MODELS", True)
    invalid_cache: Optional[Dict[str, Any]] = None
    if path.is_file():
        actual_size = path.stat().st_size
        actual_hash = _sha256(path) if actual_size == spec.size else ""
        if actual_size == spec.size and actual_hash == spec.sha256:
            return path, _metadata(spec, path, "available", actual_sha256=actual_hash)
        invalid_cache = _metadata(
            spec,
            path,
            "invalid",
            actual_size=actual_size,
            actual_sha256=actual_hash or None,
            error="Cached model failed the expected size or SHA-256 check; it was not used.",
        )
        if not auto_download:
            return None, invalid_cache

    if not auto_download:
        return None, _metadata(spec, None, "not_configured", error="Automatic model download is disabled.")

    temporary_name: Optional[Path] = None
    try:
        root.mkdir(parents=True, exist_ok=True)
        request = Request(spec.url, headers={"User-Agent": "sentinel-forensic-tool/0.1"})
        with urlopen(request, timeout=float(os.environ.get("SENTINEL_MODEL_DOWNLOAD_TIMEOUT", "30"))) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) != spec.size:
                raise ValueError(f"download size {content_length} does not match expected {spec.size}")
            with tempfile.NamedTemporaryFile(prefix=f".{spec.filename}.", suffix=".download", dir=root, delete=False) as temporary:
                temporary_name = Path(temporary.name)
                copied = 0
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    copied += len(block)
                    if copied > spec.size:
                        raise ValueError("download exceeded the expected model size")
                    temporary.write(block)
                temporary.flush()
                os.fsync(temporary.fileno())
        if copied != spec.size or _sha256(temporary_name) != spec.sha256:
            raise ValueError("download failed the expected size or SHA-256 check")
        try:
            temporary_name.chmod(0o440)
        except OSError:
            pass
        os.replace(temporary_name, path)
        return path, _metadata(spec, path, "downloaded", actual_sha256=spec.sha256, replaced_invalid_cache=invalid_cache is not None)
    except Exception as error:
        if temporary_name is not None:
            try:
                temporary_name.unlink()
            except OSError:
                pass
        return None, _metadata(spec, None, "unavailable", error=str(error))
