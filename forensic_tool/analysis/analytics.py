"""Post-acquisition media analytics.

Analytics never changes acquired evidence. Every run records the exact native
range hash, the derived media-artifact hash, the decoder/model provenance, and
an explicit result when a dependency or codec cannot process the payload.

The normal installation provisions verified OpenCV Zoo detectors lazily. The
verified model assets are stored outside evidence and are never allowed to
change a source byte. Offline examinations retain deterministic OpenCV Haar,
HOG, and frame-difference fallbacks rather than fabricating semantic findings.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..exporter import ExportError, export_segment
from ..storage import EvidenceStore, utc_now
from .model_registry import COCO_LABELS, FACE_MODEL, OBJECT_MODEL, describe_model, resolve_model


KINDS = {"motion", "object", "face"}


def _frame_limit() -> int:
    """Return an explicit safety cap; zero means process the whole segment."""
    try:
        return max(0, int(os.environ.get("SENTINEL_ANALYTICS_MAX_FRAMES", "0")))
    except ValueError:
        return 0


def _ffmpeg_info() -> Dict[str, Any]:
    system_path = shutil.which("ffmpeg")
    if system_path:
        return {"available": True, "path": system_path, "runtime": "system-ffmpeg"}
    try:
        import imageio_ffmpeg  # type: ignore

        path = imageio_ffmpeg.get_ffmpeg_exe()
        return {"available": bool(path), "path": path, "runtime": "imageio-ffmpeg"}
    except Exception as error:
        return {"available": False, "path": None, "runtime": None, "error": str(error)}


def capabilities() -> Dict[str, Any]:
    """Report runtime availability without probing or modifying evidence."""
    cv2, cv2_error = _load_cv2()
    object_model = os.environ.get("SENTINEL_OBJECT_MODEL", "")
    face_model = False
    if cv2 is not None:
        try:
            face_model = Path(cv2.data.haarcascades, "haarcascade_frontalface_default.xml").is_file()
        except AttributeError:
            face_model = False
    ffmpeg = _ffmpeg_info()
    auto_models = _env_flag("SENTINEL_AUTO_DOWNLOAD_MODELS", True)
    return {
        "ffmpeg": ffmpeg,
        "opencv": {"available": cv2 is not None, "error": cv2_error},
        "motion": {
            "available": cv2 is not None or ffmpeg["available"],
            "status_without_decoder": "not_configured" if cv2 is None and not ffmpeg["available"] else "available",
            "decoders": [name for name, available in (("opencv", cv2 is not None), ("ffmpeg", ffmpeg["available"])) if available],
        },
        "face": {
            "available": bool(cv2 is not None and face_model),
            "runtime": "opencv-haar-fallback" if face_model else None,
            "default_model": FACE_MODEL.key,
            "default_model_auto_download": auto_models,
            "default_model_provenance": describe_model(FACE_MODEL, auto_download=auto_models),
            "status_without_decoder": "not_configured" if not face_model else "available",
        },
        "object": {
            "available": cv2 is not None,
            "runtime": "opencv-dnn-configured" if object_model and Path(object_model).is_file() else "opencv-dnn-nanodet-auto" if cv2 is not None else None,
            "fallback_runtime": "opencv-hog-person" if cv2 is not None else None,
            "classes": list(COCO_LABELS) if cv2 is not None else [],
            "default_model": OBJECT_MODEL.key,
            "default_model_auto_download": auto_models,
            "default_model_provenance": describe_model(OBJECT_MODEL, auto_download=auto_models),
            "model_path_configured": bool(object_model),
            "status_without_model": "available" if cv2 is not None else "not_configured",
        },
    }


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _base_result(store: EvidenceStore, segment_id: str, kind: str, model: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    segment = store.get_segment(segment_id)
    if not segment:
        raise KeyError(f"Unknown segment: {segment_id}")
    evidence = store.get_evidence(segment["evidence_id"])
    if not evidence:
        raise KeyError(f"Unknown evidence: {segment['evidence_id']}")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(sorted(KINDS))}")
    started = utc_now()
    result = {
        "evidence_id": evidence["id"],
        "segment_id": segment_id,
        "kind": kind,
        "status": "not_configured",
        "model": model or "",
        "started_at": started,
        "completed_at": started,
        "findings": {
            "source_range": {
                "start_offset": segment["start_offset"],
                "end_offset": segment["end_offset"],
                "sha256": segment.get("source_sha256"),
            },
            "items": [],
        },
        "notes": "",
    }
    return result, segment


def _finish(result: Dict[str, Any], status: str, notes: str = "") -> Dict[str, Any]:
    result["status"] = status
    result["completed_at"] = utc_now()
    result["notes"] = notes
    return result


def _load_cv2() -> Tuple[Optional[Any], Optional[str]]:
    try:
        import cv2  # type: ignore
    except ImportError:
        return None, "OpenCV is not installed"
    return cv2, None


class _FrameStream:
    """Decode with OpenCV first and a bundled FFmpeg fallback second."""

    def __init__(self, cv2: Any, path: Path, limit: Optional[int] = None):
        self.cv2 = cv2
        self.path = path
        self.limit = _frame_limit() if limit is None else max(0, limit)
        self.decoder: Optional[str] = None
        self.error: Optional[str] = None
        self.frames = 0
        self._capture: Optional[Any] = None
        self._ffmpeg_process: Optional[subprocess.Popen[bytes]] = None
        self._ffmpeg_size: Optional[Tuple[int, int]] = None
        self._ffmpeg_numpy: Optional[Any] = None
        self._started_opencv = False
        self._finished = False

    def __iter__(self) -> "_FrameStream":
        return self

    def _start_opencv(self) -> None:
        self._started_opencv = True
        try:
            capture = self.cv2.VideoCapture(str(self.path))
            if capture.isOpened():
                self._capture = capture
            else:
                capture.release()
        except Exception as error:
            self.error = f"OpenCV decoder could not open the payload: {error}"

    def _start_ffmpeg(self) -> None:
        try:
            import numpy as np  # type: ignore

            ffmpeg = _ffmpeg_info()
            executable = ffmpeg.get("path")
            if not executable:
                raise RuntimeError("no system or packaged FFmpeg executable is available")
            probe = subprocess.run(
                [
                    executable,
                    "-hide_banner",
                    "-loglevel",
                    "info",
                    "-i",
                    str(self.path),
                    "-map",
                    "0:v:0",
                    "-frames:v",
                    "1",
                    "-f",
                    "null",
                    "-",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
            probe_text = (probe.stderr or b"").decode("utf-8", errors="replace")
            sizes = re.findall(r"(?<![0-9])(\d{2,6})x(\d{2,6})(?![0-9])", probe_text)
            if not sizes:
                raise ValueError("FFmpeg did not provide a valid decoded frame size")
            width, height = [int(value) for value in sizes[-1]]
            if width < 1 or height < 1:
                raise ValueError("FFmpeg returned an invalid frame size")
            process = subprocess.Popen(
                [
                    executable,
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-nostdin",
                    "-i",
                    str(self.path),
                    "-map",
                    "0:v:0",
                    "-an",
                    "-f",
                    "rawvideo",
                    "-pix_fmt",
                    "bgr24",
                    "-vsync",
                    "0",
                    "-",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            self._ffmpeg_size = (width, height)
            self._ffmpeg_process = process
            self._ffmpeg_numpy = np
        except Exception as error:
            self.error = f"Bundled FFmpeg decoder could not open the payload: {error}"
            self._ffmpeg_process = None

    def _finish_ffmpeg(self) -> None:
        process = self._ffmpeg_process
        if process is not None:
            return_code = process.poll()
            if return_code not in (None, 0):
                self.error = f"FFmpeg exited with status {return_code} while decoding the payload"
        self._finished = True
        self.close()
        raise StopIteration

    def __next__(self) -> Tuple[int, Any]:
        if self.limit and self.frames >= self.limit:
            self._finished = True
            self.close()
            raise StopIteration
        if not self._started_opencv:
            self._start_opencv()
        if self._capture is not None:
            ok, frame = self._capture.read()
            if ok and frame is not None:
                index = self.frames
                self.frames += 1
                self.decoder = "opencv"
                return index, frame
            self._capture.release()
            self._capture = None
            # A decoder can open a raw/proprietary-looking suffix and still
            # produce no frames. Give the bundled FFmpeg runtime a chance.
            if self.frames == 0:
                self._start_ffmpeg()
        elif self._ffmpeg_process is None:
            self._start_ffmpeg()
        if self._ffmpeg_process is not None:
            process = self._ffmpeg_process
            width, height = self._ffmpeg_size or (0, 0)
            expected = width * height * 3
            try:
                raw = process.stdout.read(expected) if process.stdout is not None else b""
            except Exception as error:
                self.error = f"FFmpeg stopped while decoding the payload: {error}"
                self.close()
                raise RuntimeError(self.error) from error
            if not raw:
                return self._finish_ffmpeg()
            if len(raw) != expected:
                self.error = f"FFmpeg returned an incomplete frame ({len(raw)} of {expected} bytes)"
                self.close()
                raise RuntimeError(self.error)
            frame = self._ffmpeg_numpy.frombuffer(raw, dtype=self._ffmpeg_numpy.uint8).reshape((height, width, 3)).copy()
            index = self.frames
            self.frames += 1
            self.decoder = "ffmpeg"
            return index, frame
        self._finished = True
        self.close()
        raise StopIteration

    def close(self) -> None:
        if self._capture is not None:
            try:
                self._capture.release()
            except Exception:
                pass
            self._capture = None
        if self._ffmpeg_process is not None:
            process = self._ffmpeg_process
            self._ffmpeg_process = None
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except Exception:
                pass
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=2)
            except Exception:
                pass
            self._ffmpeg_numpy = None


def _process_frames(cv2: Any, media_path: Path, callback: Callable[[int, Any], None]) -> Tuple[int, Optional[str], Optional[str]]:
    stream = _FrameStream(cv2, media_path)
    callback_error: Optional[str] = None
    try:
        for frame_index, frame in stream:
            try:
                callback(frame_index, frame)
            except Exception as error:
                callback_error = str(error)
                break
    except Exception as error:
        callback_error = str(error)
    finally:
        stream.close()
    return stream.frames, stream.decoder, callback_error or stream.error


def _decode_note(decoder: Optional[str], error: Optional[str]) -> str:
    note = f"Frames decoded with {decoder or 'no available'} runtime."
    if error:
        note += f" Decoder warning: {error}"
    return note


def _run_motion(result: Dict[str, Any], media_path: Path, cv2: Any) -> Dict[str, Any]:
    previous = None
    items: List[Dict[str, Any]] = []

    def process(frame_index: int, frame: Any) -> None:
        nonlocal previous
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.resize(gray, (320, 180))
        if previous is not None:
            difference = cv2.absdiff(previous, gray)
            score = float(difference.mean())
            if score >= 12.0:
                _, mask = cv2.threshold(difference, 18, 255, cv2.THRESH_BINARY)
                contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                regions = []
                for contour in contours:
                    area = float(cv2.contourArea(contour))
                    if area < 20:
                        continue
                    x, y, width, height = [int(value) for value in cv2.boundingRect(contour)]
                    regions.append({"bbox": [x, y, width, height], "area": round(area, 2)})
                items.append({
                    "frame": frame_index,
                    "score": round(score, 4),
                    "type": "frame_change",
                    "regions": regions[:50],
                })
        previous = gray

    count, decoder, error = _process_frames(cv2, media_path, process)
    if count == 0:
        return _finish(result, "unsupported", error or "No configured decoder could return a frame")
    result["findings"].update({
        "frames_examined": count,
        "items": items,
        "threshold": 12.0,
        "decoder": decoder,
    })
    return _finish(result, "complete", _decode_note(decoder, error) + " Motion remains a frame-change signal; no semantic object identity is inferred.")


def _letterbox(image: Any, cv2: Any, target: int = 416) -> Tuple[Any, Tuple[int, int, int, int]]:
    import numpy as np

    height, width = image.shape[:2]
    scale = min(target / max(width, 1), target / max(height, 1))
    new_width = max(1, int(round(width * scale)))
    new_height = max(1, int(round(height * scale)))
    resized = cv2.resize(image, (new_width, new_height), interpolation=cv2.INTER_AREA)
    top = (target - new_height) // 2
    left = (target - new_width) // 2
    canvas = np.zeros((target, target, 3), dtype=resized.dtype)
    canvas[top:top + new_height, left:left + new_width] = resized
    return canvas, (top, left, new_height, new_width)


def _nanodet_anchors() -> List[Any]:
    import numpy as np

    anchors = []
    for stride in (8, 16, 32, 64):
        feature = 416 // stride
        shift_x = np.arange(feature) * stride
        shift_y = np.arange(feature) * stride
        xv, yv = np.meshgrid(shift_x, shift_y)
        anchors.append(np.column_stack((xv.flatten() + 0.5 * (stride - 1), yv.flatten() + 0.5 * (stride - 1))))
    return anchors


def _nanodet_predictions(cv2: Any, net: Any, frame: Any) -> List[Dict[str, Any]]:
    import numpy as np

    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    input_image, scale = _letterbox(rgb, cv2)
    normalized = input_image.astype(np.float32)
    normalized = (normalized - np.array([103.53, 116.28, 123.675], dtype=np.float32)) / np.array([57.375, 57.12, 58.395], dtype=np.float32)
    net.setInput(cv2.dnn.blobFromImage(normalized))
    outputs = net.forward(net.getUnconnectedOutLayersNames())
    if len(outputs) < 2 or len(outputs) % 2:
        raise ValueError("NanoDet returned an unexpected output tensor set")
    anchors_by_level = _nanodet_anchors()
    boxes: List[List[int]] = []
    scores: List[float] = []
    classes: List[int] = []
    for level, (cls_output, box_output) in enumerate(zip(outputs[::2], outputs[1::2])):
        stride = (8, 16, 32, 64)[level]
        cls_output = np.asarray(cls_output)
        box_output = np.asarray(box_output)
        if cls_output.ndim == 3:
            cls_output = cls_output.squeeze(axis=0)
        if box_output.ndim == 3:
            box_output = box_output.squeeze(axis=0)
        anchors = anchors_by_level[level]
        count = min(len(anchors), cls_output.shape[0], box_output.reshape(-1, 32).shape[0])
        cls_output = cls_output.reshape(-1, cls_output.shape[-1])[:count]
        distances = box_output.reshape(-1, 32)[:count]
        logits = distances.reshape(-1, 4, 8)
        logits = logits - logits.max(axis=2, keepdims=True)
        probabilities = np.exp(logits)
        probabilities /= probabilities.sum(axis=2, keepdims=True)
        distances = (probabilities * np.arange(8, dtype=np.float32)).sum(axis=2) * stride
        left = anchors[:count, 0] - distances[:, 0]
        top = anchors[:count, 1] - distances[:, 1]
        right = anchors[:count, 0] + distances[:, 2]
        bottom = anchors[:count, 1] + distances[:, 3]
        for row, x1, y1, x2, y2 in zip(cls_output, left, top, right, bottom):
            class_id = int(np.argmax(row))
            confidence = float(row[class_id])
            if confidence < 0.35:
                continue
            boxes.append([int(x1), int(y1), max(1, int(x2 - x1)), max(1, int(y2 - y1))])
            scores.append(confidence)
            classes.append(class_id)
    selected = cv2.dnn.NMSBoxes(boxes, scores, 0.35, 0.60) if boxes else []
    height, width = frame.shape[:2]
    top, left, new_height, new_width = scale
    findings = []
    for selected_index in selected:
        index = int(selected_index[0]) if hasattr(selected_index, "__len__") else int(selected_index)
        x, y, box_width, box_height = boxes[index]
        x1 = max(0, min(width, int((x - left) * width / new_width)))
        y1 = max(0, min(height, int((y - top) * height / new_height)))
        x2 = max(x1 + 1, min(width, int((x + box_width - left) * width / new_width)))
        y2 = max(y1 + 1, min(height, int((y + box_height - top) * height / new_height)))
        class_id = classes[index]
        findings.append({
            "class_id": class_id,
            "label": COCO_LABELS[class_id] if class_id < len(COCO_LABELS) else f"class_{class_id}",
            "confidence": round(scores[index], 4),
            "bbox": [x1, y1, x2 - x1, y2 - y1],
        })
    return findings


def _run_nanodet(result: Dict[str, Any], media_path: Path, cv2: Any, model_path: Path, provenance: Dict[str, Any]) -> Dict[str, Any]:
    try:
        net = cv2.dnn.readNet(str(model_path))
    except Exception as error:
        return _finish(result, "unsupported", f"Verified default object model could not be loaded: {error}")
    items: List[Dict[str, Any]] = []

    def process(frame_index: int, frame: Any) -> None:
        for item in _nanodet_predictions(cv2, net, frame):
            items.append(dict(item, frame=frame_index))

    count, decoder, error = _process_frames(cv2, media_path, process)
    if count == 0:
        return _finish(result, "unsupported", error or "No configured decoder could return a frame")
    result["model"] = str(model_path)
    result["findings"].update({
        "frames_examined": count,
        "items": items,
        "runtime": "opencv-dnn-nanodet-coco",
        "model_path": str(model_path),
        "model_provenance": provenance,
        "decoder": decoder,
    })
    return _finish(result, "complete", _decode_note(decoder, error) + " Default NanoDet covers the COCO object classes; detections are not identity claims.")


def _run_hog(result: Dict[str, Any], media_path: Path, cv2: Any, model_status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        hog = cv2.HOGDescriptor()
        hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
    except Exception as error:
        return _finish(result, "unsupported", f"Built-in people detector unavailable: {error}")
    items: List[Dict[str, Any]] = []

    def process(frame_index: int, frame: Any) -> None:
        # OpenCV's default pedestrian window is 64x128. Some DVR thumbnails
        # are smaller than that and older OpenCV builds can abort in native code
        # instead of returning an empty detection set. Upscale only for the
        # detector and map boxes back to the original frame coordinates.
        height, width = frame.shape[:2]
        scale = max(1.0, 128.0 / max(height, 1), 64.0 / max(width, 1))
        detector_frame = frame
        if scale > 1.0:
            detector_frame = cv2.resize(frame, (max(64, int(round(width * scale))), max(128, int(round(height * scale)))))
        boxes, weights = hog.detectMultiScale(detector_frame, winStride=(8, 8), padding=(8, 8), scale=1.05)
        for box, weight in zip(boxes, weights):
            x, y, box_width, box_height = [int(round(value / scale)) for value in box]
            confidence = float(weight[0] if hasattr(weight, "__len__") else weight)
            items.append({
                "frame": frame_index,
                "class_id": 0,
                "label": "person",
                "confidence": round(confidence, 4),
                "bbox": [x, y, box_width, box_height],
            })

    count, decoder, error = _process_frames(cv2, media_path, process)
    if count == 0:
        return _finish(result, "unsupported", error or "No configured decoder could return a frame")
    result["findings"].update({
        "frames_examined": count,
        "items": items,
        "runtime": "opencv-hog-person",
        "model_path": None,
        "decoder": decoder,
        "extended_model": model_status,
    })
    note = _decode_note(decoder, error) + " Offline fallback detects people only."
    if model_status and model_status.get("error"):
        note += f" Extended COCO model was not used: {model_status['error']}"
    return _finish(result, "complete", note)


def _run_custom_object(result: Dict[str, Any], media_path: Path, cv2: Any, model_path: Path) -> Dict[str, Any]:
    try:
        net = cv2.dnn.readNetFromONNX(str(model_path))
    except Exception as error:
        return _finish(result, "unsupported", f"Configured object model could not be loaded by OpenCV DNN: {error}")
    labels = []
    labels_path = os.environ.get("SENTINEL_OBJECT_LABELS", "")
    if labels_path and Path(labels_path).is_file():
        labels = [line.strip() for line in Path(labels_path).read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    items: List[Dict[str, Any]] = []

    def process(frame_index: int, frame: Any) -> None:
        height, width = frame.shape[:2]
        blob = cv2.dnn.blobFromImage(frame, 1 / 255.0, (640, 640), swapRB=True, crop=False)
        net.setInput(blob)
        output = net.forward()
        if not hasattr(output, "shape") or len(output.shape) < 2:
            raise ValueError("Configured object model returned an unsupported output tensor")
        rows = output.reshape(-1, output.shape[-1])
        boxes: List[List[int]] = []
        scores: List[float] = []
        classes: List[int] = []
        for row in rows:
            if len(row) < 6:
                continue
            objectness = float(row[4]) if len(row) > 6 else 1.0
            class_offset = 5 if len(row) > 6 else 4
            class_index = class_offset
            class_score = float(row[class_offset])
            for index in range(class_offset, len(row)):
                value = float(row[index])
                if value > class_score:
                    class_score, class_index = value, index
            score = objectness * class_score
            if score < 0.35:
                continue
            center_x, center_y, box_width, box_height = [float(value) for value in row[:4]]
            if max(abs(center_x), abs(center_y), abs(box_width), abs(box_height)) <= 2:
                center_x, box_width = center_x * width, box_width * width
                center_y, box_height = center_y * height, box_height * height
            x = max(0, int(center_x - box_width / 2))
            y = max(0, int(center_y - box_height / 2))
            w = min(width - x, max(1, int(box_width)))
            h = min(height - y, max(1, int(box_height)))
            boxes.append([x, y, w, h])
            scores.append(float(score))
            classes.append(max(0, class_index - class_offset))
        selected = cv2.dnn.NMSBoxes(boxes, scores, 0.35, 0.45) if boxes else []
        for selected_index in selected:
            index = int(selected_index[0]) if hasattr(selected_index, "__len__") else int(selected_index)
            class_id = classes[index]
            items.append({
                "frame": frame_index,
                "class_id": class_id,
                "label": labels[class_id] if class_id < len(labels) else f"class_{class_id}",
                "confidence": round(scores[index], 4),
                "bbox": boxes[index],
            })

    count, decoder, error = _process_frames(cv2, media_path, process)
    if count == 0:
        return _finish(result, "unsupported", error or "No configured decoder could return a frame")
    result["model"] = str(model_path)
    result["findings"].update({
        "frames_examined": count,
        "items": items,
        "runtime": "opencv-dnn-configured",
        "model_path": str(model_path),
        "model_sha256": _sha256(model_path),
        "decoder": decoder,
    })
    return _finish(result, "complete", _decode_note(decoder, error) + " Object labels depend on the configured ONNX model and optional label file.")


def _run_object(result: Dict[str, Any], store_root: Path, media_path: Path, cv2: Any, model: str) -> Dict[str, Any]:
    model_path_text = model or os.environ.get("SENTINEL_OBJECT_MODEL", "")
    if model_path_text:
        model_path = Path(model_path_text).expanduser()
        if not model_path.is_file():
            return _finish(result, "not_configured", f"Configured object model was not found: {model_path}")
        return _run_custom_object(result, media_path, cv2, model_path)

    default_path, provenance = resolve_model(OBJECT_MODEL, store_root)
    if default_path is not None:
        detected = _run_nanodet(result, media_path, cv2, default_path, provenance)
        if detected["status"] == "complete":
            return detected
        provenance = dict(provenance, status="unusable", error=detected.get("notes", "Default object model could not produce findings"))
    # A disconnected lab should still get deterministic people analytics. The
    # failed/disabled model resolution remains in the result for auditability.
    return _run_hog(result, media_path, cv2, provenance)


def _run_yunet(result: Dict[str, Any], media_path: Path, cv2: Any, model_path: Path, provenance: Dict[str, Any]) -> Dict[str, Any]:
    if not hasattr(cv2, "FaceDetectorYN_create"):
        return _finish(result, "unsupported", "This OpenCV build does not expose the YuNet face detector")
    try:
        detector = cv2.FaceDetectorYN_create(str(model_path), "", (320, 320), 0.6, 0.3, 5000)
    except Exception as error:
        return _finish(result, "unsupported", f"Verified YuNet face model could not be loaded: {error}")
    items: List[Dict[str, Any]] = []

    def process(frame_index: int, frame: Any) -> None:
        height, width = frame.shape[:2]
        detector.setInputSize((width, height))
        _, faces = detector.detect(frame)
        if faces is None:
            return
        for face_index, face in enumerate(faces):
            values = [float(value) for value in face]
            x, y, box_width, box_height = [int(round(value)) for value in values[:4]]
            items.append({
                "frame": frame_index,
                "face_index": f"face-{frame_index:06d}-{face_index:02d}",
                "bbox": [x, y, box_width, box_height],
                "landmarks": [[round(values[index], 2), round(values[index + 1], 2)] for index in range(4, min(14, len(values) - 1), 2)],
                "confidence": round(values[-1], 4),
                "identity": None,
            })

    count, decoder, error = _process_frames(cv2, media_path, process)
    if count == 0:
        return _finish(result, "unsupported", error or "No configured decoder could return a frame")
    result["model"] = str(model_path)
    result["findings"].update({
        "frames_examined": count,
        "items": items,
        "detector": "opencv-yunet",
        "model_path": str(model_path),
        "model_provenance": provenance,
        "decoder": decoder,
    })
    return _finish(result, "complete", _decode_note(decoder, error) + " Faces are indexed as detections only; no person identity or biometric match is asserted.")


def _run_haar(result: Dict[str, Any], media_path: Path, cv2: Any, model: str, provenance: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cascade_path = ""
    try:
        cascade_path = str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml")
    except AttributeError:
        pass
    if not cascade_path or not Path(cascade_path).is_file():
        return _finish(result, "not_configured", "No bundled or verified face detector is available")
    cascade = cv2.CascadeClassifier(cascade_path)
    if cascade.empty():
        return _finish(result, "not_configured", "Bundled face detector could not be loaded")
    items: List[Dict[str, Any]] = []

    def process(frame_index: int, frame: Any) -> None:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(24, 24))
        for face_index, (x, y, width, height) in enumerate(faces):
            items.append({
                "frame": frame_index,
                "face_index": f"face-{frame_index:06d}-{face_index:02d}",
                "bbox": [int(x), int(y), int(width), int(height)],
                "identity": None,
            })

    count, decoder, error = _process_frames(cv2, media_path, process)
    if count == 0:
        return _finish(result, "unsupported", error or "No configured decoder could return a frame")
    result["findings"].update({
        "frames_examined": count,
        "items": items,
        "detector": model or "opencv-haar",
        "decoder": decoder,
        "default_model": provenance,
    })
    note = _decode_note(decoder, error) + " Faces are indexed as detections only; no person identity or biometric match is asserted."
    if provenance and provenance.get("error"):
        note += f" Higher-accuracy YuNet model was not used: {provenance['error']}"
    return _finish(result, "complete", note)


def _run_face(result: Dict[str, Any], store_root: Path, media_path: Path, cv2: Any, model: str) -> Dict[str, Any]:
    # An explicitly supplied face model remains supported for compatibility,
    # but it is never interpreted as an identity model.
    if model:
        explicit = Path(model).expanduser()
        if not explicit.is_file():
            return _finish(result, "not_configured", f"Configured face model was not found: {explicit}")
        return _run_yunet(result, media_path, cv2, explicit, {"key": "configured", "path": str(explicit), "actual_sha256": _sha256(explicit), "status": "available"})
    yunet_path, provenance = resolve_model(FACE_MODEL, store_root)
    if yunet_path is not None:
        detected = _run_yunet(result, media_path, cv2, yunet_path, provenance)
        if detected["status"] == "complete":
            return detected
    return _run_haar(result, media_path, cv2, "opencv-haar", provenance)


def run_analytics(store: EvidenceStore, segment_id: str, kind: str, model: str = "") -> Dict[str, Any]:
    result, segment = _base_result(store, segment_id, kind, model)
    media: Optional[Dict[str, Any]] = None
    try:
        media = export_segment(store, segment_id, "media")
    except ExportError as error:
        return store.save_analytics(_finish(result, "unsupported", str(error)))
    result["findings"]["media_artifact"] = {
        "path": media["path"],
        "sha256": media["sha256"],
        "size": media["size"],
        "payload_range": media.get("payload_range"),
        "native_sha256": media.get("native_sha256"),
    }
    cv2, import_error = _load_cv2()
    ffmpeg = _ffmpeg_info()
    if cv2 is None and not ffmpeg["available"]:
        return store.save_analytics(_finish(result, "not_configured", import_error or "No video analytics runtime is installed"))
    if cv2 is None:
        return store.save_analytics(_finish(result, "not_configured", "OpenCV is not installed; install the standard analytics dependencies"))
    media_path = Path(str(media["path"]))
    try:
        if kind == "motion":
            result = _run_motion(result, media_path, cv2)
        elif kind == "face":
            result = _run_face(result, store.root, media_path, cv2, model)
        else:
            result = _run_object(result, store.root, media_path, cv2, model)
    except Exception as error:  # optional decoder/model failures are findings, not server failures
        result = _finish(result, "unsupported", f"Analytics runtime could not process this payload: {error}")
    return store.save_analytics(result)
