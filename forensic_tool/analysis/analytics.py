"""Optional, post-acquisition media analytics.

Analytics never changes acquired evidence. Every run records the exact native
range hash, the optional demuxed artifact hash, the decoder/model status, and
an explicit result when a dependency is absent or cannot decode the media.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..exporter import ExportError, export_segment
from ..storage import EvidenceStore, utc_now


KINDS = {"motion", "object", "face"}


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


def _open_video(cv2: Any, path: Path) -> Tuple[Optional[Any], Optional[str]]:
    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        capture.release()
        return None, "No configured decoder could open this media payload"
    return capture, None


def _run_motion(result: Dict[str, Any], media_path: Path, cv2: Any) -> Dict[str, Any]:
    capture, error = _open_video(cv2, media_path)
    if capture is None:
        return _finish(result, "unsupported", error or "Media decoder unavailable")
    previous = None
    frame_index = 0
    items: List[Dict[str, Any]] = []
    try:
        while frame_index < 300:
            ok, frame = capture.read()
            if not ok:
                break
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.resize(gray, (320, 180))
            if previous is not None:
                difference = cv2.absdiff(previous, gray)
                score = float(difference.mean())
                # This is a reproducible motion-change signal, not a claim that
                # a person/object caused the change.
                if score >= 12.0:
                    items.append({"frame": frame_index, "score": round(score, 4), "type": "frame_change"})
            previous = gray
            frame_index += 1
    finally:
        capture.release()
    if frame_index == 0:
        return _finish(result, "unsupported", "Decoder opened the payload but returned no frames")
    result["findings"].update({"frames_examined": frame_index, "items": items, "threshold": 12.0})
    return _finish(result, "complete", "Motion is a frame-difference signal; no semantic object identity is inferred.")


def _run_face(result: Dict[str, Any], media_path: Path, cv2: Any, model: str) -> Dict[str, Any]:
    cascade_path = ""
    try:
        cascade_path = str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml")
    except AttributeError:
        pass
    if not cascade_path or not Path(cascade_path).is_file():
        return _finish(result, "not_configured", "No face detector model is configured")
    cascade = cv2.CascadeClassifier(cascade_path)
    if cascade.empty():
        return _finish(result, "not_configured", "Configured face detector model could not be loaded")
    capture, error = _open_video(cv2, media_path)
    if capture is None:
        return _finish(result, "unsupported", error or "Media decoder unavailable")
    items: List[Dict[str, Any]] = []
    frame_index = 0
    try:
        while frame_index < 300:
            ok, frame = capture.read()
            if not ok:
                break
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(24, 24))
            for face_index, (x, y, width, height) in enumerate(faces):
                items.append({
                    "frame": frame_index,
                    "face_index": f"face-{frame_index:06d}-{face_index:02d}",
                    "bbox": [int(x), int(y), int(width), int(height)],
                    "identity": None,
                })
            frame_index += 1
    finally:
        capture.release()
    if frame_index == 0:
        return _finish(result, "unsupported", "Decoder opened the payload but returned no frames")
    result["findings"].update({"frames_examined": frame_index, "items": items, "detector": model or "opencv-haar"})
    return _finish(result, "complete", "Faces are indexed as detections only; no person identity or biometric match is asserted.")


def _run_object(result: Dict[str, Any], media_path: Path, cv2: Any, model: str) -> Dict[str, Any]:
    model_path = model or os.environ.get("SENTINEL_OBJECT_MODEL", "")
    if not model_path or not Path(model_path).is_file():
        return _finish(result, "not_configured", "Object detection requires a configured ONNX model path (SENTINEL_OBJECT_MODEL or model parameter)")
    try:
        net = cv2.dnn.readNetFromONNX(model_path)
    except Exception as error:  # OpenCV emits model-specific exceptions
        return _finish(result, "unsupported", f"Configured object model could not be loaded by OpenCV DNN: {error}")
    labels = []
    labels_path = os.environ.get("SENTINEL_OBJECT_LABELS", "")
    if labels_path and Path(labels_path).is_file():
        labels = [line.strip() for line in Path(labels_path).read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    capture, error = _open_video(cv2, media_path)
    if capture is None:
        return _finish(result, "unsupported", error or "Media decoder unavailable")
    items: List[Dict[str, Any]] = []
    frame_index = 0
    try:
        while frame_index < 300:
            ok, frame = capture.read()
            if not ok:
                break
            height, width = frame.shape[:2]
            try:
                blob = cv2.dnn.blobFromImage(frame, 1 / 255.0, (640, 640), swapRB=True, crop=False)
                net.setInput(blob)
                output = net.forward()
            except Exception as model_error:
                capture.release()
                return _finish(result, "unsupported", f"Configured object model could not process a frame: {model_error}")
            if not hasattr(output, "shape") or len(output.shape) < 2:
                capture.release()
                return _finish(result, "unsupported", "Configured object model returned an unsupported output tensor")
            rows = output.reshape(-1, output.shape[-1])
            boxes = []
            scores = []
            classes = []
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
                # YOLO ONNX exports usually use normalized coordinates; accept
                # pixel coordinates as well when they exceed the unit range.
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
            frame_index += 1
    finally:
        capture.release()
    if frame_index == 0:
        return _finish(result, "unsupported", "Decoder opened the payload but returned no frames")
    result["findings"].update({"frames_examined": frame_index, "items": items, "runtime": "opencv-dnn", "model_path": model_path})
    return _finish(result, "complete", "Object labels depend on the configured ONNX model and optional label file.")


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
    if cv2 is None:
        return store.save_analytics(_finish(result, "not_configured", import_error or "OpenCV is not installed"))
    media_path = Path(str(media["path"]))
    try:
        if kind == "motion":
            result = _run_motion(result, media_path, cv2)
        elif kind == "face":
            result = _run_face(result, media_path, cv2, model)
        else:
            result = _run_object(result, media_path, cv2, model)
    except Exception as error:  # optional decoder/model failures are findings, not server failures
        result = _finish(result, "unsupported", f"Analytics runtime could not process this payload: {error}")
    return store.save_analytics(result)
