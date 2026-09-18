"""Timestamp normalization and bounded cross-camera correlation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


def normalize_timestamp(value: Any) -> Dict[str, Any]:
    """Return an auditable UTC representation without inventing missing times."""
    if value is None or value == "":
        return {"value": None, "utc": None, "precision": "unknown", "assumption": None}
    original = str(value)
    parsed: Optional[datetime] = None
    precision = "second"
    if isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
            precision = "subsecond" if not float(value).is_integer() else "second"
        except (OverflowError, OSError, ValueError):
            parsed = None
    if parsed is None:
        candidate = original.strip()
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            parsed = None
    if parsed is None:
        return {"value": original, "utc": None, "precision": "unparsed", "assumption": None}
    assumption = None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
        assumption = "timezone_not_present_assumed_utc"
    normalized = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if parsed.microsecond:
        precision = "subsecond"
    return {"value": original, "utc": normalized, "precision": precision, "assumption": assumption}


def _timestamp_for(segment: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = segment.get(key)
    return normalize_timestamp(value)


def build_timeline(segments: Iterable[Dict[str, Any]], tolerance_seconds: float = 2.0) -> Dict[str, Any]:
    """Normalize segment timestamps and correlate events across channels.

    Correlation is deliberately conservative: events are grouped only when
    they have parseable timestamps and their intervals are within the supplied
    tolerance. Untimed carvings remain visible, but are never assigned a time
    merely because a neighboring camera has one.
    """
    if tolerance_seconds < 0 or tolerance_seconds > 3600:
        raise ValueError("tolerance_seconds must be between 0 and 3600")
    events: List[Dict[str, Any]] = []
    for segment in segments:
        start = _timestamp_for(segment, "start_time")
        end = _timestamp_for(segment, "end_time")
        event = {
            "event_id": segment["id"],
            "evidence_id": segment["evidence_id"],
            "channel": segment.get("channel"),
            "kind": "media_segment",
            "state": segment.get("state"),
            "codec": segment.get("codec"),
            "physical_range": {
                "start_offset": segment["start_offset"],
                "end_offset": segment["end_offset"],
                "size": segment.get("size", max(0, segment["end_offset"] - segment["start_offset"])),
            },
            "source_sha256": segment.get("source_sha256"),
            "start": start,
            "end": end,
            "correlation_id": None,
        }
        events.append(event)

    timed = [event for event in events if event["start"]["utc"]]
    timed.sort(key=lambda event: (event["start"]["utc"], event["channel"] is None, event["event_id"]))
    groups: List[Dict[str, Any]] = []

    def seconds(value: str) -> float:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

    for event in timed:
        start = seconds(event["start"]["utc"])
        end_value = event["end"]["utc"] or event["start"]["utc"]
        end = max(start, seconds(end_value))
        matched: List[Dict[str, Any]] = []
        for group in groups:
            if start <= group["end"] + tolerance_seconds and end >= group["start"] - tolerance_seconds:
                # A correlation group is useful specifically across camera
                # channels. Same-channel overlap is retained as a timeline but
                # does not make a cross-camera correlation by itself.
                matched.append(group)
        if matched:
            target = matched[0]
            target["start"] = min(target["start"], start)
            target["end"] = max(target["end"], end)
            target["event_ids"].append(event["event_id"])
            target["channels"].append(event["channel"])
            event["correlation_id"] = target["correlation_id"]
            for other in matched[1:]:
                target["start"] = min(target["start"], other["start"])
                target["end"] = max(target["end"], other["end"])
                target["event_ids"].extend(other["event_ids"])
                target["channels"].extend(other["channels"])
                for candidate in events:
                    if candidate["event_id"] in other["event_ids"]:
                        candidate["correlation_id"] = target["correlation_id"]
                groups.remove(other)
        else:
            correlation_id = f"CORR-{len(groups) + 1:04d}"
            event["correlation_id"] = correlation_id
            groups.append({
                "correlation_id": correlation_id,
                "start": start,
                "end": end,
                "event_ids": [event["event_id"]],
                "channels": [event["channel"]],
            })

    correlations = []
    for group in groups:
        unique_channels = sorted({channel for channel in group["channels"] if channel is not None})
        if len(unique_channels) < 2:
            continue
        correlations.append({
            "correlation_id": group["correlation_id"],
            "event_ids": group["event_ids"],
            "channels": unique_channels,
            "start": datetime.fromtimestamp(group["start"], timezone.utc).isoformat().replace("+00:00", "Z"),
            "end": datetime.fromtimestamp(group["end"], timezone.utc).isoformat().replace("+00:00", "Z"),
            "basis": f"normalized timestamps within {tolerance_seconds:g} seconds",
        })
    events.sort(key=lambda event: (event["start"]["utc"] is None, event["start"]["utc"] or "", event["physical_range"]["start_offset"]))
    return {
        "tolerance_seconds": tolerance_seconds,
        "events": events,
        "correlations": correlations,
        "limitations": [
            "A timestamp without timezone is normalized with an explicit assumed-UTC marker.",
            "Untimed segments are not assigned a wall-clock time and cannot form a synchronized correlation.",
            "Correlation indicates temporal proximity only; it does not establish that cameras share a calibrated clock.",
        ],
    }
