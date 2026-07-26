from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DISPOSITIONS = {"confirmed", "false_positive", "needs_review"}
SEVERITIES = {"low", "medium", "high", "critical"}


def event_fingerprint(event: dict[str, Any]) -> str:
    """Return a stable identifier without exposing event contents."""
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def load_feedback(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def feedback_index(path: Path) -> dict[str, dict[str, Any]]:
    return {
        record["event_key"]: record
        for record in load_feedback(path)
        if record.get("event_key")
    }


def save_feedback(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    temporary.replace(path)


def upsert_feedback(
    path: Path,
    event: dict[str, Any],
    *,
    original_severity: str,
    analyst_severity: str,
    disposition: str,
    notes: str = "",
) -> dict[str, Any]:
    normalized_severity = analyst_severity.lower()
    if normalized_severity not in SEVERITIES:
        raise ValueError(f"Unsupported severity: {analyst_severity}")
    if disposition not in DISPOSITIONS:
        raise ValueError(f"Unsupported disposition: {disposition}")

    event_key = event_fingerprint(event)
    record = {
        "event_key": event_key,
        "original_severity": original_severity.lower(),
        "analyst_severity": normalized_severity,
        "disposition": disposition,
        "notes": notes.strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    records = load_feedback(path)
    updated = False
    for index, existing in enumerate(records):
        if existing.get("event_key") == event_key:
            records[index] = record
            updated = True
            break
    if not updated:
        records.append(record)

    save_feedback(path, records)
    return record
