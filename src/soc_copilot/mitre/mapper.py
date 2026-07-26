from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from soc_copilot.config import load_settings

TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@lru_cache(maxsize=1)
def _load_mitre_index(path: str | None = None) -> list[dict]:
    cfg = load_settings()
    index_path = Path(path) if path else cfg.mitre_index
    with open(index_path, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_mitre_techniques(path: str | None = None) -> dict[str, str]:
    """
    Load a name/alias -> technique id lookup table from the slim MITRE index.

    Returns dict mapping lowercase names and aliases to technique IDs (e.g. T1059.001).
    """
    lookup: dict[str, str] = {}
    for entry in _load_mitre_index(path):
        technique_id = entry["id"]
        lookup[entry["name"].lower()] = technique_id
        for alias in entry.get("aliases", []):
            lookup[alias.lower()] = technique_id
    return lookup


def _canonical_name(technique_id: str, path: str | None = None) -> str:
    for entry in _load_mitre_index(path):
        if entry["id"].upper() == technique_id.upper():
            return entry["name"]
    return technique_id


def _lookup_by_name(guess_lower: str, technique_db: dict[str, str]) -> str | None:
    if guess_lower in technique_db:
        return technique_db[guess_lower]

    for name, tid in technique_db.items():
        if name in guess_lower or guess_lower in name:
            return tid
    return None


def map_to_mitre(technique_guess: str, technique_db: dict[str, str] | None = None) -> str:
    """Map an LLM technique guess to a MITRE ATT&CK ID and canonical name."""
    if not technique_guess or technique_guess.lower() in {
        "not applicable",
        "n/a",
        "no specific mitre technique identified",
        "no specific mitre technique name applicable",
        "parse error",
    }:
        return "Unmapped"

    db = technique_db or load_mitre_techniques()
    guess_lower = technique_guess.lower()

    id_match = TECHNIQUE_ID_PATTERN.search(technique_guess)
    if id_match:
        technique_id = id_match.group(0).upper()
        return f"{technique_id} ({_canonical_name(technique_id)})"

    technique_id = _lookup_by_name(guess_lower, db)
    if technique_id:
        return f"{technique_id} ({_canonical_name(technique_id)})"

    return "Unmapped"


def mitre_url(value: str) -> str | None:
    """Build an ATT&CK technique URL from an ID or mapped technique label."""
    match = TECHNIQUE_ID_PATTERN.search(value or "")
    if not match:
        return None
    technique_id = match.group(0).upper().replace(".", "/")
    return f"https://attack.mitre.org/techniques/{technique_id}/"
