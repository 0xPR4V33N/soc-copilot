from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from soc_copilot.config import Settings, load_settings
from soc_copilot.mitre.mapper import load_mitre_techniques, map_to_mitre
from soc_copilot.triage.llm import triage_event
from soc_copilot.triage.rules import rule_triage


def parse_triage_record(triage: Any) -> dict[str, Any]:
    """Support legacy string-encoded triage and new object schema."""
    if isinstance(triage, dict):
        return triage
    if isinstance(triage, str):
        try:
            parsed = json.loads(triage)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {
        "severity": "unknown",
        "technique_guess": "parse error",
        "summary": "N/A",
        "source": "unknown",
    }


def enrich_with_mitre(triage: dict[str, Any], technique_db: dict[str, str] | None = None) -> dict[str, Any]:
    db = technique_db or load_mitre_techniques()
    enriched = dict(triage)
    if not enriched.get("mitre"):
        enriched["mitre"] = map_to_mitre(enriched.get("technique_guess", ""), db)
    return enriched


def hybrid_triage(
    event: dict,
    settings: Settings | None = None,
    llm_triage=triage_event,
) -> dict[str, Any]:
    """Use deterministic rules when they match, otherwise fall back to the local LLM."""
    verdict = rule_triage(event)
    if verdict is not None:
        return verdict

    llm_verdict = llm_triage(event, settings)
    llm_verdict.setdefault("confidence", None)
    llm_verdict.setdefault("rule_ids", [])
    llm_verdict.setdefault("indicators", [])
    return llm_verdict


def run_triage(
    input_file: Path | None = None,
    output_file: Path | None = None,
    settings: Settings | None = None,
) -> Path:
    """Triage all events in input_file and write structured results."""
    cfg = settings or load_settings()
    source = input_file or cfg.events_raw
    destination = output_file or cfg.events_processed
    technique_db = load_mitre_techniques(str(cfg.mitre_index))

    with open(source, encoding="utf-8") as f:
        events = json.load(f)

    if isinstance(events, dict):
        events = [events]

    destination.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for event in events:
        triage = hybrid_triage(event, cfg)
        triage = enrich_with_mitre(triage, technique_db)
        results.append({"event": event, "triage": triage})
        print(
            f"Processed {event.get('TimeCreated', 'unknown time')} -> "
            f"{triage['severity'].upper()} | {triage.get('mitre', 'Unmapped')}"
        )

    with open(destination, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Triaged {len(results)} events -> {destination}")
    return destination
