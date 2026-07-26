from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_PATH = ROOT / "config" / "settings.yaml"


@dataclass(frozen=True)
class Settings:
    root: Path
    events_raw: Path
    events_processed: Path
    events_sample: Path
    analyst_feedback: Path
    sample_labels: Path
    mitre_index: Path
    mitre_stix: Path
    benchmark_output: Path
    summary_report: Path
    portfolio_bundle: Path
    model_path: Path
    n_ctx: int
    n_threads: int
    max_tokens: int
    temperature: float
    max_events: int
    event_ids: tuple[int, ...]


def load_settings(path: Path | None = None) -> Settings:
    config_path = path or SETTINGS_PATH
    with open(config_path, encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    paths = raw["paths"]
    model = raw["model"]
    export = raw["export"]

    return Settings(
        root=ROOT,
        events_raw=ROOT / paths["events_raw"],
        events_processed=ROOT / paths["events_processed"],
        events_sample=ROOT / paths["events_sample"],
        analyst_feedback=ROOT / paths["analyst_feedback"],
        sample_labels=ROOT / paths["sample_labels"],
        mitre_index=ROOT / paths["mitre_index"],
        mitre_stix=ROOT / paths["mitre_stix"],
        benchmark_output=ROOT / paths["benchmark_output"],
        summary_report=ROOT / paths["summary_report"],
        portfolio_bundle=ROOT / paths["portfolio_bundle"],
        model_path=ROOT / model["path"],
        n_ctx=model["n_ctx"],
        n_threads=model["n_threads"],
        max_tokens=model["max_tokens"],
        temperature=model["temperature"],
        max_events=export["max_events"],
        event_ids=tuple(export.get("event_ids", [export.get("event_id", 1)])),
    )
