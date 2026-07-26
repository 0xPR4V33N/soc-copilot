#!/usr/bin/env python3
"""Generate a portfolio-friendly markdown summary from current outputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_copilot.config import load_settings  # noqa: E402
from soc_copilot.evaluation import load_labels  # noqa: E402
from soc_copilot.feedback import load_feedback  # noqa: E402
from soc_copilot.reporting import (  # noqa: E402
    build_portfolio_summary,
    render_summary_markdown,
)


def _load_json(path: Path, default):
    if not path.exists():
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SOC Copilot summary report")
    parser.add_argument("--triaged", type=Path, default=None, help="Triaged JSON path")
    parser.add_argument("--labels", type=Path, default=None, help="Labels JSON path")
    parser.add_argument("--feedback", type=Path, default=None, help="Feedback JSON path")
    parser.add_argument("--benchmark", type=Path, default=None, help="Benchmark JSON path")
    parser.add_argument("--out", type=Path, default=None, help="Report markdown path")
    args = parser.parse_args()

    settings = load_settings()
    triaged_path = args.triaged or settings.events_processed
    labels_path = args.labels or settings.sample_labels
    feedback_path = args.feedback or settings.analyst_feedback
    benchmark_path = args.benchmark or settings.benchmark_output
    out_path = args.out or settings.summary_report

    results = _load_json(triaged_path, [])
    if not isinstance(results, list):
        raise ValueError(f"Triaged file must contain a list: {triaged_path}")

    labels = load_labels(labels_path) if labels_path.exists() else None
    feedback_records = load_feedback(feedback_path)
    benchmark_payload = _load_json(benchmark_path, None)

    summary = build_portfolio_summary(
        results=results,
        labels=labels,
        feedback_records=feedback_records,
        benchmark=benchmark_payload,
    )
    markdown = render_summary_markdown(summary)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    print(f"Wrote summary report -> {out_path}")


if __name__ == "__main__":
    main()
