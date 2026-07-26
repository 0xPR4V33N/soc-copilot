#!/usr/bin/env python3
"""Compare triage quality across local models on the same dataset."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_copilot.config import load_settings  # noqa: E402
from soc_copilot.evaluation import evaluate_results, load_labels  # noqa: E402
from soc_copilot.triage.llm import triage_event  # noqa: E402
from soc_copilot.triage.pipeline import enrich_with_mitre, hybrid_triage  # noqa: E402


def _run_single_model(
    *,
    name: str,
    model_path: str | None,
    events: list[dict],
    labels: list[dict] | None,
):
    settings = load_settings()
    start = perf_counter()
    results: list[dict] = []
    for event in events:
        verdict = hybrid_triage(
            event,
            settings,
            llm_triage=lambda current_event, cfg: triage_event(
                current_event,
                cfg,
                model_path=model_path,
                source=f"llm:{name}",
            ),
        )
        results.append(
            {"event": event, "triage": enrich_with_mitre(verdict)}
        )
    elapsed = perf_counter() - start

    evaluation = evaluate_results(results, labels) if labels else {}
    return {
        "name": name,
        "model_path": model_path or str(settings.model_path),
        "runtime_seconds": round(elapsed, 3),
        "evaluation": evaluation,
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark local SOC triage models")
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Input events JSON (defaults to demo sample events)",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=None,
        help="Optional labels JSON for evaluation metrics",
    )
    parser.add_argument(
        "--primary-name",
        default="primary",
        help="Label for default configured model",
    )
    parser.add_argument(
        "--secondary-model",
        default=None,
        help="Optional second model path for comparison",
    )
    parser.add_argument(
        "--secondary-name",
        default="secondary",
        help="Label for second model",
    )
    parser.add_argument(
        "--use-triaged",
        type=Path,
        default=None,
        help="Use an existing triaged JSON file instead of running models",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for benchmark JSON",
    )
    parser.add_argument(
        "--include-results",
        action="store_true",
        help="Include per-event triage objects in benchmark output (larger file).",
    )
    args = parser.parse_args()

    settings = load_settings()
    input_path = args.input or settings.events_sample
    labels_path = args.labels or settings.sample_labels
    output_path = args.output or settings.benchmark_output

    with open(input_path, encoding="utf-8") as f:
        events = json.load(f)
    labels = load_labels(labels_path) if labels_path.exists() else None

    if args.use_triaged:
        with open(args.use_triaged, encoding="utf-8") as f:
            pretriaged = json.load(f)
        models = [
            {
                "name": args.primary_name,
                "model_path": "precomputed",
                "runtime_seconds": 0.0,
                "evaluation": evaluate_results(pretriaged, labels) if labels else {},
                "results": pretriaged,
            }
        ]
    else:
        models = [
            _run_single_model(
                name=args.primary_name,
                model_path=None,
                events=events,
                labels=labels,
            )
        ]
        if args.secondary_model:
            models.append(
                _run_single_model(
                    name=args.secondary_name,
                    model_path=args.secondary_model,
                    events=events,
                    labels=labels,
                )
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    models_payload = []
    for model in models:
        base = {
            "name": model["name"],
            "model_path": model["model_path"],
            "runtime_seconds": model["runtime_seconds"],
            "evaluation": model.get("evaluation", {}),
        }
        if args.include_results:
            base["results"] = model.get("results", [])
        models_payload.append(base)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": str(input_path),
        "labels": str(labels_path) if labels_path.exists() else None,
        "models": models_payload,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Wrote benchmark results -> {output_path}")
    for model in models:
        metrics = model.get("evaluation", {})
        if metrics:
            print(
                f"{model['name']}: accuracy={metrics.get('severity_accuracy', 0):.0%}, "
                f"f1={metrics.get('f1', 0):.0%}, runtime={model['runtime_seconds']:.2f}s"
            )


if __name__ == "__main__":
    main()
