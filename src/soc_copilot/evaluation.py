from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from soc_copilot.triage.pipeline import parse_triage_record


SUSPICIOUS = {"high", "critical"}


def load_labels(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        labels = json.load(f)
    if not isinstance(labels, list):
        raise ValueError("Labels file must contain a JSON list")
    return labels


def evaluate_results(
    results: list[dict[str, Any]],
    labels: list[dict[str, Any]],
) -> dict[str, float | int]:
    """Evaluate exact severity and suspicious-vs-benign classification."""
    expected_by_index = {
        int(label["event_index"]): str(label["expected_severity"]).lower()
        for label in labels
    }

    exact_correct = true_positive = true_negative = false_positive = false_negative = 0
    evaluated = 0

    for event_index, item in enumerate(results):
        expected = expected_by_index.get(event_index)
        if expected is None:
            continue

        predicted = str(
            parse_triage_record(item.get("triage", {})).get("severity", "unknown")
        ).lower()
        evaluated += 1
        exact_correct += int(predicted == expected)

        expected_positive = expected in SUSPICIOUS
        predicted_positive = predicted in SUSPICIOUS
        if expected_positive and predicted_positive:
            true_positive += 1
        elif not expected_positive and not predicted_positive:
            true_negative += 1
        elif not expected_positive and predicted_positive:
            false_positive += 1
        else:
            false_negative += 1

    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "evaluated": evaluated,
        "severity_accuracy": exact_correct / evaluated if evaluated else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
    }
