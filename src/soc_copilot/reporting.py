from __future__ import annotations

from collections import Counter
from typing import Any

from soc_copilot.evaluation import evaluate_results
from soc_copilot.feedback import load_feedback
from soc_copilot.triage.pipeline import parse_triage_record


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    severities = Counter()
    sources = Counter()
    mapped = 0
    for item in results:
        triage = parse_triage_record(item.get("triage", {}))
        severities[str(triage.get("severity", "unknown")).lower()] += 1
        sources[str(triage.get("source", "unknown")).lower()] += 1
        if triage.get("mitre") and triage.get("mitre") != "Unmapped":
            mapped += 1
    total = len(results)
    return {
        "total_events": total,
        "mitre_mapped": mapped,
        "mitre_coverage": (mapped / total) if total else 0.0,
        "severity_counts": dict(severities),
        "source_counts": dict(sources),
    }


def summarize_feedback(records: list[dict[str, Any]]) -> dict[str, Any]:
    dispositions = Counter(record.get("disposition", "unknown") for record in records)
    overrides = sum(
        1
        for record in records
        if record.get("original_severity") != record.get("analyst_severity")
    )
    total = len(records)
    return {
        "analyst_reviews": total,
        "severity_overrides": overrides,
        "override_rate": (overrides / total) if total else 0.0,
        "disposition_counts": dict(dispositions),
    }


def build_portfolio_summary(
    *,
    results: list[dict[str, Any]],
    labels: list[dict[str, Any]] | None = None,
    feedback_records: list[dict[str, Any]] | None = None,
    benchmark: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {"triage": summarize_results(results)}
    if labels:
        summary["evaluation"] = evaluate_results(results, labels)
    if feedback_records is not None:
        summary["feedback"] = summarize_feedback(feedback_records)
    if benchmark:
        summary["benchmark"] = benchmark
    return summary


def render_summary_markdown(summary: dict[str, Any]) -> str:
    triage = summary["triage"]
    lines = [
        "# AI SOC Copilot Portfolio Summary",
        "",
        "## Dataset Snapshot",
        f"- Total events: {triage['total_events']}",
        f"- MITRE mapped events: {triage['mitre_mapped']} ({triage['mitre_coverage']:.0%})",
        f"- Severity distribution: {triage['severity_counts']}",
        f"- Decision source distribution: {triage['source_counts']}",
        "",
    ]

    if "evaluation" in summary:
        eval_metrics = summary["evaluation"]
        lines += [
            "## Labeled Evaluation",
            f"- Labeled events: {eval_metrics['evaluated']}",
            f"- Severity accuracy: {eval_metrics['severity_accuracy']:.0%}",
            f"- Precision: {eval_metrics['precision']:.0%}",
            f"- Recall: {eval_metrics['recall']:.0%}",
            f"- F1: {eval_metrics['f1']:.0%}",
            "",
        ]

    if "feedback" in summary:
        feedback = summary["feedback"]
        lines += [
            "## Analyst Feedback",
            f"- Reviewed events: {feedback['analyst_reviews']}",
            f"- Severity overrides: {feedback['severity_overrides']} ({feedback['override_rate']:.0%})",
            f"- Dispositions: {feedback['disposition_counts']}",
            "",
        ]

    if "benchmark" in summary:
        lines += ["## Model Benchmark"]
        for model in summary["benchmark"].get("models", []):
            metrics = model.get("evaluation", {})
            lines.append(
                f"- {model['name']}: accuracy {metrics.get('severity_accuracy', 0):.0%}, "
                f"F1 {metrics.get('f1', 0):.0%}, runtime {model.get('runtime_seconds', 0):.2f}s"
            )
        lines.append("")

    lines += [
        "## Portfolio Talking Points",
        "- Hybrid triage (rules first, LLM fallback) reduces noisy model decisions.",
        "- Analyst-in-the-loop feedback records false positives and severity corrections.",
        "- Quantitative metrics (accuracy, precision, recall, F1) track quality over time.",
    ]
    return "\n".join(lines) + "\n"


def load_feedback_summary(path) -> list[dict[str, Any]]:
    return load_feedback(path)
