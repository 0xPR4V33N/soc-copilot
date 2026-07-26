import unittest

from soc_copilot.reporting import (
    build_portfolio_summary,
    render_summary_markdown,
    summarize_feedback,
    summarize_results,
)


class ReportingTests(unittest.TestCase):
    def test_summarize_results_counts_sources_and_coverage(self):
        results = [
            {"triage": {"severity": "high", "source": "rule", "mitre": "T1059.001 (PowerShell)"}},
            {"triage": {"severity": "low", "source": "llm:phi3", "mitre": "Unmapped"}},
        ]

        summary = summarize_results(results)

        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["mitre_mapped"], 1)
        self.assertEqual(summary["source_counts"]["rule"], 1)
        self.assertEqual(summary["source_counts"]["llm:phi3"], 1)

    def test_feedback_summary_tracks_override_rate(self):
        records = [
            {"original_severity": "low", "analyst_severity": "high", "disposition": "confirmed"},
            {"original_severity": "high", "analyst_severity": "high", "disposition": "confirmed"},
        ]

        summary = summarize_feedback(records)

        self.assertEqual(summary["analyst_reviews"], 2)
        self.assertEqual(summary["severity_overrides"], 1)
        self.assertEqual(summary["override_rate"], 0.5)

    def test_markdown_report_includes_benchmark_section(self):
        payload = build_portfolio_summary(
            results=[{"triage": {"severity": "low", "source": "rule", "mitre": "Unmapped"}}],
            labels=[{"event_index": 0, "expected_severity": "low"}],
            feedback_records=[],
            benchmark={"models": [{"name": "phi3", "runtime_seconds": 1.23, "evaluation": {"severity_accuracy": 1, "f1": 1}}]},
        )

        markdown = render_summary_markdown(payload)

        self.assertIn("## Model Benchmark", markdown)
        self.assertIn("phi3", markdown)
        self.assertIn("accuracy", markdown)


if __name__ == "__main__":
    unittest.main()
