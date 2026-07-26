import unittest

from soc_copilot.evaluation import evaluate_results


class EvaluationTests(unittest.TestCase):
    def test_calculates_binary_detection_metrics(self):
        results = [
            {"triage": {"severity": "high"}},
            {"triage": {"severity": "low"}},
            {"triage": {"severity": "high"}},
            {"triage": {"severity": "low"}},
        ]
        labels = [
            {"event_index": 0, "expected_severity": "critical"},
            {"event_index": 1, "expected_severity": "low"},
            {"event_index": 2, "expected_severity": "low"},
            {"event_index": 3, "expected_severity": "high"},
        ]

        metrics = evaluate_results(results, labels)

        self.assertEqual(metrics["evaluated"], 4)
        self.assertEqual(metrics["true_positive"], 1)
        self.assertEqual(metrics["true_negative"], 1)
        self.assertEqual(metrics["false_positive"], 1)
        self.assertEqual(metrics["false_negative"], 1)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["severity_accuracy"], 0.25)


if __name__ == "__main__":
    unittest.main()
