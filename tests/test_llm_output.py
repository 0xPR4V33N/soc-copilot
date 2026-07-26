import unittest

from soc_copilot.triage.llm import _normalize_triage


class LlmOutputTests(unittest.TestCase):
    def test_clamps_confidence_and_validates_severity(self):
        verdict = _normalize_triage(
            {
                "severity": "HIGH",
                "technique_guess": "PowerShell",
                "summary": "Suspicious command.",
                "confidence": 1.7,
            }
        )

        self.assertEqual(verdict["severity"], "high")
        self.assertEqual(verdict["confidence"], 1.0)

    def test_invalid_values_use_safe_defaults(self):
        verdict = _normalize_triage(
            {
                "severity": "severe",
                "technique_guess": "",
                "summary": "",
                "confidence": "unknown",
            }
        )

        self.assertEqual(verdict["severity"], "unknown")
        self.assertIsNone(verdict["confidence"])


if __name__ == "__main__":
    unittest.main()
