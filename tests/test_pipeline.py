import unittest

from soc_copilot.triage.pipeline import hybrid_triage
from tests.helpers import make_event


class HybridPipelineTests(unittest.TestCase):
    def test_rule_match_skips_llm(self):
        event = make_event(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
        )

        def fail_if_called(_event, _settings):
            raise AssertionError("LLM should not run for a conclusive rule match")

        verdict = hybrid_triage(event, llm_triage=fail_if_called)

        self.assertEqual(verdict["source"], "rule")
        self.assertEqual(verdict["severity"], "critical")

    def test_no_rule_match_uses_llm(self):
        expected = {
            "severity": "low",
            "technique_guess": "Not applicable",
            "summary": "Benign interactive editor launch.",
            "source": "llm",
        }

        def fake_llm(_event, _settings):
            return dict(expected)

        verdict = hybrid_triage(make_event(), llm_triage=fake_llm)

        self.assertEqual(verdict["source"], "llm")
        self.assertIsNone(verdict["confidence"])
        self.assertEqual(verdict["rule_ids"], [])


if __name__ == "__main__":
    unittest.main()
