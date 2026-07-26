import tempfile
import unittest
from pathlib import Path

from soc_copilot.feedback import event_fingerprint, feedback_index, upsert_feedback
from tests.helpers import make_event


class AnalystFeedbackTests(unittest.TestCase):
    def test_upsert_persists_and_replaces_decision(self):
        event = make_event()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feedback.json"

            upsert_feedback(
                path,
                event,
                original_severity="low",
                analyst_severity="medium",
                disposition="needs_review",
                notes="First review",
            )
            upsert_feedback(
                path,
                event,
                original_severity="low",
                analyst_severity="high",
                disposition="confirmed",
                notes="Escalated after validation",
            )

            records = feedback_index(path)
            record = records[event_fingerprint(event)]
            self.assertEqual(len(records), 1)
            self.assertEqual(record["analyst_severity"], "high")
            self.assertEqual(record["disposition"], "confirmed")

    def test_rejects_invalid_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                upsert_feedback(
                    Path(directory) / "feedback.json",
                    make_event(),
                    original_severity="low",
                    analyst_severity="low",
                    disposition="ignored",
                )


if __name__ == "__main__":
    unittest.main()
