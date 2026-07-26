import unittest

from soc_copilot.triage.rules import evaluate_rules, rule_triage
from tests.helpers import make_event


class RuleTriageTests(unittest.TestCase):
    def test_encoded_powershell_is_critical(self):
        event = make_event(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
            parent_image=r"C:\Windows\System32\cmd.exe",
            current_directory=r"C:\Users\analyst\AppData\Local\Temp",
        )

        verdict = rule_triage(event)

        self.assertIsNotNone(verdict)
        self.assertEqual(verdict["severity"], "critical")
        self.assertEqual(verdict["source"], "rule")
        self.assertIn("SOC-R001", verdict["rule_ids"])
        self.assertIn("SOC-R002", verdict["rule_ids"])
        self.assertEqual(verdict["mitre"], "T1059.001 (PowerShell)")

    def test_scripted_whoami_is_high(self):
        event = make_event(
            image=r"C:\Windows\System32\whoami.exe",
            command_line="whoami /all",
            parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )

        findings = evaluate_rules(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SOC-R003")
        self.assertEqual(findings[0].mitre_id, "T1033")

    def test_trusted_service_chain_is_low(self):
        event = make_event(
            image=r"C:\Windows\System32\svchost.exe",
            command_line=r"C:\Windows\System32\svchost.exe -k netsvcs",
            parent_image=r"C:\Windows\System32\services.exe",
            user=r"NT AUTHORITY\SYSTEM",
            current_directory=r"C:\Windows\System32",
        )

        verdict = rule_triage(event)

        self.assertEqual(verdict["severity"], "low")
        self.assertEqual(verdict["rule_ids"], ["SOC-R100"])

    def test_unknown_pattern_uses_fallback(self):
        self.assertIsNone(rule_triage(make_event()))

    def test_scripting_engine_web_connection_is_medium(self):
        event = {
            "Id": 3,
            "Message": (
                "Network connection detected:\r\n"
                "Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n"
                "DestinationIp: 203.0.113.10\r\n"
                "DestinationHostname: example.invalid\r\n"
                "DestinationPort: 443\r\n"
                "Protocol: tcp"
            ),
        }

        verdict = rule_triage(event)

        self.assertEqual(verdict["severity"], "medium")
        self.assertEqual(verdict["rule_ids"], ["SOC-R005"])
        self.assertTrue(verdict["mitre"].startswith("T1071.001"))

    def test_registry_run_key_is_high(self):
        event = {
            "Id": 13,
            "Message": (
                "Registry value set:\r\n"
                "Image: C:\\Windows\\System32\\reg.exe\r\n"
                "TargetObject: "
                "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\r\n"
                "Details: C:\\Users\\analyst\\AppData\\Local\\Temp\\update.exe"
            ),
        }

        verdict = rule_triage(event)

        self.assertEqual(verdict["severity"], "high")
        self.assertEqual(verdict["rule_ids"], ["SOC-R006"])
        self.assertTrue(verdict["mitre"].startswith("T1547.001"))


if __name__ == "__main__":
    unittest.main()
