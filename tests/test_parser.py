import unittest

from soc_copilot.parse.sysmon_event import parse_sysmon_message
from tests.helpers import make_event


class SysmonParserTests(unittest.TestCase):
    def test_extracts_process_and_parent_fields(self):
        event = make_event(
            image=r"C:\Windows\System32\whoami.exe",
            command_line="whoami /all",
            parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )

        parsed = parse_sysmon_message(event)

        self.assertEqual(parsed.event_id, 1)
        self.assertEqual(parsed.image, r"C:\Windows\System32\whoami.exe")
        self.assertEqual(parsed.command_line, "whoami /all")
        self.assertTrue(parsed.parent_image.endswith("powershell.exe"))
        self.assertEqual(parsed.process_id, "4000")

    def test_missing_fields_get_safe_defaults(self):
        parsed = parse_sysmon_message({"Id": 1, "Message": "Process Create:"})

        self.assertEqual(parsed.image, "N/A")
        self.assertEqual(parsed.command_line, "")
        self.assertEqual(parsed.parent_image, "")

    def test_parses_network_event_fields(self):
        event = {
            "Id": 3,
            "Message": (
                "Network connection detected:\r\n"
                "Image: C:\\Windows\\System32\\powershell.exe\r\n"
                "DestinationIp: 203.0.113.10\r\n"
                "DestinationHostname: example.invalid\r\n"
                "DestinationPort: 443\r\n"
                "Protocol: tcp"
            ),
        }

        parsed = parse_sysmon_message(event)

        self.assertEqual(parsed.event_type, "Network Connect")
        self.assertEqual(parsed.destination_ip, "203.0.113.10")
        self.assertEqual(parsed.destination_port, "443")

    def test_parses_registry_event_fields(self):
        event = {
            "Id": 13,
            "Message": (
                "Registry value set:\r\n"
                "Image: C:\\Windows\\System32\\reg.exe\r\n"
                "TargetObject: HKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\r\n"
                "Details: C:\\Temp\\update.exe"
            ),
        }

        parsed = parse_sysmon_message(event)

        self.assertEqual(parsed.event_type, "Registry Value Set")
        self.assertTrue(parsed.target_object.endswith(r"Run\Updater"))


if __name__ == "__main__":
    unittest.main()
