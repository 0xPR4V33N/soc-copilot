import unittest

from soc_copilot.mitre.mapper import map_to_mitre, mitre_url


class MitreMapperTests(unittest.TestCase):
    def test_maps_exact_technique_name(self):
        technique_db = {"powershell": "T1059.001"}

        mapped = map_to_mitre("PowerShell", technique_db)

        self.assertEqual(mapped, "T1059.001 (PowerShell)")

    def test_builds_subtechnique_url(self):
        self.assertEqual(
            mitre_url("T1059.001 (PowerShell)"),
            "https://attack.mitre.org/techniques/T1059/001/",
        )

    def test_unmapped_has_no_url(self):
        self.assertIsNone(mitre_url("Unmapped"))


if __name__ == "__main__":
    unittest.main()
