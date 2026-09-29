import unittest
from searchcve.models import CVEItem, Metrics, EPSSData, KEVData, PoCReference
from searchcve.formatter import format_table, format_inspector_card, get_severity_color, Colors


class TestFormatter(unittest.TestCase):
    def setUp(self):
        self.item = CVEItem(
            id="CVE-2024-45434",
            description="OpenSynergy BlueSDK has a Use-After-Free flaw allowing remote code execution.",
            published_date="2024-08-15T00:00:00.000",
            last_modified_date="2024-08-16T00:00:00.000",
            metrics=Metrics(
                base_score=9.8,
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                attack_vector="NETWORK",
                attack_complexity="LOW",
                privileges_required="NONE",
            ),
            epss=EPSSData(score=0.9234, percentile=0.991),
            kev=KEVData(date_added="2024-09-01", due_date="2024-09-22", known_ransomware_campaign_use="Known"),
            pocs=[PoCReference(url="https://github.com/example/poc", source="GitHub", poc_type="GitHub PoC")],
            cwe_ids=["CWE-416"],
            cwe_names=["CWE-416: Use After Free"],
        )

    def test_table_formatting(self):
        output = format_table([self.item], query_title="bluetooth")
        self.assertIn("CVE-2024-45434", output)
        self.assertIn("9.8", output)
        self.assertIn("92.3%", output)
        self.assertIn("KEV", output)
        self.assertIn("PoC", output)
        self.assertIn("SearchCVE Advanced", output)

    def test_inspector_card_formatting(self):
        card = format_inspector_card(self.item)
        self.assertIn("CVE DOSSIER: CVE-2024-45434", card)
        self.assertIn("CRITICAL", card)
        self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", card)
        self.assertIn("CISA KNOWN EXPLOITED VULNERABILITY", card)
        self.assertIn("92.34%", card)
        self.assertIn("CWE-416: Use After Free", card)
        self.assertIn("https://github.com/example/poc", card)


if __name__ == "__main__":
    unittest.main()
