import unittest
import json
from searchcve.models import CVEItem, Metrics, EPSSData, KEVData
from searchcve.exporter import to_json, to_csv, to_markdown, to_html


class TestExporter(unittest.TestCase):
    def setUp(self):
        self.items = [
            CVEItem(
                id="CVE-2021-44228",
                description="Apache Log4j2 JNDI Remote Code Execution vulnerability.",
                published_date="2021-12-10T10:00:00.000",
                last_modified_date="2021-12-15T10:00:00.000",
                metrics=Metrics(
                    base_score=10.0,
                    version="3.1",
                    severity="CRITICAL",
                    attack_vector="NETWORK",
                    privileges_required="NONE",
                ),
                epss=EPSSData(score=0.9750, percentile=0.999),
                kev=KEVData(date_added="2021-12-10", known_ransomware_campaign_use="Known"),
                cwe_ids=["CWE-502"],
            )
        ]

    def test_json_export(self):
        raw = to_json(self.items)
        parsed = json.loads(raw)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["id"], "CVE-2021-44228")
        self.assertEqual(parsed[0]["cvss_score"], 10.0)
        self.assertTrue(parsed[0]["is_kev"])

    def test_csv_export(self):
        csv_out = to_csv(self.items)
        self.assertIn("CVE-2021-44228", csv_out)
        self.assertIn("10.0", csv_out)
        self.assertIn("CRITICAL", csv_out)
        self.assertIn("YES", csv_out)

    def test_markdown_export(self):
        md = to_markdown(self.items, query_title="log4j")
        self.assertIn("| **10.0** |", md)
        self.assertIn("CVE-2021-44228", md)
        self.assertIn("CRITICAL", md)

    def test_html_export(self):
        html_out = to_html(self.items, query_title="log4j")
        self.assertIn("SearchCVE Advanced Threat Dossier", html_out)
        self.assertIn("CVE-2021-44228", html_out)
        self.assertIn("badge-critical", html_out)
        self.assertIn("KEV ACTIVE", html_out)


if __name__ == "__main__":
    unittest.main()
