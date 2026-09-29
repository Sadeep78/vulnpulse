import unittest
from vulnhound.models import CVEItem, Metrics, EPSSData, KEVData, PoCReference


class TestCVEModels(unittest.TestCase):
    def test_metrics_from_nvd(self):
        sample_metrics = {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        }
        m = Metrics.from_nvd_metrics(sample_metrics)
        self.assertIsNotNone(m)
        self.assertEqual(m.base_score, 9.8)
        self.assertEqual(m.severity, "CRITICAL")
        self.assertEqual(m.attack_vector, "NETWORK")
        self.assertEqual(m.privileges_required, "NONE")

    def test_cve_item_properties(self):
        item = CVEItem(
            id="CVE-2024-12345",
            description="Buffer overflow vulnerability",
            published_date="2024-05-10T12:00:00.000",
            last_modified_date="2024-05-11T12:00:00.000",
            metrics=Metrics(
                base_score=9.8,
                severity="CRITICAL",
                attack_vector="NETWORK",
                privileges_required="NONE",
            ),
            epss=EPSSData(score=0.8523, percentile=0.985),
            kev=KEVData(date_added="2024-05-15", due_date="2024-06-05"),
            pocs=[PoCReference(url="https://github.com/user/poc", source="GitHub", poc_type="GitHub PoC")],
        )

        self.assertEqual(item.cvss_score, 9.8)
        self.assertEqual(item.severity, "CRITICAL")
        self.assertTrue(item.is_kev)
        self.assertTrue(item.has_poc)
        self.assertTrue(item.is_remote)
        self.assertTrue(item.is_preauth)
        self.assertEqual(item.year, 2024)
        self.assertEqual(item.epss.percentage_str, "85.23%")

    def test_poc_detection_from_references(self):
        cve_raw = {
            "id": "CVE-2023-9999",
            "descriptions": [{"lang": "en", "value": "Test vuln"}],
            "references": [
                {"url": "https://www.exploit-db.com/exploits/50000", "source": "exploit-db"},
                {"url": "https://github.com/threat-actor/cve-2023-9999-poc", "source": "github"},
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-9999", "tags": ["Patch"]},
            ],
        }
        item = CVEItem.from_nvd_cve(cve_raw)
        self.assertTrue(item.has_poc)
        self.assertEqual(len(item.pocs), 2)
        poc_types = [p.poc_type for p in item.pocs]
        self.assertIn("Exploit-DB", poc_types)
        self.assertIn("GitHub PoC", poc_types)


if __name__ == "__main__":
    unittest.main()
