import unittest
from vulnhound.cli import create_parser, apply_advanced_filters, sort_items
from vulnhound.models import CVEItem, Metrics, EPSSData, KEVData, PoCReference


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.parser = create_parser()
        self.items = [
            CVEItem(
                id="CVE-2024-0001",
                description="Remote code execution without auth",
                published_date="2024-01-01T00:00:00.000",
                last_modified_date="2024-01-02T00:00:00.000",
                metrics=Metrics(base_score=9.8, severity="CRITICAL", attack_vector="NETWORK", privileges_required="NONE"),
                epss=EPSSData(score=0.90, percentile=0.98),
                kev=KEVData(date_added="2024-01-05"),
                pocs=[PoCReference(url="https://exploit-db.com/1", source="edb", poc_type="Exploit-DB")],
            ),
            CVEItem(
                id="CVE-2023-0002",
                description="Local privilege escalation requiring auth",
                published_date="2023-01-01T00:00:00.000",
                last_modified_date="2023-01-02T00:00:00.000",
                metrics=Metrics(base_score=6.5, severity="MEDIUM", attack_vector="LOCAL", privileges_required="HIGH"),
                epss=EPSSData(score=0.05, percentile=0.20),
            ),
        ]

    def test_parser_args(self):
        args = self.parser.parse_args(["bluetooth", "--last", "5", "--year", "2025", "--sort", "cvss", "--kev"])
        self.assertEqual(args.query, "bluetooth")
        self.assertEqual(args.last_n, 5)
        self.assertEqual(args.year, 2025)
        self.assertEqual(args.sort, "cvss")
        self.assertTrue(args.kev)

    def test_filters(self):
        # Filter for remote only
        args = self.parser.parse_args(["dummy", "--remote"])
        filtered = apply_advanced_filters(self.items, args)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "CVE-2024-0001")

        # Filter for KEV only
        args = self.parser.parse_args(["dummy", "--kev"])
        filtered = apply_advanced_filters(self.items, args)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "CVE-2024-0001")

        # Filter for CVSS min
        args = self.parser.parse_args(["dummy", "--cvss-min", "8.0"])
        filtered = apply_advanced_filters(self.items, args)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "CVE-2024-0001")

    def test_sorting(self):
        # Sort by cvss asc
        sorted_items = sort_items(self.items, sort_by="cvss", reverse=False)
        self.assertEqual(sorted_items[0].id, "CVE-2023-0002")

        # Sort by cvss desc
        sorted_items = sort_items(self.items, sort_by="cvss", reverse=True)
        self.assertEqual(sorted_items[0].id, "CVE-2024-0001")


if __name__ == "__main__":
    unittest.main()
