import unittest
from searchcve.auditor import DependencyAuditor


class TestAuditor(unittest.TestCase):
    def test_parse_requirements_txt(self):
        sample_reqs = """
        # Core requirements
        requests==2.25.0
        urllib3>=1.26.5
        flask~=2.0.1
        pytest
        # comment line
        """
        parsed = DependencyAuditor.parse_requirements_txt(sample_reqs)
        self.assertEqual(len(parsed), 4)
        self.assertEqual(parsed[0], ("requests", "2.25.0"))
        self.assertEqual(parsed[1], ("urllib3", "1.26.5"))
        self.assertEqual(parsed[2], ("flask", "2.0.1"))
        self.assertEqual(parsed[3], ("pytest", None))

    def test_parse_package_json(self):
        sample_json = """{
            "name": "my-app",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "4.17.15"
            },
            "devDependencies": {
                "mocha": "~8.0.0"
            }
        }"""
        parsed = DependencyAuditor.parse_package_json(sample_json)
        self.assertEqual(len(parsed), 3)
        pkg_names = [p[0] for p in parsed]
        self.assertIn("express", pkg_names)
        self.assertIn("lodash", pkg_names)
        self.assertIn("mocha", pkg_names)


if __name__ == "__main__":
    unittest.main()
