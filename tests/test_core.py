import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from backend.scanner import run_scan
from backend.agents.report_agent import ReportAgent
from backend import reviewer


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_dir = REPO_ROOT / "sample_code"

    def test_vulnerable_fixture_produces_normalized_findings(self):
        result = run_scan(str(self.sample_dir / "login.py"))
        self.assertEqual(result["status"], "findings")
        required = {"rule_id", "path", "line", "severity", "message", "snippet"}
        for finding in result["findings"]:
            self.assertTrue(
                required.issubset(finding.keys()),
                f"Finding missing fields: {finding.keys()}",
            )

    def test_safe_fixture_is_clean(self):
        result = run_scan(str(self.sample_dir / "safe_login.py"))
        self.assertEqual(result["status"], "clean", f"Unexpected findings: {result['findings']}")

    def test_missing_target_is_scan_failed(self):
        result = run_scan("this_path_does_not_exist_xyz")
        self.assertEqual(result["status"], "scan_failed")
        self.assertTrue(result["error"])


class ReportAgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = ReportAgent()

    def test_valid_finding_renders_report(self):
        report = self.agent.execute(
            {"issue": "SQL Injection", "severity": "High", "cwe": "CWE-89"},
            evidence=[{"rule_id": "r1", "path": "login.py", "line": 14, "severity": "WARNING"}],
        )
        self.assertIn("SQL Injection", report)
        self.assertIn("SCANNER EVIDENCE", report)

    def test_non_dict_finding_rejected(self):
        with self.assertRaises(ValueError):
            self.agent.execute(["issue", "severity"])

    def test_missing_issue_rejected(self):
        with self.assertRaises(ValueError):
            self.agent.execute({"severity": "High"})

    def test_empty_issue_rejected(self):
        with self.assertRaises(ValueError):
            self.agent.execute({"issue": "   "})


class ReviewerNormalizationTests(unittest.TestCase):
    def test_single_item_list_accepted(self):
        result = reviewer._normalize_finding([{"issue": "SQLi", "severity": "High"}])
        self.assertIsNotNone(result)
        self.assertEqual(result["issue"], "SQLi")

    def test_ambiguous_list_rejected(self):
        self.assertIsNone(reviewer._normalize_finding([{"issue": "A"}, {"issue": "B"}]))

    def test_missing_issue_rejected(self):
        self.assertIsNone(reviewer._normalize_finding({"severity": "High"}))

    def test_non_dict_rejected(self):
        self.assertIsNone(reviewer._normalize_finding("garbage"))

    def test_nepotism_fields_dropped(self):
        result = reviewer._normalize_finding(
            {"issue": "SQLi", "made_up_field": "x", "severity": "", "owasp": None, "cwe": "CWE-89"}
        )
        self.assertNotIn("made_up_field", result)
        self.assertNotIn("severity", result)
        self.assertNotIn("owasp", result)
        self.assertIn("cwe", result)

    def test_missing_key_raises_review_error(self):
        saved = reviewer.os.environ.get("GEMINI_API_KEY")
        reviewer.os.environ.pop("GEMINI_API_KEY", None)
        try:
            with self.assertRaises(reviewer.ReviewError):
                reviewer.review_code("code")
        finally:
            if saved is not None:
                reviewer.os.environ["GEMINI_API_KEY"] = saved


if __name__ == "__main__":
    unittest.main()
