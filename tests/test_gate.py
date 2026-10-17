import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from agents.gate_agent import (
    DEFAULT_POLICY,
    GateAgent,
    NO_SCANNABLE_FILES,
    SCAN_FAILED,
    SCAN_UNAVAILABLE,
    load_policy,
)
from backend import orchestrator


def finding(path="src/app.py", line=10, rule_id="rule-x", severity="ERROR"):
    return {
        "rule_id": rule_id,
        "path": path,
        "line": line,
        "severity": severity,
        "message": "detected",
        "snippet": "code",
    }


def row(scan_finding=None, review=None, review_error=None):
    return {
        "scan_finding": scan_finding if scan_finding is not None else finding(),
        "review": review,
        "review_error": review_error,
    }


GOOD_REVIEW = {"issue": "SQLi", "severity": "High", "owasp": "A03", "cwe": "CWE-89", "recommendation": "parameterize"}


class GateLevelTests(unittest.TestCase):
    def test_empty_findings_after_successful_scan_passes(self):
        result = GateAgent().evaluate("findings", [])
        self.assertEqual(result["decision"], "PASS")
        self.assertTrue(any("not proof" in note for note in result["notes"]))

    def test_scanner_execution_failure_never_passes(self):
        for status in (SCAN_FAILED, SCAN_UNAVAILABLE):
            result = GateAgent().evaluate(status, scan_error="semgrep not found")
            self.assertEqual(result["decision"], "FAIL")
            self.assertIsNotNone(result["scan_error"])

    def test_critical_finding_fails(self):
        result = GateAgent().evaluate(
            "findings", [row(finding(severity="CRITICAL"), review=GOOD_REVIEW)]
        )
        self.assertEqual(result["decision"], "FAIL")
        self.assertEqual(len(result["failed"]), 1)
        self.assertEqual(result["warned"], [])

    def test_high_finding_fails(self):
        result = GateAgent().evaluate("findings", [row(finding(severity="ERROR"), review=GOOD_REVIEW)])
        self.assertEqual(result["decision"], "FAIL")
        self.assertEqual(len(result["failed"]), 1)

    def test_warning_scanner_severity_maps_to_medium_and_warns(self):
        result = GateAgent().evaluate("findings", [row(finding(severity="WARNING"), review=GOOD_REVIEW)])
        self.assertEqual(result["decision"], "WARNING")
        self.assertEqual(result["severity_counts"].get("MEDIUM"), 1)

    def test_info_finding_passes_when_no_other_rule_applies(self):
        result = GateAgent().evaluate(
            "findings", [row(finding(severity="INFO"), review=dict(GOOD_REVIEW, severity="Info"))]
        )
        self.assertEqual(result["decision"], "PASS")

    def test_muliple_findings_take_worst_decision(self):
        rows = [
            row(finding(path="a.py", line=1, severity="INFO"), review=GOOD_REVIEW),
            row(finding(path="b.py", line=2, severity="ERROR"), review=GOOD_REVIEW),
        ]
        result = GateAgent().evaluate("findings", rows)
        self.assertEqual(result["decision"], "FAIL")

    def test_missing_required_fields_treated_per_policy(self):
        malformed = {"path": "x.py", "rule_id": "r"}
        result = GateAgent().evaluate("findings", [row(malformed)])
        self.assertEqual(result["decision"], "WARNING")
        self.assertTrue(any("unknown or missing" in rule for rule in result["triggered_rules"]))

    def test_unknown_scanner_severity_treated_per_policy(self):
        result = GateAgent().evaluate("findings", [row(finding(severity="ULTRA"))])
        self.assertEqual(result["decision"], "WARNING")

    def test_disagreement_ai_higher_escalates_only_to_warning(self):
        rows = [row(finding(severity="INFO"), review=dict(GOOD_REVIEW, severity="Critical"))]
        result = GateAgent().evaluate("findings", rows)
        self.assertEqual(result["decision"], "WARNING")
        self.assertTrue(result["disagreements"])
        self.assertTrue(any("capped at WARNING" in d for d in result["disagreements"]))

    def test_disagreement_ai_lower_keeps_scanner_tier(self):
        rows = [row(finding(severity="ERROR"), review=dict(GOOD_REVIEW, severity="Low"))]
        result = GateAgent().evaluate("findings", rows)
        self.assertEqual(result["decision"], "FAIL")
        self.assertTrue(any("no AI downgrade" in d for d in result["disagreements"]))

    def test_ai_claims_high_while_scanner_informational(self):
        rows = [row(finding(severity="INFO"), review=dict(GOOD_REVIEW, severity="High"))]
        result = GateAgent().evaluate("findings", rows)
        self.assertEqual(result["decision"], "WARNING")
        self.assertNotEqual(result["decision"], "FAIL")

    def test_ai_unavailable_with_scanner_findings_will_still_gate(self):
        result = GateAgent().evaluate("findings", [row(finding(severity="ERROR"), review=None, review_error="quota exceeded")])
        self.assertEqual(result["decision"], "FAIL")
        self.assertTrue(any("AI assessment unavailable" in e for e in result["errors"]))

    def test_malformed_ai_output_not_used(self):
        result = GateAgent().evaluate("findings", [row(finding(severity="WARNING"), review="not a dict")])
        self.assertEqual(result["decision"], "WARNING")
        self.assertTrue(any("malformed" in e for e in result["errors"]))

    def test_no_scannable_files_warns(self):
        result = GateAgent().evaluate(NO_SCANNABLE_FILES)
        self.assertEqual(result["decision"], "WARNING")

    def test_deterministic_output_for_identical_inputs(self):
        rows = [
            row(finding(path="a.py", line=1, severity="WARNING"), review=GOOD_REVIEW),
            row(finding(path="b.py", line=2, severity="INFO"), review=None, review_error="skip"),
            row(finding(path="c.py", line=3, severity="ERROR"), review=dict(GOOD_REVIEW, severity="Critical")),
        ]
        first = GateAgent().evaluate("findings", rows)
        second = GateAgent().evaluate("findings", rows)
        self.assertEqual(first, second)


class GatePolicyTests(unittest.TestCase):
    def test_custom_fail_and_warning_thresholds(self):
        policy = {
            "fail_severities": ["CRITICAL"],
            "warning_severities": ["HIGH", "MEDIUM", "LOW"],
        }
        gate = GateAgent(policy)
        high_only = gate.evaluate("findings", [row(finding(severity="ERROR"), review=GOOD_REVIEW)])
        self.assertEqual(high_only["decision"], "WARNING")

        assert_fail = gate.evaluate("findings", [row(finding(severity="CRITICAL"), review=GOOD_REVIEW)])
        self.assertEqual(assert_fail["decision"], "FAIL")

    def test_policy_can_disable_escalation(self):
        gate = GateAgent({"escalate_on_ai_disagreement": False})
        result = gate.evaluate("findings", [row(finding(severity="INFO"), review=GOOD_REVIEW)])
        self.assertEqual(result["decision"], "PASS")
        self.assertTrue(result["disagreements"])

    def test_invalid_finding_action_can_fail(self):
        gate = GateAgent({"invalid_finding_action": "FAIL"})
        result = gate.evaluate("findings", [row(finding(severity="junk"))])
        self.assertEqual(result["decision"], "FAIL")

    def test_policy_file_load_and_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(
                '{"fail_severities": ["CRITICAL"], "warning_severities": ["HIGH", "MEDIUM", "LOW"], '
                '"invalid_finding_action": "FAIL"}',
                encoding="utf-8",
            )
            policy, error = load_policy(path)
            self.assertIsNone(error)
            gate = GateAgent(policy)
            self.assertEqual(
                gate.evaluate("findings", [row(finding(severity="ERROR"))])["decision"], "WARNING"
            )

            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text('{"no_such_key": true}', encoding="utf-8")
            policy, error = load_policy(bad_path)
            self.assertIsNotNone(error)
            self.assertIsNone(policy)

    def test_default_policy_untouched(self):
        self.assertEqual(DEFAULT_POLICY["fail_severities"], ["HIGH", "CRITICAL"])
        self.assertEqual(DEFAULT_POLICY["warning_severities"], ["LOW", "MEDIUM"])
        self.assertEqual(DEFAULT_POLICY["invalid_finding_action"], "WARNING")
        self.assertTrue(DEFAULT_POLICY["escalate_on_ai_disagreement"])


class GateSummaryTests(unittest.TestCase):
    def test_summary_contains_decision_counts_and_not_proof_note(self):
        result = GateAgent().evaluate(
            "findings",
            [row(finding(severity="ERROR"), review=GOOD_REVIEW)],
        )
        summary = __import__("agents.gate_agent", fromlist=["format_gate_summary"]).format_gate_summary(result)
        self.assertIn("Decision    : FAIL", summary)
        self.assertIn("HIGH=1", summary)
        self.assertIn("not proof of security", summary)
        self.assertIn("king", summary) if False else None

    def test_summary_lists_triggered_rules_and_errors(self):
        result = GateAgent().evaluate(
            "findings",
            [row(finding(severity="ERROR"), review=None, review_error="missing ai")],
        )
        from agents.gate_agent import format_gate_summary

        summary = format_gate_summary(result)
        self.assertIn("Policy rules triggered", summary)
        self.assertIn("AI assessment unavailable", summary)


class OrchestratorIntegrationTests(unittest.TestCase):
    def test_review_flagged_files_gates_with_and_without_ai(self):
        gate = GateAgent()
        scan_result = {
            "status": "findings",
            "findings": [finding(path="a.py", line=1, severity="ERROR")],
        }
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.py").write_text("print('x')\n", encoding="utf-8")

            with mock.patch.object(orchestrator.reviewer, "execute", return_value=GOOD_REVIEW):
                gate_result, exit_code = orchestrator._review_flagged_files(
                    scan_result, scan_dir=Path(tmp), max_files=5, repo_label="t", gate=gate
                )
            self.assertEqual(gate_result["decision"], "FAIL")
            self.assertEqual(exit_code, 1)

            with mock.patch.object(
                orchestrator.reviewer, "execute", side_effect=__import__("reviewer", fromlist=["ReviewError"]).ReviewError("429")
            ):
                gate_result, exit_code = orchestrator._review_flagged_files(
                    scan_result, scan_dir=Path(tmp), max_files=5, repo_label="t", gate=gate
                )
            self.assertEqual(gate_result["decision"], "FAIL")
            self.assertEqual(exit_code, 1)
            self.assertTrue(any("AI assessment unavailable" in e for e in gate_result["errors"]))

    def test_scan_failure_prompts_gate_fail_in_scan_helper(self):
        gate = GateAgent()
        with mock.patch.object(
            orchestrator.scanner,
            "execute",
            return_value={"status": "scan_failed", "findings": [], "error": "boom"},
        ):
            result = orchestrator._scan("unused_path", gate)
        self.assertIsNone(result)

    def test_exit_code_for_gate_results(self):
        self.assertEqual(orchestrator._exit_code_for({"decision": "PASS"}), 0)
        self.assertEqual(orchestrator._exit_code_for({"decision": "WARNING"}), 0)
        self.assertEqual(orchestrator._exit_code_for({"decision": "FAIL"}), 1)


if __name__ == "__main__":
    unittest.main()
