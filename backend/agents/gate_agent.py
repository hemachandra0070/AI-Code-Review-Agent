import json
from pathlib import Path

SEVERITY_ALIASES = {
    "INFO": "INFO",
    "LOW": "LOW",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}
SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
DECISIONS = ("PASS", "WARNING", "FAIL")
DECISION_RANK = {"PASS": 0, "WARNING": 1, "FAIL": 2}

DEFAULT_POLICY = {
    "fail_severities": ["HIGH", "CRITICAL"],
    "warning_severities": ["LOW", "MEDIUM"],
    "invalid_finding_action": "WARNING",
    "escalate_on_ai_disagreement": True,
}

SCAN_FINDINGS = "findings"
SCAN_CLEAN = "clean"
SCAN_FAILED = "scan_failed"
SCAN_UNAVAILABLE = "scanner_unavailable"
NO_SCANNABLE_FILES = "no_scannable_files"


class GateAgent:

    def __init__(self, policy=None):
        self.policy = _validated_policy(policy or {})

    def evaluate(self, scan_status, rows=None, scan_error=None):
        result = {
            "decision": "PASS",
            "scan_status": scan_status,
            "scan_error": scan_error,
            "severity_counts": {},
            "rows": [],
            "failed": [],
            "warned": [],
            "triggered_rules": [],
            "disagreements": [],
            "errors": [],
            "notes": [],
        }

        if scan_status in (SCAN_FAILED, SCAN_UNAVAILABLE):
            result["decision"] = "FAIL"
            reason = _scan_failure_rule(scan_status, scan_error)
            result["triggered_rules"].append(reason)
            result["notes"].append(
                "The gate fails closed for failed or unavailable scans so that nothing "
                "verified can never be reported as clear."
            )
            return result

        if scan_status == NO_SCANNABLE_FILES:
            result["decision"] = "WARNING"
            result["triggered_rules"].append(
                "No scannable code files were found; nothing was verified."
            )
            result["notes"].append(
                "No decision could be based on scanned evidence; unchanged or skipped content is not covered."
            )
            return result

        rows = rows or []
        processed = [self._process_row(row) for row in rows]
        result["rows"] = processed

        for row in processed:
            severity = row["normalized"]
            if severity:
                result["severity_counts"][severity] = result["severity_counts"].get(severity, 0) + 1
                if row["decision"] == "FAIL":
                    result["failed"].append(row)
                elif row["decision"] == "WARNING":
                    result["warned"].append(row)
            if row.get("rule_triggered"):
                result["triggered_rules"].append(row["rule_triggered"])
            if row.get("disagreement"):
                result["disagreements"].append(row["disagreement"])
            if row.get("error"):
                result["errors"].append(row["error"])

        decisions = [row["decision"] for row in processed] or ["PASS"]
        result["decision"] = max(decisions, key=lambda decision: DECISION_RANK[decision])

        if not processed:
            result["notes"].append(
                "Scan completed successfully with no findings. This is not proof that the code is "
                "secure; the scanner only detects rules that match configured patterns, and "
                "unscanned code was not evaluated."
            )
        if any(row["review_status"] != "ok" for row in processed):
            result["notes"].append(
                "Some findings had no valid AI assessment; their gate decisions rely on scanner evidence only."
            )

        return result

    def _process_row(self, row):
        scan_finding = row.get("scan_finding") or {}
        review = row.get("review")
        review_error = row.get("review_error")

        label = _row_label(scan_finding)
        result = {
            "label": label,
            "path": scan_finding.get("path", "unknown-path"),
            "line": scan_finding.get("line"),
            "rule_id": scan_finding.get("rule_id", "unknown-rule"),
            "scanner_severity": scan_finding.get("severity"),
            "normalized": SEVERITY_ALIASES.get(
                str(scan_finding.get("severity") or "").strip().upper()
            ),
            "ai_severity": None,
            "ai_normalized": None,
            "review_status": "missing",
            "review_error": review_error,
            "decision": None,
            "rule_triggered": None,
            "disagreement": None,
            "error": review_error and f"{label}: AI assessment unavailable ({review_error})",
        }

        if review_error:
            result["error"] = f"{label}: AI assessment unavailable ({review_error})"
        elif isinstance(review, dict) and str(review.get("issue") or "").strip():
            result["review_status"] = "ok"
            ai_raw = str(review.get("severity") or "").strip().upper()
            result["ai_severity"] = review.get("severity")
            result["ai_normalized"] = SEVERITY_ALIASES.get(ai_raw)
        else:
            result["review_status"] = "invalid"
            result["error"] = f"{label}: AI assessment is malformed and was not used for the gate decision."

        if result["normalized"] is None:
            action = self.policy["invalid_finding_action"]
            result["rule_triggered"] = (
                f"{label}: unknown or missing scanner severity; invalid_finding_action={action}."
            )
            result["decision"] = action
            return result

        tier = _tier(result["normalized"], self.policy)
        result["decision"] = tier
        result["rule_triggered"] = (
            f"{label}: scanner severity {result['normalized']} maps to policy tier {tier}."
        )

        if result["review_status"] != "ok" and result["error"] is None:
            result["error"] = (
                f"{label}: AI assessment missing; decision based on scanner severity only."
            )

        if result["review_status"] == "ok" and result["ai_normalized"]:
            disagreement = self._resolve_disagreement(result, tier)
            if disagreement:
                result["disagreement"] = disagreement["rule"]
                result["rule_triggered"] = f"{result['rule_triggered']} {disagreement['rule']}"
                result["decision"] = disagreement["decision"]

        return result

    def _resolve_disagreement(self, row, scan_tier):
        ai_rank = SEVERITY_RANK[row["ai_normalized"]]
        scanner_rank = SEVERITY_RANK[row["normalized"]]

        if ai_rank == scanner_rank:
            return None

        if ai_rank < scanner_rank:
            return {
                "rule": (
                    f"AI severity {row['ai_normalized']} is lower than scanner severity "
                    f"{row['normalized']}; scanner evidence is retained (no AI downgrade)."
                ),
                "decision": scan_tier,
            }

        if not self.policy["escalate_on_ai_disagreement"]:
            return {
                "rule": (
                    f"AI severity {row['ai_normalized']} exceeds scanner severity {row['normalized']}; "
                    "escalation disabled, scanner evidence governs."
                ),
                "decision": scan_tier,
            }

        scan_rank = DECISION_RANK[scan_tier]
        ai_tier = _tier(row["ai_normalized"], self.policy)

        if ai_tier == "FAIL" and scan_tier != "FAIL":
            return {
                "rule": (
                    f"AI severity {row['ai_normalized']} exceeds scanner severity {row['normalized']}; "
                    "escalation is capped at WARNING because FAIL requires scanner evidence."
                ),
                "decision": "WARNING",
            }

        escalated = ai_tier if DECISION_RANK[ai_tier] > scan_rank else scan_tier
        return {
            "rule": (
                f"AI severity {row['ai_normalized']} exceeds scanner severity {row['normalized']}; "
                f"decision escalated to {escalated}."
            ),
            "decision": escalated,
        }


def load_policy(path):
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"Could not load policy file ({path}): {exc}"
    if not isinstance(raw, dict):
        return None, f"Policy file ({path}) must contain a JSON object."
    try:
        return _validated_policy(raw), None
    except ValueError as exc:
        return None, f"Invalid policy file ({path}): {exc}"


def _validated_policy(values):
    merged = dict(DEFAULT_POLICY)
    unknown = set(values) - set(DEFAULT_POLICY)
    if unknown:
        raise ValueError(f"unknown policy keys: {', '.join(sorted(unknown))}")

    for key in ("fail_severities", "warning_severities"):
        provided = values.get(key)
        if provided is None:
            continue
        if not isinstance(provided, list) or not all(isinstance(s, str) for s in provided):
            raise ValueError(f"{key} must be a list of severity names")
        names = [s.strip().upper() for s in provided]
        invalid = [s for s in names if s not in SEVERITY_RANK]
        if invalid:
            raise ValueError(
                f"{key} contains invalid normalized severities: {', '.join(invalid)}. "
                f"Valid: {', '.join(SEVERITY_RANK)}"
            )
        merged[key] = names

    action = values.get("invalid_finding_action")
    if action is not None:
        if not isinstance(action, str) or action.strip().upper() not in DECISIONS:
            raise ValueError(f"invalid_finding_action must be one of {', '.join(DECISIONS)}")
        merged["invalid_finding_action"] = action.strip().upper()

    escalate = values.get("escalate_on_ai_disagreement")
    if escalate is not None:
        if not isinstance(escalate, bool):
            raise ValueError("escalate_on_ai_disagreement must be true or false")
        merged["escalate_on_ai_disagreement"] = escalate

    return merged


def _tier(normalized, policy):
    if normalized in policy["fail_severities"]:
        return "FAIL"
    if normalized in policy["warning_severities"]:
        return "WARNING"
    return "PASS"


def _row_label(scan_finding):
    path = scan_finding.get("path") or "unknown-path"
    line = scan_finding.get("line")
    rule = scan_finding.get("rule_id") or "unknown-rule"
    if isinstance(line, int):
        return f"{path}:{line} [{rule}]"
    return f"{path} [{rule}]"


def _scan_failure_rule(scan_status, scan_error):
    status_word = "scanner is unavailable" if scan_status == SCAN_UNAVAILABLE else "scan failed"
    reason = f"Gate fails closed: {status_word}"
    if scan_error:
        reason = f"{reason} ({scan_error})"
    return f"{reason}; nothing could be verified."


def format_gate_summary(result):
    lines = [
        "=====================",
        "GATE DECISION",
        "=====================",
        "",
        f"Decision    : {result['decision']}",
        f"Scan status : {result['scan_status']}",
        "",
        _format_counts(result.get("severity_counts", {})),
    ]

    if result.get("failed"):
        lines.append("")
        lines.append("Findings that caused FAIL:")
        lines.extend(f"- {row['label']}" for row in result["failed"])

    if result.get("warned"):
        lines.append("")
        lines.append("Findings causing WARNING:")
        lines.extend(f"- {row['label']}" for row in result["warned"])

    if result.get("triggered_rules"):
        lines.append("")
        lines.append("Policy rules triggered:")
        lines.extend(f"- {rule}" for rule in result["triggered_rules"])

    if result.get("disagreements"):
        lines.append("")
        lines.append("Scanner/AI disagreements:")
        lines.extend(f"- {rule}" for rule in result["disagreements"])

    if result.get("errors"):
        lines.append("")
        lines.append("Processing errors:")
        lines.extend(f"- {error}" for error in result["errors"])

    lines.append("")
    lines.append(
        "NOTE: A passing gate result is not proof of security. It reflects only the "
        "configured policy applied to the evidence gathered in this run."
    )
    return "\n".join(lines)


def _format_counts(counts):
    if not counts:
        return "Findings    : none"
    ordered = sorted(counts.items(), key=lambda item: -SEVERITY_RANK.get(item[0], 0))
    return "Findings    : " + ", ".join(f"{severity}={count}" for severity, count in ordered)
