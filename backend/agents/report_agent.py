AI_SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SCANNER_SEVERITY_RANKS = {"INFO": 1, "WARNING": 2, "ERROR": 3}


class ReportAgent:

    def execute(self, finding, evidence=None):
        if not isinstance(finding, dict):
            raise ValueError(
                f"ReportAgent expected a finding dict, got {type(finding).__name__}."
            )

        issue = str(finding.get("issue") or "").strip()
        if not issue:
            raise ValueError("Finding must contain a non-empty 'issue' field.")

        note = validate_severity(finding, evidence)
        if note:
            finding = dict(finding)
            finding["severity_note"] = note

        parts = [
            "=====================================",
            "SECURITY REVIEW REPORT",
            "=====================================",
            "",
            "AI ANALYSIS",
            _format_analysis(finding),
        ]

        if evidence:
            parts.append("")
            parts.append("SCANNER EVIDENCE (from Semgrep)")
            parts.append(_format_evidence(evidence))

        parts.append("")
        parts.append("=====================================")
        return "\n".join(parts)


def _format_analysis(finding):
    lines = [
        f"Issue       : {finding.get('issue', 'N/A')}",
        f"Severity    : {finding.get('severity', 'N/A')}",
        f"OWASP       : {finding.get('owasp', 'N/A')}",
        f"CWE         : {finding.get('cwe', 'N/A')}",
        f"File        : {finding.get('file', 'N/A')}",
        f"Line        : {finding.get('line', 'N/A')}",
    ]
    if finding.get("severity_note"):
        lines.append(f"Note        : {finding['severity_note']}")
    lines.extend(
        [
            "",
            "Recommendation:",
            finding.get("recommendation", "N/A"),
        ]
    )
    return "\n".join(lines)


def validate_severity(finding, evidence):
    normalized_finding = dict(finding or {})
    normalized_finding.setdefault("severity", "")
    ai_rank = AI_SEVERITY_RANKS.get(str(normalized_finding.get("severity", "")).strip().upper())

    evidence = [item for item in (evidence or []) if isinstance(item, dict)]
    scanner_ranks = [
        SCANNER_SEVERITY_RANKS[str(item.get("severity", "")).strip().upper()]
        for item in evidence
        if str(item.get("severity", "").strip().upper()) in SCANNER_SEVERITY_RANKS
    ]

    if ai_rank is None:
        return "Severity note: AI severity is not recognized; validated scanner severities: " + (
            ", ".join(sorted({str(item.get('severity')) for item in evidence})) or "none available"
        )
    if not scanner_ranks:
        return "Severity note: scanner evidence carries no severity; AI assessment is unverified."
    scanner_severities = sorted(
        {str(item.get("severity", "")).strip().upper() for item in evidence
         if str(item.get("severity", "")).strip().upper() in SCANNER_SEVERITY_RANKS}
    )
    if max(scanner_ranks) < ai_rank:
        return (
            "Severity note: AI severity exceeds the scanner's maximum rule severity "
            f"({', '.join(scanner_severities)}); treat AI assessment with caution."
        )
    return None


def _format_evidence(evidence):
    lines = []
    for item in evidence:
        label = f"{item.get('path', 'unknown-path')}:{item.get('line') or '?'}"
        rule = item.get("rule_id", "unknown-rule")
        message = item.get("message", "")
        lines.append(f"- {label} [{item.get('severity', 'N/A')}] {rule}")
        if message:
            lines.append(f"  {message}")
    return "\n".join(lines)
