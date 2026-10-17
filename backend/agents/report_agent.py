class ReportAgent:

    def execute(self, finding, evidence=None):
        if not isinstance(finding, dict):
            raise ValueError(
                f"ReportAgent expected a finding dict, got {type(finding).__name__}."
            )

        issue = str(finding.get("issue") or "").strip()
        if not issue:
            raise ValueError("Finding must contain a non-empty 'issue' field.")

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
        "",
        "Recommendation:",
        finding.get("recommendation", "N/A"),
    ]
    return "\n".join(lines)


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
