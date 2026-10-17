import argparse
import json
import sys
from pathlib import Path

from agents.report_agent import ReportAgent
from agents.security_review_agent import SecurityReviewAgent
from agents.static_scan_agent import StaticScanAgent
from reviewer import ReviewError

scanner = StaticScanAgent()
reviewer = SecurityReviewAgent()
report_agent = ReportAgent()

DEFAULT_SCAN_PATH = Path(__file__).resolve().parent.parent / "sample_code"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Agentic security review: Semgrep scan + Gemini analysis + report."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_SCAN_PATH,
        help="Path for Semgrep to scan (default: sample_code).",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Source file to include as code context (default: <path>/login.py).",
    )
    args = parser.parse_args(argv)

    scan_path = args.path.resolve()
    code_file = (args.file or scan_path / "login.py").resolve()

    if not code_file.exists():
        print(f"Code context file not found: {code_file}")
        print("Use --file to point to a source code file inside the scan path.")
        return 1

    scan_result = scanner.execute(str(scan_path))

    if scan_result.get("status") == "scanner_unavailable":
        print(f"Scan could not start: {scan_result['error']}")
        return 1
    if scan_result.get("status") == "scan_failed":
        print(f"Scan did not complete: {scan_result['error']}")
        return 1

    if not scan_result["findings"]:
        print(
            "Scan completed with no findings. This is not proof that the code is "
            "secure; the scanner only detects rules that match configured patterns."
        )
        return 0

    with open(code_file, "r", encoding="utf-8") as f:
        code = f.read()

    combined_input = f"""
CODE:
{code}

SEMGREP RESULTS:
{json.dumps(scan_result['findings'], indent=2)}
"""

    try:
        review = reviewer.execute(combined_input)
        report = report_agent.execute(review, evidence=scan_result["findings"])
    except ReviewError as exc:
        print(f"Security review could not complete: {exc}")
        return 1
    except ValueError as exc:
        print(f"Report generation failed: {exc}")
        return 1

    print("\n===== FINAL REPORT =====\n")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
