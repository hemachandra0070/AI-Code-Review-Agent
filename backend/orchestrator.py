import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from agents.code_fetch_agent import CodeFetchAgent
from agents.gate_agent import (
    GateAgent,
    NO_SCANNABLE_FILES,
    SCAN_CLEAN,
    SCAN_FAILED,
    SCAN_UNAVAILABLE,
    format_gate_summary,
    load_policy,
)
from agents.report_agent import ReportAgent
from agents.security_review_agent import SecurityReviewAgent
from agents.static_scan_agent import StaticScanAgent
from github_handler import (
    ADDED,
    MODIFIED,
    REMOVED,
    RENAMED,
    fetch_file_blob,
    get_pr_changed_files,
    get_pr_comments,
    get_pull_request,
    normalize_repo_url,
    owner_repo,
    post_pr_comment,
)
from reviewer import ReviewError

scanner = StaticScanAgent()
reviewer = SecurityReviewAgent()
report_agent = ReportAgent()
code_fetcher = CodeFetchAgent()

DEFAULT_SCAN_PATH = Path(__file__).resolve().parent.parent / "sample_code"
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "gate_policy.json"
DEFAULT_MAX_FILES = 5
MAX_FILE_BYTES = 512 * 1024
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".cs",
    ".c", ".cpp", ".h", ".hpp", ".kt", ".swift", ".rs", ".scala", ".json",
    ".yaml", ".yml", ".sql", ".sh", ".html", ".cshtml",
}
SCANNABLE_STATUSES = {ADDED, MODIFIED, RENAMED, "changed", "copied"}
COMMENT_MARKER_TEMPLATE = "<!-- agentic-dpg-report pr:{pr} head:{sha} -->"


def main(argv=None):
    args = _parse_args(argv)

    if args.pr is not None and not args.repo:
        print("--pr requires --repo (owner/repo or full HTTPS URL).")
        return 1

    gate = GateAgent(_get_policy(args.policy))

    if args.repo:
        if args.pr is not None:
            return _run_pr_mode(args, gate)
        return _run_github_mode(args, gate)
    return _run_local_mode(args, gate)


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Agentic security review: static scan + AI analysis + deterministic gate decision. "
            "Scans a local path by default, or fetches a GitHub repository or pull request with --repo."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_SCAN_PATH,
        help="Path for Semgrep to scan (default: sample_code). Ignored when --repo is given.",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Source file to include as code context (default: <path>/login.py). Local mode only.",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="GitHub repository to fetch and scan (owner/repo or full HTTPS URL).",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=None,
        help="Pull request number. Requires --repo; scans only the PR's changed files via the GitHub API.",
    )
    parser.add_argument(
        "--ref",
        default=None,
        help="Branch or tag to fetch when using --repo (default: default branch).",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help=f"Maximum number of flagged files to AI-review in one run (default: {DEFAULT_MAX_FILES}).",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help=(
            "Path to a gate policy JSON file (default: gate_policy.json in the repository root "
            "if it exists, otherwise built-in defaults)."
        ),
    )
    parser.add_argument(
        "--comment",
        action="store_true",
        help=(
            "Post a summary comment with findings and gate decision to the pull request. "
            "Requires GITHUB_TOKEN with write permissions and is deduplicated per PR head commit."
        ),
    )
    return parser.parse_args(argv)


def _get_policy(policy_arg):
    path = Path(policy_arg) if policy_arg else DEFAULT_POLICY_PATH
    if not path.exists() and not policy_arg:
        return {}
    policy, error = load_policy(path)
    if error:
        print(f"Warning: {error}; using built-in default gate policy.")
        return {}
    return policy


def _exit_code_for(gate_result):
    if gate_result["decision"] == "FAIL":
        return 1
    return 0


def _run_local_mode(args, gate):
    scan_path = args.path.resolve()
    code_file = (args.file or scan_path / "login.py").resolve()

    if not code_file.exists():
        print(f"Code context file not found: {code_file}")
        print("Use --file to point to a source code file inside the scan path.")
        return 1

    scan_result = _scan(scan_path, gate)
    if scan_result is None:
        return 1

    if not scan_result["findings"]:
        gate_result = gate.evaluate(SCAN_CLEAN)
        print("\n===== GATE RESULT =====\n")
        print(format_gate_summary(gate_result))
        return _exit_code_for(gate_result)

    code = _read_code(code_file)
    if code is None:
        rows = [
            {"scan_finding": finding, "review": None, "review_error": "code context could not be read"}
            for finding in scan_result["findings"]
        ]
        gate_result = gate.evaluate(scan_result["status"], rows)
        print("\n===== GATE RESULT =====\n")
        print(format_gate_summary(gate_result))
        return _exit_code_for(gate_result)

    combined_input = _build_combined_input(code, scan_result["findings"])

    review = None
    review_error = None
    try:
        review = reviewer.execute(combined_input)
    except ReviewError as exc:
        review_error = str(exc)
        print(f"Security review could not complete: {exc}")

    rows = [
        {"scan_finding": finding, "review": review, "review_error": review_error}
        for finding in scan_result["findings"]
    ]
    gate_result = gate.evaluate(scan_result["status"], rows)

    print("\n===== FINAL REPORT =====\n")
    if review is not None:
        try:
            print(report_agent.execute(review, evidence=scan_result["findings"]))
        except ValueError as exc:
            print(f"Report generation failed: {exc}")
    print()
    print(format_gate_summary(gate_result))
    return _exit_code_for(gate_result)


def _run_github_mode(args, gate):
    with tempfile.TemporaryDirectory(prefix="agenticdpg_clone_") as clone_dir:
        fetch = code_fetcher.execute(args.repo, clone_dir, ref=args.ref)
        if fetch.get("status") != "fetched":
            print(f"Repository fetch failed: {fetch.get('error', 'unknown error')}")
            return 1

        print("[Code Fetch Agent] Cloned to temporary directory (cleaned up on exit).")

        scan_result = _scan(Path(fetch["path"]), gate)
        if scan_result is None:
            return 1

        if not scan_result["findings"]:
            return _print_clean_gate(scan_result["status"], gate)

        _, exit_code = _review_flagged_files(
            scan_result,
            scan_dir=Path(fetch["path"]),
            max_files=args.max_files,
            repo_label=f"{fetch['repo']} ({fetch['ref']})",
            gate=gate,
        )
        return exit_code


def _run_pr_mode(args, gate):
    try:
        owner, repo = owner_repo(normalize_repo_url(args.repo))
    except ValueError as exc:
        print(f"Invalid repository: {exc}")
        return 1

    token = (os.getenv("GITHUB_TOKEN") or "").strip() or None

    pr_meta = get_pull_request(owner, repo, args.pr, token=token)
    if pr_meta.get("status") != "ok":
        print(f"Could not fetch pull request #{args.pr}: {pr_meta.get('error')}")
        return 1

    files_result = get_pr_changed_files(owner, repo, args.pr, token=token)
    if files_result.get("status") != "ok":
        print(f"Could not fetch changed files for PR #{args.pr}: {files_result.get('error')}")
        return 1

    with tempfile.TemporaryDirectory(prefix="agenticdpg_pr_") as pr_dir:
        selected, notes = _select_pr_files(owner, repo, files_result["files"], Path(pr_dir), token=token)

        for note in notes:
            print(f"[PR Filter] {note}")

        if not selected:
            print(
                "No scannable code files found in this pull request "
                "(deleted, binary, unsupported, skipped, or oversized files only)."
            )
            gate_result = gate.evaluate(NO_SCANNABLE_FILES)
            print("\n===== GATE RESULT =====\n")
            print(format_gate_summary(gate_result))
            return _exit_code_for(gate_result)

        print(f"[PR Mode] Scanning {len(selected)} changed file(s) from PR #{args.pr} head {pr_meta['head_sha'][:10]}...")

        scan_result = _scan(Path(pr_dir), gate)
        if scan_result is None:
            return 1

        if not scan_result["findings"]:
            print(
                "Scan of the PR's changed files found no findings. Unchanged code was not scanned."
            )
            return _print_clean_gate(scan_result["status"], gate, pr_context=True)

        gate_result, _ = _review_flagged_files(
            scan_result,
            scan_dir=Path(pr_dir),
            max_files=args.max_files,
            repo_label=f"PR #{args.pr} of {owner}/{repo} (head {pr_meta['head_sha'][:10]})",
            gate=gate,
        )

        if args.comment:
            _post_pr_findings_comment(
                owner=owner,
                repo=repo,
                pr_number=args.pr,
                head_sha=pr_meta["head_sha"],
                scan_result=scan_result,
                reports_text=_collect_reports_text(scan_result, Path(pr_dir), args.max_files),
                gate_text=format_gate_summary(gate_result),
                token=token,
            )
        return _exit_code_for(gate_result)


def _print_clean_gate(scan_status, gate, pr_context=False):
    gate_result = gate.evaluate(SCAN_CLEAN)
    print("\n===== GATE RESULT =====\n")
    print(format_gate_summary(gate_result))
    if pr_context:
        print("Only the pull request's changed files were scanned; the rest of the repository was not.")
    return _exit_code_for(gate_result)


def _select_pr_files(owner, repo, changed_files, pr_dir, token=None):
    selected = []
    notes = []
    for pr_file in changed_files:
        filename = pr_file["filename"]
        status = pr_file["status"]

        if status == REMOVED:
            notes.append(f"{filename}: file deleted in this PR; not scanned.")
            continue
        if status not in SCANNABLE_STATUSES:
            notes.append(f"{filename}: unsupported change status '{status or 'unknown'}'; not scanned.")
            continue

        extension = Path(filename).suffix.lower()
        if extension not in SCANNABLE_EXTENSIONS:
            notes.append(f"{filename}: unsupported file type '{extension or 'none'}'; not scanned.")
            continue

        if pr_file.get("previous_filename"):
            notes.append(f"{filename}: renamed from {pr_file['previous_filename']}; scanning current name at head.")

        if not pr_file.get("sha"):
            notes.append(f"{filename}: no content hash available; not scanned.")
            continue

        blob = fetch_file_blob(owner, repo, pr_file["sha"], token=token)
        if blob.get("status") != "ok":
            notes.append(f"{filename}: content fetch failed ({blob.get('error')}); not scanned.")
            continue

        content = blob["content"]
        if len(content) > MAX_FILE_BYTES:
            notes.append(f"{filename}: file exceeds {_format_bytes(MAX_FILE_BYTES)} limit; not scanned.")
            continue
        if b"\x00" in content[:4096]:
            notes.append(f"{filename}: binary content detected; not scanned.")
            continue

        target = pr_dir / filename
        if not str(target.resolve()).startswith(str(pr_dir.resolve())):
            notes.append(f"{filename}: unsafe path; not scanned.")
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        selected.append(filename)

    return selected, notes


def _format_bytes(size):
    return f"{size // 1024} KB"


def _collect_reports_text(scan_result, scan_dir, max_files):
    groups = {}
    for finding in scan_result["findings"]:
        resolved = str(_resolve_finding_path(finding["path"], scan_dir))
        groups.setdefault(resolved, []).append(finding)

    ordered = sorted(groups.items(), key=lambda item: -len(item[1]))[: max(1, max_files)]
    parts = []
    for path, findings in ordered:
        code = _read_code(path)
        if code is None:
            continue
        try:
            review = reviewer.execute(_build_combined_input(code, findings))
        except ReviewError:
            continue
        parts.append(f"### `{findings[0]['path']}`\n\n{report_agent.execute(review, evidence=findings)}")
    return "\n\n".join(parts)


def _post_pr_findings_comment(owner, repo, pr_number, head_sha, scan_result, reports_text, gate_text=None, token=None):
    marker = COMMENT_MARKER_TEMPLATE.format(pr=pr_number, sha=head_sha)
    if not token:
        print("Warning: --comment requires GITHUB_TOKEN in .env; comment not posted.")
        return False

    existing = get_pr_comments(owner, repo, pr_number, token=token)
    if existing.get("status") == "ok":
        for comment in existing.get("comments", []):
            body = (comment or {}).get("body", "")
            if marker in body:
                print(f"Comment already posted earlier for PR #{pr_number} at this head; not posting duplicates.")
                return True

    body = (
        f"{marker}\n"
        f"**Agentic DPG security review — PR #{pr_number} (head {head_sha[:10]})**\n\n"
        "Findings below come from Semgrep scan results; AI analysis is advisory and "
        "severity may differ from the scanner's rule severity.\n\n"
        f"{reports_text}\n\n"
        "_Generated by Agentic DPG._"
    )
    if gate_text:
        body = f"{body}\n\n{gate_text}"

    posted = post_pr_comment(owner, repo, pr_number, body, token=token)
    if posted.get("status") == "posted":
        print(f"Comment posted: {posted.get('html_url', 'comment created')}")
        return True
    print(f"Comment posting failed: {posted.get('error')}")
    return False


def _scan(scan_path, gate=None):
    scan_result = scanner.execute(str(scan_path))

    if scan_result.get("status") == SCAN_UNAVAILABLE:
        gate_result = gate.evaluate(SCAN_UNAVAILABLE, scan_error=scan_result["error"]) if gate else None
        print(f"Scan could not start: {scan_result['error']}")
        if gate_result:
            print("\n===== GATE RESULT =====\n")
            print(format_gate_summary(gate_result))
        return None
    if scan_result.get("status") == SCAN_FAILED:
        gate_result = gate.evaluate(SCAN_FAILED, scan_error=scan_result["error"]) if gate else None
        print(f"Scan did not complete: {scan_result['error']}")
        if gate_result:
            print("\n===== GATE RESULT =====\n")
            print(format_gate_summary(gate_result))
        return None

    return scan_result


def _resolve_finding_path(path, scan_dir):
    candidate = Path(path)
    if candidate.exists():
        return candidate
    return Path(scan_dir) / path


def _review_flagged_files(scan_result, scan_dir, max_files, repo_label, gate=None):
    groups = {}
    for finding in scan_result["findings"]:
        resolved = str(_resolve_finding_path(finding["path"], scan_dir))
        groups.setdefault(resolved, []).append(finding)

    ordered = sorted(groups.items(), key=lambda item: -len(item[1]))
    selected = ordered[: max(1, max_files)]
    skipped_files = ordered[len(selected):]

    reports = []
    failures = []
    rows = []
    for path, findings in selected:
        code = _read_code(path)
        if code is None:
            for finding in findings:
                rows.append(
                    {"scan_finding": finding, "review": None, "review_error": "code context could not be read"}
                )
            failures.append(f"{path}: code context could not be read; findings were not AI-reviewed.")
            continue

        combined_input = _build_combined_input(code, findings)
        review = None
        review_error = None
        try:
            review = reviewer.execute(combined_input)
        except ReviewError as exc:
            review_error = str(exc)
            failures.append(f"{path}: security review failed ({exc})")

        for finding in findings:
            rows.append({"scan_finding": finding, "review": review, "review_error": review_error})

        if review is not None:
            try:
                reports.append(report_agent.execute(review, evidence=findings))
            except ValueError as exc:
                failures.append(f"{path}: report generation failed ({exc})")

    for path, findings in skipped_files:
        for finding in findings:
            rows.append(
                {
                    "scan_finding": finding,
                    "review": None,
                    "review_error": "skipped (--max-files cap)",
                }
            )

    if skipped_files:
        print(
            f"Note: {len(skipped_files)} file(s) with findings were skipped "
            f"(--max-files={max_files}). Their findings count toward the gate decision "
            "using scanner evidence only."
        )
    for failure in failures:
        print(f"Warning: {failure}")

    gate_result = gate.evaluate(scan_result["status"], rows) if gate else None

    print(f"\n===== SECURITY REPORTS for {repo_label} =====\n")
    for report in reports:
        print(report)
        print()

    if gate_result is not None:
        print("\n===== GATE RESULT =====\n")
        print(format_gate_summary(gate_result))

    exit_code = _exit_code_for(gate_result) if gate_result else 0
    if not reports and failures:
        exit_code = max(1, exit_code)
    return gate_result, exit_code


def _read_code(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Could not read code context {path}: {exc}")
        return None


def _build_combined_input(code, findings):
    return f"""
CODE:
{code}

SEMGREP RESULTS:
{json.dumps(findings, indent=2)}
"""


if __name__ == "__main__":
    sys.exit(main())
