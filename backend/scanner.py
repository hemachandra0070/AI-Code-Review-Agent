import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_CONFIG = "p/default"
SCAN_TIMEOUT_SECONDS = 600

SCAN_FINDINGS = "findings"
SCAN_CLEAN = "clean"
SCAN_FAILED = "scan_failed"
SCAN_UNAVAILABLE = "scanner_unavailable"


def _semgrep_exe():
    exe = shutil.which("semgrep")
    if exe:
        return exe
    suffix = "semgrep.exe" if os.name == "nt" else "semgrep"
    candidate = Path(sys.executable).parent / suffix
    if candidate.exists():
        return str(candidate)
    return None


def run_scan(path, config=None):
    if not os.path.exists(path):
        return _failed_result(f"Scan target does not exist: {path}")

    exe = _semgrep_exe()
    if exe is None:
        return {
            "status": SCAN_UNAVAILABLE,
            "findings": [],
            "raw_output": "",
            "error": "Semgrep executable not found. Install it or ensure the venv Scripts directory is on PATH.",
        }

    try:
        proc = subprocess.run(
            [
                exe,
                "scan",
                "--config",
                config or DEFAULT_CONFIG,
                "--json",
                "--quiet",
                path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _failed_result(f"Semgrep scan timed out after {SCAN_TIMEOUT_SECONDS} seconds.")
    except OSError as exc:
        return _failed_result(f"Semgrep could not be executed: {exc}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return _failed_result(
            f"Semgrep output was not valid JSON (exit code {proc.returncode}). "
            f"stderr: {proc.stderr.strip()[:500]}"
        )

    findings = [_normalize_finding(result) for result in data.get("results", [])]
    status = SCAN_FINDINGS if findings else SCAN_CLEAN

    result = {
        "status": status,
        "findings": findings,
        "raw_output": proc.stdout,
        "returncode": proc.returncode,
        "scanner_errors": data.get("errors", []),
    }

    if proc.returncode != 0 and not data.get("results"):
        result["status"] = SCAN_FAILED
        result["error"] = f"Semgrep exited with code {proc.returncode}. stderr: {proc.stderr.strip()[:500]}"

    return result


def _normalize_finding(result):
    extra = result.get("extra") or {}
    start = result.get("start") or {}
    return {
        "rule_id": result.get("check_id", "unknown-rule"),
        "path": result.get("path", "unknown-path"),
        "line": start.get("line"),
        "severity": extra.get("severity", ""),
        "message": extra.get("message", ""),
        "snippet": (extra.get("lines") or "").strip(),
    }


def _failed_result(error):
    return {
        "status": SCAN_FAILED,
        "findings": [],
        "raw_output": "",
        "error": error,
    }
