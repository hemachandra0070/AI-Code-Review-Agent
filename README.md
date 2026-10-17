# Agentic DPG — AI Code Security Review Agent

An agentic, multi-agent security review tool combining **Semgrep** static analysis with a **Gemini**-powered AI security review agent. Scanner findings are normalized, analyzed by the AI, and rendered into a structured security report that separates scanner evidence from AI analysis.

## Project Structure

```
AI-Code-Review-Agent/
├── backend/
│   ├── orchestrator.py          # Entry point: scan → review → report
│   ├── scanner.py               # Semgrep wrapper (--json, normalized findings)
│   ├── reviewer.py              # Gemini review (schema-constrained JSON output)
│   ├── agents/
│   │   ├── static_scan_agent.py
│   │   ├── security_review_agent.py
│   │   └── report_agent.py
├── sample_code/
│   ├── login.py                 # Vulnerable fixture (SQL injection)
│   └── safe_login.py            # Safe fixture (parameterized query)
├── tests/                       # Offline unit tests (no live API calls)
├── test_scan.py                 # Manual scanner test
├── requirements.txt
├── .env.example
└── AGENTS.md
```

## Setup

Requires Python 3.9+ and Windows PowerShell.

```powershell
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your Gemini API key:

```
GEMINI_API_KEY=your_api_key_here
```

`GITHUB_TOKEN` is optional for public repositories and required for private ones or for `--comment` posting.

Minimum permissions for `GITHUB_TOKEN`:

| Use case | Fine-grained token | Classic token |
| --- | --- | --- |
| Public repo PR review | not required (anonymous API access) | not required |
| Private repo PR review | `pull requests: read`, `metadata: read` | `repo` (read access) |
| `--comment` posting | `pull requests: write`, `metadata: read` | `repo` (full) |

Tokens are read from the environment only and are never logged; token material in API/clone output is redacted.

Semgrep is installed into the venv (`venv\Scripts\semgrep.exe`). The scanner resolves it automatically — adding `venv\Scripts` to PATH is not required.

## Running

From the repository root (default: scans `sample_code` and reviews `login.py`):

```powershell
.\venv\Scripts\python.exe backend\orchestrator.py
```

Custom scan target and code context file:

```powershell
.\venv\Scripts\python.exe backend\orchestrator.py path\to\scan --file path\to\file.py
```

Scan a GitHub repository (clone mode) — `owner/repo` or a full HTTPS URL, optionally a specific branch or tag:

```powershell
.\venv\Scripts\python.exe backend\orchestrator.py --repo owner/repo
.\venv\Scripts\python.exe backend\orchestrator.py --repo https://github.com/owner/repo --ref feature-branch
```

GitHub mode clones the repo into a temporary directory (deleted on exit), scans it with Semgrep, groups findings per file, and generates one review report per flagged file (most findings first), capped by `--max-files` (default 5). Files that could not be reviewed are listed as warnings.

Review a GitHub pull request — fetches only the PR's changed files via the GitHub API (no full clone):

```powershell
.\venv\Scripts\python.exe backend\orchestrator.py --repo owner/repo --pr 123
```

PR mode skips deleted files, binary content, unsupported file types, oversized files (>512 KB), and unsafe paths (each with a filter note), scans the remaining changed code files, reviews flagged files like clone mode, and validates AI severity against the scanner's rule severity (an inflation note is added when the AI rates higher than the scanner). Add `--comment` to publish a summary comment on the PR (deduplicated per head commit; requires `GITHUB_TOKEN` with write permissions).

Exit codes: `0` = completed (findings reported, or clean scan notice), `1` = scan failed, scanner unavailable, fetch failure, or API/report failure.

## Tests

Offline unit tests (Semgrep runs locally, but no Gemini API calls):

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests
```

There are 82 tests covering scanner normalization and status handling, report rendering and validation, Gemini response normalization/error handling, GitHub URL normalization with token redaction, PR changed-file fetching/pagination/failures, changed-file selection, comment deduplication, severity validation, and the Gate Agent (policy tiers, thresholds, disagreements, fail-closed behavior, configurable policies, and orchestrator integration).

`test_scan.py` (scanner only) and `backend/test_review.py` (live Gemini call) are manual utilities.

## Example Report

```
=====================================
SECURITY REVIEW REPORT
=====================================

AI ANALYSIS
Issue       : SQL Injection
Severity    : Critical
OWASP       : A03:2021-Injection
CWE         : CWE-89
File        : D:\...\sample_code\login.py
Line        : 16

Recommendation:
To prevent SQL Injection, use parameterized queries instead of f-strings
or string concatenation for SQL commands. For sqlite3, pass parameters
as a tuple, e.g.: cursor.execute("SELECT * FROM users WHERE username=?", (username,))

SCANNER EVIDENCE (from Semgrep)
- ...\login.py:16 [WARNING] python.lang.security.audit.formatted-sql-query...
- ...\login.py:16 [ERROR] python.sqlalchemy...execute-raw-query...

=====================================
```

## The Gate Agent

The Gate Agent (`backend/agents/gate_agent.py`) applies a deterministic security policy to the run's evidence and produces `PASS`, `WARNING`, or `FAIL`. It uses scanner severities as its primary evidence, never treats AI conclusions as ground truth, and shows every decision reason.

- A scanner that failed or is unavailable **fails closed** (`FAIL`); it is never treated as PASS.
- An empty scan (successful, zero findings) yields `PASS` with an explicit "not proof of security" note.
- AI severity cannot directly cause a `FAIL`; disagreement between scanner and AI is recorded, and AI-only escalation is capped at `WARNING`.

### Default severity policy

Raw severities are normalized to `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (Semgrep `WARNING`→`MEDIUM`, `ERROR`→`HIGH`; original values are preserved in evidence):

| Normalized severity | Default decision |
| --- | --- |
| CRITICAL, HIGH | `FAIL` |
| LOW, MEDIUM | `WARNING` |
| INFO | `PASS` (unless another rule applies) |
| Invalid/unknown severity | `WARNING` (`invalid_finding_action`, configurable) |

The overall decision is the highest applicable finding decision (`FAIL > WARNING > PASS`). Gate `FAIL` makes the orchestrator exit with code `1`; `PASS`/`WARNING` exit `0`.

### Configuring thresholds

Two ways to configure — no code changes required:

1. Place a `gate_policy.json` in the repository root (auto-loaded when present).
2. Pass `--policy path\to\policy.json` for a custom file.

Unsupported keys or invalid values are rejected with a clear warning and the built-in defaults are used. See `gate_policy.example.json`:

```json
{
  "fail_severities": ["CRITICAL"],
  "warning_severities": ["HIGH", "MEDIUM", "LOW"],
  "invalid_finding_action": "WARNING",
  "escalate_on_ai_disagreement": true
}
```

### Gate result in reports

In local, clone, and PR modes the console output includes a `GATE DECISION` block with: the overall decision, findings counted by normalized severity, the findings that caused failure, warnings, the triggered policy rules, scanner/AI disagreements, and processing errors (missing AI assessments are marked, and the gate still decides on scanner evidence). GATE `FAIL` makes the orchestrator exit with code `1`; `PASS`/`WARNING` exit `0`.

`--comment` includes the same gate block in the PR comment. Publishing (a comment) is informational only: the tool never blocks, closes, or modifies a pull request, and gate `FAIL` only affects the process exit code if you wire a CI job to treat nonzero exits as blocking.

## Design Notes

- **Scanner output is evidence, not proof.** A `clean` status prints an explicit notice that no findings does not mean the code is secure. Scan failures (`scanner_unavailable`, `scan_failed`) are also distinguishable.
- **AI output is schema-constrained.** The reviewer uses Gemini structured-output mode and validates the shape after parsing; malformed responses raise a clear `ReviewError` instead of producing a fake finding.
- **Evidence vs. analysis are kept separate.** Reports label the Semgrep rule findings as "SCANNER EVIDENCE" and the model's interpretation as "AI ANALYSIS".
- **Transient API errors** (HTTP 429/5xx) are retried up to 3 times with backoff; other errors fail immediately with a clear message.
- **Gate decisions are deterministic.** Identical scan findings, AI results, and policy produce identical gate output. AI disagreements escalate at most to `WARNING` (never to `FAIL`, which requires scanner evidence).

## Known Limitations

- Requires the `GEMINI_API_KEY` to be set; network access to the Gemini API is needed for the review step.
- `tests/` includes no network-dependent cases; clone behavior against real repositories is verified manually.
- The AI severity rating is model-driven and may differ from the scanner's rule severity (e.g. a WARNING-rule finding was rated Critical in testing).
- GitHub integration is clone mode plus PR mode: PR mode analyzes changed files only and is not proof a PR is safe (unchanged code is not scanned); PR comments are plain issue comments, not line-anchored review comments, and posting is opt-in with per-head-commit deduplication.
- Review is per single code file (the `--file` argument) combined with the full scan result; multi-file review is not yet implemented.
- Static analysis is only as good as the configured rule set (default: Semgrep `p/default`); unsupported vulnerability classes produce no findings.
- GitHub PR integration, dependency scanning (Trivy/OSV), gate policies, and threat modeling are planned future milestones and not yet implemented.
