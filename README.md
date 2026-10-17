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

Exit codes: `0` = completed (findings reported, or clean scan notice), `1` = scan failed, scanner unavailable, or API/report failure.

## Tests

Offline unit tests (Semgrep runs locally, but no Gemini API calls):

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests
```

There are 13 tests covering scanner normalization and status handling, report rendering and validation, and Gemini response normalization/error handling.

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

## Design Notes

- **Scanner output is evidence, not proof.** A `clean` status prints an explicit notice that no findings does not mean the code is secure. Scan failures (`scanner_unavailable`, `scan_failed`) are also distinguishable.
- **AI output is schema-constrained.** The reviewer uses Gemini structured-output mode and validates the shape after parsing; malformed responses raise a clear `ReviewError` instead of producing a fake finding.
- **Evidence vs. analysis are kept separate.** Reports label the Semgrep rule findings as "SCANNER EVIDENCE" and the model's interpretation as "AI ANALYSIS".
- **Transient API errors** (HTTP 429/5xx) are retried up to 3 times with backoff; other errors fail immediately with a clear message.

## Known Limitations

- Requires the `GEMINI_API_KEY` to be set; network access to the Gemini API is needed for the review step.
- The AI severity rating is model-driven and may differ from the scanner's rule severity (e.g. a WARNING-rule finding was rated Critical in testing).
- Review is per single code file (the `--file` argument) combined with the full scan result; multi-file review is not yet implemented.
- Static analysis is only as good as the configured rule set (default: Semgrep `p/default`); unsupported vulnerability classes produce no findings.
- GitHub PR integration, dependency scanning (Trivy/OSV), gate policies, and threat modeling are planned future milestones and not yet implemented.
