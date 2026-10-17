# Agentic DPG — Complete Project Context for OpenCode

## 1. Project Identity

**Project Name:** Agentic DPG  
**Full Name:** Agentic DevSecOps Pipeline Guardian  
**Existing Repository/Folder Name:** AI-Code-Review-Agent  
**Project Type:** Agentic AI-based DevSecOps and automated code security review tool  
**Primary Language:** Python  
**Current AI Provider:** Google Gemini API  
**Current Development Environment:** Windows 11, VS Code, Python virtual environment

### Project Overview

Agentic DPG is an AI-powered, multi-agent security review system designed to identify vulnerabilities in source code during the software development lifecycle.

The objective is to automate and improve the security review process by combining traditional static application security testing tools with AI-powered analysis and multiple specialized agents.

The tool should eventually integrate into a developer's GitHub workflow, analyze code changes, identify security vulnerabilities, explain their severity, recommend fixes, and optionally enforce security policies before code is merged.

The project is partially implemented. Continue from the existing codebase rather than starting over.

---

## 2. Problem Statement

Security vulnerabilities are frequently introduced during software development. Manual security reviews can be slow, inconsistent, and difficult to scale.

Traditional static analysis tools detect known patterns but may produce findings that require further interpretation. Developers must understand the vulnerability, determine its severity, evaluate its impact, and decide how to fix it.

Agentic DPG aims to automate this workflow through a coordinated set of agents.

The system should:

- Scan source code for potential security vulnerabilities.
- Use an LLM to analyze and explain scanner findings.
- Classify findings by severity and security standards.
- Recommend practical remediation.
- Generate structured security reports.
- Integrate with GitHub pull requests.
- Detect vulnerable dependencies.
- Apply configurable security policies.
- Eventually support threat modeling and automated remediation suggestions.

The system must not claim that code is completely secure merely because a scanner reports no findings.

---

## 3. Current Technology Stack

### Existing or already explored

- Python
- Google Gemini API
- `google-genai` Python SDK
- `python-dotenv` for environment configuration
- Semgrep for static security analysis
- JSON for structured agent outputs and report data

### Planned or optional technologies

- GitHub REST API or GitHub Actions for repository integration
- Trivy or OSV for dependency vulnerability detection
- FastAPI for a future service interface
- Docker for packaging
- LangGraph or another orchestration framework if the existing orchestration needs it
- A dashboard in a later development phase

Do not introduce additional frameworks unless they provide a concrete benefit to the next milestone.

The immediate objective is to stabilize the existing Python MVP.

---

## 4. Current Implementation Status

The following is the status based on the latest recorded development sessions. Inspect the actual repository to verify the current state.

### A. Static Scan Agent — Implemented

The project uses Semgrep to scan source code for potential vulnerabilities.

Previously, the scanner was tested using sample Python code. An early scan produced zero findings, but subsequent AI-assisted review successfully identified a SQL injection vulnerability in a test case.

The scanner's output should be treated as evidence for further analysis, not as a guarantee that all vulnerabilities have been detected.

### B. Security Review Agent — Implemented

The project uses the Google Gemini API to analyze security findings.

The AI agent is intended to:

- Understand the scanner finding and surrounding code.
- Explain the security issue.
- Assign or assess severity.
- Identify relevant OWASP and CWE classifications.
- Explain potential impact.
- Recommend a safer implementation.
- Return structured data for downstream agents.

The implementation previously used `google.genai` and the `gemini-2.5-flash` model.

The model and API configuration must be checked in the actual code before making changes.

### C. Orchestrator — Implemented

An orchestrator was created to coordinate the workflow between the scanner, AI review agent, and report generation.

A previous end-to-end execution successfully identified a SQL injection vulnerability and produced a security review report.

The orchestrator's exact current location and import structure must be determined by inspecting the repository.

### D. Report Agent — Implemented, but Requires Verification

The Report Agent formats findings into a readable security report.

A previous successful report contained:

- Issue: SQL Injection
- Severity: High
- OWASP: A03:2021 — Injection
- CWE: CWE-89
- Remediation: Use parameterized queries instead of unsafe SQL string construction.

However, report parsing and error handling were not fully stabilized in the last recorded debugging session.

### E. GitHub Integration — Not Confirmed

GitHub integration was discussed but has not been confirmed as implemented.

### F. Dependency Agent — Planned

A dedicated agent for detecting vulnerable third-party dependencies has not been confirmed as implemented.

### G. Gate Agent — Planned

A policy enforcement agent has not been confirmed as implemented.

### H. Threat Modeling, Dashboard and Automated Fixes — Future Scope

These are future enhancements, not prerequisites for fixing the current MVP.

---

## 5. Existing Workflow

The current intended workflow is:

1. Receive or select source code.
2. Run Semgrep against the code.
3. Collect scanner findings.
4. Send relevant findings and code context to the Gemini-powered Security Review Agent.
5. Parse the AI response into structured data.
6. Pass validated findings to the Report Agent.
7. Generate a security review report.
8. Return the report to the user.

Conceptually:

Source Code → Static Scan Agent → Security Review Agent → Validated Finding → Report Agent → Security Report

The orchestrator coordinates these steps.

Do not assume that all steps currently have production-grade validation or error handling. Verify them.

---

## 6. Known Bugs and Previous Issues

### Issue 1: Gemini JSON parsing

The Gemini API response was not always valid JSON in the exact format expected by the application.

This resulted in parsing errors and a downstream error similar to:

`KeyError: 'issue'`

The Report Agent expected a dictionary containing the `issue` field, but the upstream response did not always provide the expected structure.

#### Required approach

- Inspect the current prompt and response parsing logic.
- Check the actual response structure before changing code.
- Handle JSON enclosed in Markdown code fences when applicable.
- Handle malformed JSON and missing fields gracefully.
- Validate the parsed result against an explicit schema.
- Use consistent field names across all agents.
- Provide safe defaults only for optional fields.
- Do not silently invent missing vulnerability findings or classifications.
- Return clear error messages when the AI response cannot be validated.
- Ensure one malformed AI response does not crash the entire pipeline without explanation.

Prefer a structured-output or schema-constrained response feature if supported by the current SDK and model. Do not assume that JSON mode alone guarantees valid application data.

### Issue 2: Gemini API quota and rate limits

A previous session encountered a Gemini API error similar to:

`429 ResourceExhausted: Quota exceeded`

The application should handle rate limits and transient provider failures gracefully.

Implement appropriate bounded retries and backoff only where useful. Do not retry indefinitely or conceal quota exhaustion.

### Issue 3: Python imports and execution paths

Earlier development encountered:

`ModuleNotFoundError: No module named 'backend'`

There were also different import patterns during development, including imports from local modules such as `scanner` and `reviewer`.

Inspect the actual directory structure and determine the correct way to run the project.

Do not reorganize all modules simply to solve an import error. Make the smallest maintainable change.

### Issue 4: Scanner output may be empty

A previous Semgrep run returned zero findings.

An empty result is valid when the scanner finds no matching issues, but it must not be treated as proof that the source code is secure.

Ensure the application distinguishes between:

- Scan completed with findings.
- Scan completed without findings.
- Scan failed.
- Scanner unavailable or incorrectly configured.

---

## 7. Project Structure

The following represents the known and proposed architecture, not a verified inventory of the current files.

Some previously discussed filenames include:

- `backend/scanner.py`
- `backend/reviewer.py`
- `backend/orchestrator.py`
- `backend/agents/static_scan_agent.py`
- `backend/agents/security_review_agent.py`
- `backend/agents/compliance_agent.py`
- `backend/agents/report_agent.py`
- `backend/github_handler.py`
- `sample_code/`
- `reports/`
- `requirements.txt`
- `README.md`

Earlier development also referenced `scanner.py`, `test_scan.py`, `reviewer.py`, `report_agent.py`, and `orchestrator.py`.

The actual repository may differ from these examples.

**Important instruction:** Inspect the real directory tree before referring to, creating, renaming, or deleting files. Reuse existing modules wherever possible.

---

## 8. Immediate Development Goal

The immediate goal is to complete and stabilize the existing MVP using the current Gemini API.

Do not replace Gemini with Ollama or another provider yet.

Do not spend time designing a multi-provider architecture or deployment platform at this stage.

### Step 1: Inspect the repository

Before editing anything:

- Display the project directory tree.
- Read the README and requirements file, if present.
- Inspect the scanner, reviewer, orchestrator and report agent.
- Inspect any existing agent classes and test files.
- Identify the current Python environment and dependencies.
- Check how environment variables and the Gemini API key are loaded.
- Identify the existing entry point and correct execution command.
- Identify uncommitted or user-created changes before modifying files.

Produce a concise assessment of what is working, what is broken, and what is missing.

### Step 2: Run the existing application

Use the actual entry point discovered in the repository.

A previously discussed command was:

`python backend/orchestrator.py`

However, run it only if that path matches the actual directory structure.

Capture the output and any errors. Do not assume the previous execution results guarantee the current code still works.

### Step 3: Fix the existing pipeline

Prioritize the following:

1. Correct scanner-to-reviewer data flow.
2. Correct Gemini response parsing.
3. Consistent finding schemas.
4. Report Agent validation and formatting.
5. Error handling for API failures and empty scanner results.
6. Correct imports and execution paths.

Keep changes small and test each meaningful change.

### Step 4: Test security findings

Create or reuse two test fixtures:

**Vulnerable example:** Python code that constructs SQL queries using unsafe string interpolation with untrusted input.

**Safe example:** Equivalent code using parameterized SQL queries.

Verify that:

- Semgrep detects supported patterns in the vulnerable fixture.
- The AI agent receives the correct scanner findings.
- The report includes the relevant issue, severity, evidence, and remediation.
- The safe fixture does not receive an unsupported vulnerability claim.
- A clean scan is not described as proof of security.
- Invalid AI responses and API errors are handled clearly.

Tests should be deterministic where possible. Do not make every unit test dependent on a live Gemini API call.

### Step 5: Document the working MVP

Update the README only after confirming the actual setup and execution commands.

Document:

- Python environment setup.
- Dependency installation.
- Semgrep installation or configuration.
- Gemini API configuration.
- How to run the application.
- How to run tests.
- Example report output.
- Known limitations.

Never put API keys or secrets in the README, source code, logs, test fixtures, or Git history.

---

## 9. Security and Reliability Requirements

Because this is a security tool, its own implementation must follow secure coding practices.

- Load secrets from environment variables.
- Keep `.env` out of version control.
- Provide `.env.example` with placeholder values only, if needed.
- Never log API keys or authentication tokens.
- Treat repository code, comments and file contents as untrusted input.
- Do not execute arbitrary repository code merely to analyze it.
- Avoid unsafe shell command construction.
- Validate all agent outputs before using them downstream.
- Preserve scanner evidence separately from AI-generated interpretations.
- Clearly distinguish confirmed scanner findings from AI hypotheses.
- Include file paths and line numbers when available.
- Do not invent line numbers, evidence, CWE identifiers or severity just to fill a report.
- Handle malformed files, timeouts, rate limits and empty results.
- Avoid automatic code changes or blocking merges without an explicit policy.
- Treat AI-generated fixes as suggestions until validated.
- Never expose private repository contents to an external AI provider without the configured authorization and an appropriate data-handling decision.

---

## 10. Planned Agents and Future Roadmap

Implement these only after the current MVP is stable.

### Agent 1: Static Scan Agent

**Status:** Implemented.

Responsibilities:

- Run Semgrep.
- Parse scan output.
- Normalize scanner findings.
- Preserve evidence and source locations.
- Distinguish empty results from scan failures.

### Agent 2: Security Review Agent

**Status:** Implemented, requires continued validation.

Responsibilities:

- Analyze scanner findings with Gemini.
- Explain exploitability and potential impact.
- Assess severity and relevant security classifications.
- Recommend remediation.
- Return validated structured output.

### Agent 3: Dependency Agent

**Status:** Planned.

Responsibilities:

- Inspect dependency manifests and lockfiles.
- Identify vulnerable third-party packages.
- Retrieve vulnerability information from suitable tools or databases.
- Report affected package versions and available fixes.
- Avoid making unsupported claims about vulnerability status.

Potential tools include Trivy and OSV.

### Agent 4: Gate Agent

**Status:** Planned.

Responsibilities:

- Apply configurable security policies.
- Evaluate validated findings against severity thresholds.
- Produce pass, warning or fail decisions.
- Explain which policy triggered a decision.
- Support a future CI/CD integration.

The Gate Agent should use deterministic policy logic rather than relying entirely on an LLM's judgment.

### Agent 5: Threat Modeling Agent

**Status:** Future enhancement.

Responsibilities:

- Identify important application assets and trust boundaries.
- Analyze architecture and potential attack surfaces.
- Generate candidate threats.
- Suggest mitigations and security checks.

### Future GitHub Integration

Once the core workflow is stable:

- Integrate with GitHub repositories and pull requests.
- Analyze changed files rather than unnecessarily rescanning everything.
- Publish findings as pull-request comments or check results.
- Add configurable severity thresholds.
- Ensure tokens have the minimum necessary permissions.
- Handle webhook verification and duplicate event delivery if webhooks are used.

### Future UI and Deployment

Potential future enhancements:

- FastAPI service.
- Web dashboard.
- Docker packaging.
- GitHub Actions integration.
- Centralized report history.
- Audit logging and metrics.
- Configurable security policies.

These features are not required before the core MVP works reliably.

---

## 11. Development Principles for OpenCode

Follow these instructions throughout the project:

1. **Understand before editing.** Inspect existing files and explain the current implementation.
2. **Preserve working code.** Do not rebuild the project from scratch.
3. **Make incremental changes.** Solve one issue at a time.
4. **Use the existing Gemini API.** Provider replacement is explicitly deferred.
5. **Do not invent project files.** Confirm actual paths before using them.
6. **Avoid unnecessary dependencies.** Prefer the existing stack.
7. **Test changes.** Run appropriate unit tests or targeted checks after editing.
8. **Explain modifications.** State which files changed and why.
9. **Be honest about verification.** Never claim tests passed unless they were actually run.
10. **Ask before destructive changes.** Do not delete files, overwrite significant user work, reset Git history or expose secrets.
11. **Avoid scope creep.** Do not jump to dashboards, deployment or additional agents while existing errors remain unresolved.
12. **Do not silently modify security behavior.** Explain changes to severity classifications, policy thresholds and remediation logic.
13. **Preserve backward compatibility** with the current agent interfaces where reasonably possible.

---

## 12. Definition of a Stable MVP

The MVP can be considered stable when:

- The application runs from a documented entry point.
- Semgrep can scan supported source files.
- Scanner findings are passed correctly to the Security Review Agent.
- Gemini responses are parsed and validated reliably.
- The Report Agent generates consistent reports.
- Vulnerable and safe sample code can be tested.
- API errors, malformed responses and empty scans are handled.
- Secrets are not committed or exposed.
- Automated tests cover core logic without requiring a live API for every test.
- The README accurately documents setup, execution and limitations.

GitHub integration, dependency scanning, threat modeling, a dashboard and multi-provider support are subsequent milestones.

---

## 13. Instructions for Your First Response

Start by inspecting the current project directory and source files.

Then report:

1. The actual project structure.
2. Which agents and modules already exist.
3. The current execution entry point.
4. The exact issues found in the existing code.
5. The smallest set of changes required to stabilize the MVP.
6. The tests you recommend running first.

Do not immediately rewrite files or implement all future agents.

**First objective: make the existing Semgrep + Gemini + Orchestrator + Report Agent workflow reliable. Then proceed to GitHub integration.**