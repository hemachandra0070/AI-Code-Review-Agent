import json
import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

MODEL = "gemini-2.5-flash"
MAX_ATTEMPTS = 3
RETRY_WAIT_SECONDS = 2
RETRIABLE_ERROR_CODES = {429, 500, 502, 503}

REQUIRED_FIELDS = ("issue", "severity", "owasp", "cwe", "recommendation")
OPTIONAL_FIELDS = ("file", "line")

REVIEW_SCHEMA = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "issue": types.Schema(
            type=types.Type.STRING,
            description="Short name of the security issue being analyzed.",
        ),
        "severity": types.Schema(
            type=types.Type.STRING,
            description="Severity: one of Low, Medium, High, Critical.",
        ),
        "owasp": types.Schema(
            type=types.Type.STRING,
            description="Relevant OWASP Top 10 category.",
        ),
        "cwe": types.Schema(
            type=types.Type.STRING,
            description="Relevant CWE identifier.",
        ),
        "file": types.Schema(
            type=types.Type.STRING,
            description="File path of the finding if known from the provided evidence.",
        ),
        "line": types.Schema(
            type=types.Type.INTEGER,
            nullable=True,
            description="Line number of the finding if known from the provided evidence.",
        ),
        "recommendation": types.Schema(
            type=types.Type.STRING,
            description="Concrete remediation advice.",
        ),
    },
    required=list(REQUIRED_FIELDS),
)


class ReviewError(RuntimeError):
    pass


def _get_client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ReviewError(
            "GEMINI_API_KEY is not set. Add it to the .env file or environment."
        )
    return genai.Client(api_key=api_key)


def _strip_fences(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def _normalize_finding(parsed):
    if isinstance(parsed, list):
        parsed = parsed[0] if len(parsed) == 1 else None
    if not isinstance(parsed, dict):
        return None

    issue = str(parsed.get("issue") or "").strip()
    if not issue:
        return None

    finding = {"issue": issue}
    for field in REQUIRED_FIELDS[1:] + OPTIONAL_FIELDS:
        if field in parsed and parsed[field] not in (None, ""):
            finding[field] = parsed[field]

    return finding


def review_code(code):
    prompt = f"""
Analyze the following security review material (source code and/or scanner findings).

Analyze ONLY what is shown. Do NOT invent findings, files, or line numbers not present in the evidence.

Return a single JSON object exactly in this schema:
{{
    "issue": "",
    "severity": "Low|Medium|High|Critical",
    "owasp": "",
    "cwe": "",
    "file": "",
    "line": null,
    "recommendation": ""
}}

Material:

{code}
"""

    client = _get_client()

    response_text = None
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=REVIEW_SCHEMA,
                ),
            )
            response_text = (response.text or "").strip()
            break
        except Exception as exc:
            last_error = exc
            error_code = getattr(exc, "code", None)
            if error_code not in RETRIABLE_ERROR_CODES or attempt == MAX_ATTEMPTS:
                raise ReviewError(
                    f"Gemini API call failed (attempt {attempt}/{MAX_ATTEMPTS}): {exc}"
                ) from exc
            wait = RETRY_WAIT_SECONDS * attempt
            print(f"[Security Review Agent] Transient error {error_code}, retrying in {wait}s...")
            time.sleep(wait)

    if not response_text:
        raise ReviewError(
            f"Gemini returned an empty response. Last error: {last_error}"
        )

    try:
        parsed = json.loads(_strip_fences(response_text))
    except json.JSONDecodeError as exc:
        raise ReviewError(
            f"Gemini response was not valid JSON: {exc}. Response started with: {response_text[:200]}"
        ) from exc

    finding = _normalize_finding(parsed)
    if finding is None:
        raise ReviewError(
            f"Gemini response did not match the expected finding schema. "
            f"Response: {json.dumps(parsed)[:300]}"
        )

    return finding
