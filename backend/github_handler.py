import base64
import binascii
import json as jsonlib
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

GIT_TIMEOUT_SECONDS = 600
API_TIMEOUT_SECONDS = 60
API_BASE = "https://api.github.com"
API_ACCEPT = "application/vnd.github+json"
API_USER_AGENT = "agentic-dpg"
API_VERSION = "2022-11-28"
PR_PAGE_SIZE = 100
PR_MAX_PAGES = 20
USER_AGENT = "agentic-dpg"

REMOVED = "removed"
ADDED = "added"
MODIFIED = "modified"
RENAMED = "renamed"

_REPO_PATTERN = re.compile(
    r"^(?:https://(?:www\.)?github\.com/|git@github\.com:)"
    r"([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)
_SHORT_PATTERN = re.compile(r"^([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)$")


def normalize_repo_url(repo_url):
    repo_url = str(repo_url or "").strip()
    if not repo_url:
        raise ValueError("Repository URL is empty.")

    match = _REPO_PATTERN.match(repo_url)
    if not match:
        match = _SHORT_PATTERN.match(repo_url)
    if not match:
        raise ValueError(
            f"Unsupported repository reference: '{repo_url}'. "
            "Use owner/repo, a GitHub HTTPS URL, or an SSH URL."
        )

    owner, repo = match.group(1), match.group(2)
    return f"https://github.com/{owner}/{repo}"


def _inject_token(url, token):
    prefix = "https://"
    if not token or not url.startswith(prefix):
        return url
    return f"{prefix}x-access-token:{token}@{url[len(prefix):]}"


def _sanitize_output(text, clone_url):
    if not clone_url or "x-access-token:" not in clone_url:
        return text
    sanitized = re.sub(r"https://x-access-token:[^@]+@", "https://x-access-token:***@", clone_url)
    return text.replace(clone_url, sanitized)


def clone_repo(repo_url, dest, ref=None, token=None):
    try:
        normalized = normalize_repo_url(repo_url)
    except ValueError as exc:
        return {"status": "failed", "error": str(exc)}

    clone_url = _inject_token(normalized, token)

    command = ["git", "clone", "--depth", "1"]
    if ref:
        command += ["--branch", str(ref)]
    command += [clone_url, str(dest)]

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_CREDENTIAL_STORE"] = "none"

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "repo": normalized,
            "error": f"git clone timed out after {GIT_TIMEOUT_SECONDS} seconds.",
        }
    except OSError as exc:
        return {
            "status": "failed",
            "repo": normalized,
            "error": f"git could not be executed: {exc}",
        }

    stderr = _sanitize_output(proc.stderr or "", clone_url)

    if proc.returncode != 0:
        detail = stderr.strip().splitlines()
        reason = detail[-1] if detail else f"git clone exited with code {proc.returncode}."
        if "Authentication failed" in reason or "could not read Username" in reason:
            reason = (
                "Authentication failed. If the repository is private, set "
                "GITHUB_TOKEN in .env with minimum read access."
            )
        return {
            "status": "failed",
            "repo": normalized,
            "error": reason,
        }

    return {
        "status": "fetched",
        "repo": normalized,
        "ref": ref or "default branch",
        "path": str(dest),
        "log": _sanitize_output(stderr.strip(), clone_url),
    }


def owner_repo(normalized_url):
    remainder = normalized_url.replace("https://github.com/", "")
    owner, _, repo = remainder.partition("/")
    return owner, repo


def _request(method, url, token=None, data=None):
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("Accept", API_ACCEPT)
    req.add_header("User-Agent", API_USER_AGENT)
    req.add_header("X-GitHub-Api-Version", API_VERSION)
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read()
        except Exception:
            pass
        return exc.code, body, dict(exc.headers or {})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, None, {"x-transport-error": str(exc)}


def api_get(path, params=None, token=None):
    url = API_BASE + "/" + path.lstrip("/")
    if params:
        url += "?" + urllib.parse.urlencode(params)
    status, body, headers = _request("GET", url, token=token)
    payload = None
    if status is not None:
        try:
            payload = jsonlib.loads(body.decode("utf-8", "replace"))
        except (jsonlib.JSONDecodeError, ValueError):
            payload = None
    return status, payload, headers


def api_post(path, data, token=None):
    url = API_BASE + "/" + path.lstrip("/")
    body = jsonlib.dumps(data).encode("utf-8")
    status, response, headers = _request("POST", url, token=token, data=body)
    payload = None
    if status is not None:
        try:
            payload = jsonlib.loads(response.decode("utf-8", "replace"))
        except (jsonlib.JSONDecodeError, ValueError):
            payload = None
    return status, payload, headers


def get_pull_request(owner, repo, number, token=None):
    path = f"repos/{owner}/{repo}/pulls/{int(number)}"
    status, payload, headers = api_get(path, token=token)
    if status is None:
        return {"status": "failed", "error": f"GitHub API transport error: {headers.get('x-transport-error')}"}
    if status == 404:
        return {"status": "not_found", "error": "Pull request not found or inaccessible."}
    if status == 403:
        return {"status": _rate_limit_status(headers), "error": _rate_limit_error(headers)}
    if status != 200:
        detail = _error_detail(payload, headers)
        return {"status": "failed", "error": f"GitHub API error {status}: {detail}"}
    if not isinstance(payload, dict) or not (payload.get("head") or {}).get("sha"):
        return {"status": "failed", "error": "GitHub API returned a malformed pull request payload."}
    return {
        "status": "ok",
        "head_sha": payload["head"]["sha"],
        "title": payload.get("title", ""),
        "author": (payload.get("user") or {}).get("login", "unknown"),
    }


def get_pr_changed_files(owner, repo, number, token=None):
    path = f"repos/{owner}/{repo}/pulls/{int(number)}/files"
    files = []
    page = 1
    while page <= PR_MAX_PAGES:
        status, payload, headers = api_get(
            path, params={"per_page": PR_PAGE_SIZE, "page": page}, token=token
        )
        if status is None:
            return {"status": "failed", "error": f"GitHub API transport error: {headers.get('x-transport-error')}"}
        if status == 404:
            return {"status": "not_found", "error": "Pull request not found or inaccessible."}
        if status == 403:
            return {"status": _rate_limit_status(headers), "error": _rate_limit_error(headers)}
        if status != 200:
            detail = _error_detail(payload, headers)
            return {"status": "failed", "error": f"GitHub API error {status}: {detail}"}
        if not isinstance(payload, list):
            return {"status": "failed", "error": "GitHub API returned a malformed changed-files payload."}
        for item in payload:
            if not isinstance(item, dict) or not item.get("filename"):
                return {"status": "failed", "error": "GitHub API returned a malformed changed-files entry."}
        files.extend(payload)
        if len(payload) < PR_PAGE_SIZE:
            break
        page += 1
    else:
        return {
            "status": "failed",
            "error": f"Changed-files pagination exceeded {PR_MAX_PAGES} pages.",
        }

    return {"status": "ok", "files": [normalize_pr_file(item) for item in files]}


def normalize_pr_file(item):
    return {
        "filename": item.get("filename", ""),
        "status": item.get("status", ""),
        "additions": item.get("additions", 0),
        "deletions": item.get("deletions", 0),
        "changes": item.get("changes", 0),
        "sha": item.get("sha", ""),
        "patch": item.get("patch"),
        "previous_filename": item.get("previous_filename"),
    }


def fetch_file_blob(owner, repo, sha, token=None):
    path = f"repos/{owner}/{repo}/git/blobs/{sha}"
    status, payload, headers = api_get(path, token=token)
    if status is None:
        return {"status": "failed", "error": f"GitHub API transport error: {headers.get('x-transport-error')}"}
    if status == 422:
        return {"status": "failed", "error": "File exceeds GitHub blob size limits."}
    if status == 404:
        return {"status": "failed", "error": f"File content not found for blob {sha[:10]}."}
    if status == 403:
        return {"status": _rate_limit_status(headers), "error": _rate_limit_error(headers)}
    if status != 200:
        detail = _error_detail(payload, headers)
        return {"status": "failed", "error": f"GitHub API error {status}: {detail}"}
    if not isinstance(payload, dict) or not payload.get("content"):
        return {"status": "failed", "error": "GitHub API returned a malformed blob payload."}
    try:
        raw_base64 = re.sub(r"\s", "", payload["content"])
        content = base64.b64decode(raw_base64, validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        return {"status": "failed", "error": f"Could not decode file content: {exc}"}
    return {"status": "ok", "content": content}


def get_pr_comments(owner, repo, number, token=None):
    path = f"repos/{owner}/{repo}/issues/{int(number)}/comments"
    status, payload, headers = api_get(path, params={"per_page": PR_PAGE_SIZE}, token=token)
    if status is None:
        return {"status": "failed", "error": f"GitHub API transport error: {headers.get('x-transport-error')}"}
    if status == 404:
        return {"status": "not_found", "error": "Pull request not found or inaccessible."}
    if status == 403:
        return {"status": _rate_limit_status(headers), "error": _rate_limit_error(headers)}
    if status != 200:
        detail = _error_detail(payload, headers)
        return {"status": "failed", "error": f"GitHub API error {status}: {detail}"}
    if not isinstance(payload, list):
        return {"status": "failed", "error": "GitHub API returned a malformed comments payload."}
    return {"status": "ok", "comments": payload}


def post_pr_comment(owner, repo, number, body, token=None):
    path = f"repos/{owner}/{repo}/issues/{int(number)}/comments"
    status, payload, headers = api_post(path, {"body": body}, token=token)
    if status is None:
        return {"status": "failed", "error": f"GitHub API transport error: {headers.get('x-transport-error')}"}
    if status == 403:
        return {"status": _rate_limit_status(headers), "error": _rate_limit_error(headers, posting=True)}
    if status >= 400:
        detail = _error_detail(payload, headers)
        return {"status": "failed", "error": f"GitHub API error {status}: {detail}"}
    if not isinstance(payload, dict) or "id" not in payload:
        return {"status": "failed", "error": "GitHub API returned a malformed comment payload."}
    return {"status": "posted", "comment_id": payload["id"], "html_url": payload.get("html_url", "")}


def _error_detail(payload, headers):
    if isinstance(payload, dict) and payload.get("message"):
        return payload["message"]
    return headers.get("x-transport-error", "no details available")


def _rate_limit_status(headers):
    if str(headers.get("x-ratelimit-remaining", "")) == "0":
        return "rate_limited"
    return "auth_failed"


def _rate_limit_error(headers, posting=False):
    if str(headers.get("x-ratelimit-remaining", "")) == "0":
        if posting:
            return (
                "GitHub API rate limit exceeded. Set GITHUB_TOKEN in .env (minimum "
                "'pull requests: read' / classic repo scope) and retry."
            )
        return (
            "GitHub API rate limit exceeded for anonymous access. Set GITHUB_TOKEN in "
            ".env (minimum 'pull requests: read' / classic repo scope) and retry."
        )
    return (
        "GitHub API access denied. If the repository is private or commenting is intended, "
        "set GITHUB_TOKEN in .env with minimum required permissions."
    )

