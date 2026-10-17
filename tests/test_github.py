import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from backend import github_handler


class NormalizeRepoUrlTests(unittest.TestCase):
    def test_owner_repo_short_form(self):
        self.assertEqual(
            github_handler.normalize_repo_url("octocat/Hello-World"),
            "https://github.com/octocat/Hello-World",
        )

    def test_https_url(self):
        self.assertEqual(
            github_handler.normalize_repo_url("https://github.com/octocat/Hello-World"),
            "https://github.com/octocat/Hello-World",
        )

    def test_https_url_with_git_suffix(self):
        self.assertEqual(
            github_handler.normalize_repo_url("https://github.com/octocat/Hello-World.git"),
            "https://github.com/octocat/Hello-World",
        )

    def test_ssh_url(self):
        self.assertEqual(
            github_handler.normalize_repo_url("git@github.com:octocat/Hello-World.git"),
            "https://github.com/octocat/Hello-World",
        )

    def test_www_url_trailing_slash(self):
        self.assertEqual(
            github_handler.normalize_repo_url("https://www.github.com/octocat/Hello-World/"),
            "https://github.com/octocat/Hello-World",
        )

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            github_handler.normalize_repo_url("   ")

    def test_non_github_host_rejected(self):
        with self.assertRaises(ValueError):
            github_handler.normalize_repo_url("https://gitlab.com/owner/repo")

    def test_nonsense_rejected(self):
        with self.assertRaises(ValueError):
            github_handler.normalize_repo_url("not a repo url with spaces")


class TokenHandlingTests(unittest.TestCase):
    def test_inject_token_adds_prefix(self):
        result = github_handler._inject_token("https://github.com/owner/repo", "s3cr3t")
        self.assertEqual(
            result,
            "https://x-access-token:s3cr3t@github.com/owner/repo",
        )

    def test_no_token_unchanged(self):
        self.assertEqual(
            github_handler._inject_token("https://github.com/owner/repo", None),
            "https://github.com/owner/repo",
        )

    def test_non_https_unchanged(self):
        self.assertEqual(
            github_handler._inject_token("git@github.com:owner/repo", "s3cr3t"),
            "git@github.com:owner/repo",
        )

    def test_sanitize_output_redacts_token(self):
        token = "s3cr3t"
        clone_url = github_handler._inject_token("https://github.com/owner/repo", token)
        stderr = f"fatal: unable to access '{clone_url}': 404"
        sanitized = github_handler._sanitize_output(stderr, clone_url)
        self.assertNotIn(token, sanitized)
        self.assertIn("x-access-token:***", sanitized)

    def test_sanitize_output_no_token_untouched(self):
        stderr = "Cloning into 'repo'..."
        self.assertEqual(github_handler._sanitize_output(stderr, "https://github.com/owner/repo"), stderr)


class CloneRepoValidationTests(unittest.TestCase):
    def test_invalid_url_fails_without_subprocess(self):
        result = github_handler.clone_repo("https://gitlab.com/owner/repo", "unused_dest")
        self.assertEqual(result["status"], "failed")
        self.assertIn("Unsupported repository reference", result["error"])


if __name__ == "__main__":
    unittest.main()
