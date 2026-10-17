import base64
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from backend import github_handler
from backend import orchestrator
from backend.agents import report_agent
from backend.agents.report_agent import ReportAgent, validate_severity


def pr_file(filename, status="modified", sha="deadbeef", patch="@@ -1 +1 @@", **extra):
    item = {
        "filename": filename,
        "status": status,
        "additions": 1,
        "deletions": 0,
        "changes": 1,
        "sha": sha,
        "patch": patch,
    }
    item.update(extra)
    return item


class ChangedFilesPaginationTests(unittest.TestCase):
    def test_pagination_accumulates_pages(self):
        page1 = [pr_file(f"p1/a{i}.py", sha=f"sha{i}") for i in range(100)]
        page2 = [pr_file("p2/b.py", sha="shab"), pr_file("p2/c.py", sha="shac")]
        responses = [
            (200, page1, {}),
            (200, page2, {}),
        ]
        calls = []

        def fake_api_get(path, params=None, token=None):
            calls.append(params)
            return responses.pop(0)

        with mock.patch.object(github_handler, "api_get", fake_api_get):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["files"]), 102)
        self.assertEqual(result["files"][0]["filename"], "p1/a0.py")
        self.assertEqual(result["files"][101]["filename"], "p2/c.py")
        self.assertEqual(calls[0]["page"], 1)
        self.assertEqual(calls[1]["page"], 2)

    def test_single_page_stops_early(self):
        files = [pr_file("one.py", sha="s1")]
        with mock.patch.object(
            github_handler, "api_get", lambda path, params=None, token=None: (200, files, {})
        ):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["files"]), 1)


class ChangedFilesFailureTests(unittest.TestCase):
    def test_not_found(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, params=None, token=None: (404, {"message": "Not Found"}, {})
        ):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)
        self.assertEqual(result["status"], "not_found")

    def test_rate_limit_suggests_token(self):
        with mock.patch.object(
            github_handler,
            "api_get",
            lambda path, params=None, token=None: (403, {"message": "rate limit"}, {"x-ratelimit-remaining": "0"}),
        ):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)
        self.assertEqual(result["status"], "rate_limited")
        self.assertIn("GITHUB_TOKEN", result["error"])

    def test_transport_error(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, params=None, token=None: (None, None, {"x-transport-error": "no net"})
        ):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)
        self.assertEqual(result["status"], "failed")
        self.assertIn("transport", result["error"])

    def test_malformed_payload(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, params=None, token=None: (200, {"unexpected": "dict"}, {})
        ):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)
        self.assertEqual(result["status"], "failed")
        self.assertIn("malformed", result["error"])

    def test_malformed_entry(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, params=None, token=None: (200, [{"no": "filename"}], {})
        ):
            result = github_handler.get_pr_changed_files("owner", "repo", 7)
        self.assertEqual(result["status"], "failed")

    def test_pull_request_not_found(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, token=None: (404, {"message": "Not Found"}, {})
        ):
            result = github_handler.get_pull_request("owner", "repo", 7)
        self.assertEqual(result["status"], "not_found")


class BlobTests(unittest.TestCase):
    def test_blob_decode(self):
        encoded = base64.b64encode(b"main.py content").decode("ascii")
        with mock.patch.object(
            github_handler, "api_get", lambda path, token=None: (200, {"content": encoded}, {})
        ):
            result = github_handler.fetch_file_blob("owner", "repo", "sha")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["content"], b"main.py content")

    def test_too_large(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, token=None: (422, {"message": "too large"}, {})
        ):
            result = github_handler.fetch_file_blob("owner", "repo", "sha")
        self.assertEqual(result["status"], "failed")
        self.assertIn("size", result["error"])

    def test_missing_blob(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, token=None: (404, {"message": "Not Found"}, {})
        ):
            result = github_handler.fetch_file_blob("owner", "repo", "sha")
        self.assertEqual(result["status"], "failed")

    def test_malformed_blob(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, token=None: (200, {"nope": 1}, {})
        ):
            result = github_handler.fetch_file_blob("owner", "repo", "sha")
        self.assertEqual(result["status"], "failed")

    def test_invalid_base64(self):
        with mock.patch.object(
            github_handler, "api_get", lambda path, token=None: (200, {"content": "!!!"}, {})
        ):
            result = github_handler.fetch_file_blob("owner", "repo", "sha")
        self.assertEqual(result["status"], "failed")


class ChangedFileSelectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.pr_dir = Path(self._tmp.name)

    def _select(self, files, tempdir):
        with mock.patch.object(
            orchestrator.github_handler,
            "fetch_file_blob",
            github_handler.fetch_file_blob,
        ):
            return orchestrator._select_pr_files("owner", "repo", files, tempdir, token=None)

    def test_deleted_file_skipped_with_note(self):
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            side_effect=AssertionError("must not fetch deleted files"),
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("gone.py", status="removed", sha="")], self.pr_dir
            )
        self.assertEqual(selected, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("deleted", notes[0])

    def test_renamed_file_scanned_with_note(self):
        payload = io.BytesIO(b"print('x')")
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            lambda owner, repo, sha, token=None: {"status": "ok", "content": payload.getvalue()},
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner",
                "repo",
                [pr_file("renamed.py", status="renamed", previous_filename="old.py")],
                self.pr_dir,
            )
        self.assertEqual(selected, ["renamed.py"])
        self.assertTrue(any("renamed from old.py" in note for note in notes))

    def test_unsupported_type_skipped(self):
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            side_effect=AssertionError("must not fetch unsupported files"),
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("image.exe", sha="s")], self.pr_dir
            )
        self.assertEqual(selected, [])
        self.assertTrue(any("unsupported file type" in note for note in notes))

    def test_oversized_file_skipped(self):
        content = b"a" * (orchestrator.MAX_FILE_BYTES + 1)
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            lambda owner, repo, sha, token=None: {"status": "ok", "content": content},
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("big.py", sha="s")], self.pr_dir
            )
        self.assertEqual(selected, [])
        self.assertTrue(any("exceeds" in note for note in notes))

    def test_binary_content_skipped(self):
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            lambda owner, repo, sha, token=None: {"status": "ok", "content": b"PK\x00\x03data"},
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("archive.py", sha="s")], self.pr_dir
            )
        self.assertEqual(selected, [])
        self.assertTrue(any("binary" in note for note in notes))

    def test_supported_file_written(self):
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            lambda owner, repo, sha, token=None: {"status": "ok", "content": b"print('ok')"},
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("src/main.py", sha="s")], self.pr_dir
            )
        self.assertEqual(selected, ["src/main.py"])
        self.assertFalse(notes)
        self.assertTrue((self.pr_dir / "src" / "main.py").exists())

    def test_unsafe_path_skipped(self):
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            lambda owner, repo, sha, token=None: {"status": "ok", "content": b"x"},
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("../escape.py", sha="s")], self.pr_dir
            )
        self.assertEqual(selected, [])
        self.assertTrue(any("unsafe path" in note for note in notes))

    def test_blob_failure_reported(self):
        with mock.patch.object(
            orchestrator,
            "fetch_file_blob",
            lambda owner, repo, sha, token=None: {"status": "failed", "error": "GitHub API error 404: Not Found"},
        ):
            selected, notes = orchestrator._select_pr_files(
                "owner", "repo", [pr_file("src/missing.py", sha="s")], self.pr_dir
            )
        self.assertEqual(selected, [])
        self.assertTrue(any("content fetch failed" in note for note in notes))


class CommentDeduplicationTests(unittest.TestCase):
    def test_marker_dedupe_prevents_duplicate_post(self):
        marker = orchestrator.COMMENT_MARKER_TEMPLATE.format(pr=3, sha="abc123")
        with mock.patch.object(
            orchestrator,
            "get_pr_comments",
            lambda *a, **k: {"status": "ok", "comments": [{"body": f"{marker}\n"}]},
        ):
            with mock.patch.object(
                orchestrator,
                "post_pr_comment",
                side_effect=AssertionError("must not re-post duplicated comment"),
            ) as poster:
                posted = orchestrator._post_pr_findings_comment(
                    "owner", "repo", 3, "abc123", {}, "reports", token="t"
                )
        self.assertTrue(posted)
        poster.assert_not_called()

    def test_no_token_skips_posting(self):
        posted = orchestrator._post_pr_findings_comment("owner", "repo", 3, "abc123", {}, "reports", token=None)
        self.assertFalse(posted)


class SeverityValidationTests(unittest.TestCase):
    def test_ai_inflation_flagged(self):
        note = validate_severity({"severity": "Critical", "issue": "SQLi"}, [{"severity": "WARNING"}])
        self.assertIn("exceeds the scanner's maximum rule severity", note)
        self.assertIn("WARNING", note)

    def test_matching_severity_not_flagged(self):
        note = validate_severity({"severity": "High", "issue": "SQLi"}, [{"severity": "ERROR"}])
        self.assertIsNone(note)

    def test_unknown_ai_severity_flagged(self):
        note = validate_severity({"severity": "Maybe", "issue": "SQLi"}, [{"severity": "ERROR"}])
        self.assertIn("not recognized", note)

    def test_no_evidence_unverified(self):
        note = validate_severity({"severity": "High", "issue": "SQLi"}, [])
        self.assertIn("unverified", note)

    def test_note_rendered_in_report(self):
        report = ReportAgent().execute(
            {"issue": "SQLi", "severity": "Critical"},
            evidence=[{"severity": "WARNING"}],
        )
        self.assertIn("Severity note", report)
        self.assertIn("exceeds", report)


class PrArgumentTests(unittest.TestCase):
    def test_pr_without_repo_rejected(self):
        exit_code = orchestrator.main(["--pr", "3"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
