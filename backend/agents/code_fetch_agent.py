import os

from github_handler import clone_repo


class CodeFetchAgent:

    def execute(self, repo_url, dest, ref=None):
        print("[Code Fetch Agent] Cloning repository...")

        token = os.getenv("GITHUB_TOKEN")
        result = clone_repo(repo_url, dest, ref=ref, token=token)
        status = result.get("status", "failed")

        print(f"[Code Fetch Agent] Fetch status: {status} ({result.get('repo', 'unknown repo')}, {result.get('ref', 'unknown ref')})")

        return result
