from scanner import run_scan


class StaticScanAgent:

    def execute(self, path):
        print("[Static Scan Agent] Running Semgrep...")

        result = run_scan(path)
        status = result.get("status", "scan_failed")
        count = len(result.get("findings", []))

        print(f"[Static Scan Agent] Scan status: {status} ({count} findings)")

        return result
