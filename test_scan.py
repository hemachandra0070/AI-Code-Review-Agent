import json

from backend.scanner import run_scan

result = run_scan("sample_code")

print(f"Status: {result['status']}")
if result.get("error"):
    print(f"Error: {result['error']}")
print(json.dumps(result["findings"], indent=2))
