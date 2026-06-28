---
name: testing-recon-suite
description: Test the recon-suite CLI tool end-to-end. Use when verifying DNS brute force, passive enumeration, report generation, or error handling changes.
---

# Testing the Automated Recon Tool

## Environment Setup

- **Python 3.11+** required
- Install dependencies: `pip install -r requirements.txt`
- The embedded Python on Devin's Windows VM does not add `.` to `sys.path`. To run the tool, create a `run_test.py` wrapper:
  ```python
  import sys, os
  sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
  from main import main
  sys.exit(main())
  ```
  Then run: `python run_test.py <domain> [flags]`
- Sublist3r might not be installable in all environments. The tool gracefully falls back to crt.sh for passive enumeration.
- crt.sh may return 503 intermittently -- this is a transient upstream issue, not a bug. Retry or accept 0 passive results.

## Running the Tool

```
python run_test.py google.com                          # default settings
python run_test.py google.com --workers 5              # custom concurrency
python run_test.py google.com --wordlist path/to/file  # custom wordlist
```

## Key Test Scenarios

1. **Basic end-to-end:** Run against `google.com`. Expect brute-force hits for subdomains like `mail`, `api`, `admin`, `vpn`. Report generated at `reports/google.com.html`.
2. **Portable paths:** Run from a directory other than the repo root (e.g. `C:\Users\Administrator`). The tool should find `wordlists/subdomains.txt` via `Path(__file__).parent` without warnings.
3. **Bad wordlist encoding:** Create a non-UTF-8 file (`\xff\xfe` bytes). Expect "Could not decode wordlist ... as UTF-8" message and fallback to 7 built-in defaults.
4. **Missing wordlist:** Use `--wordlist nonexistent_file.txt`. Expect "Wordlist not found" warning and graceful fallback.
5. **Workers flag:** Use `--workers N`. Verify output says "Resolving with N concurrent workers".

## Report Verification

Check `reports/<domain>.html` for:
- Passive table: `<th>Subdomain</th><th>Source</th>` (Source = "Sublist3r", "crt.sh", or "N/A")
- Brute-force table: `<th>Hostname</th><th>IP Address</th><th>Record Type</th>` (Record Type = "A" or "CNAME")
- Use `Select-String` (PowerShell) or `grep` to verify specific HTML elements.

## Notes

- All testing is shell-based (CLI tool). No recording needed.
- PowerShell treats tqdm's stderr progress bar as an error -- the exit code may show 1 even on success. Verify actual output content rather than relying on exit code alone.
- The default wordlist has only 7 entries, so brute-force completes in ~2-5 seconds.

## Devin Secrets Needed

None -- the tool uses public DNS and HTTP APIs only.