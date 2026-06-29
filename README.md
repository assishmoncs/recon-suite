# Automated Recon Tool (v2)

A clean, modular Python 3 command-line tool for domain reconnaissance.
This is **version 2** with enhanced passive enumeration, PDF report
generation, expanded wordlists, and improved error resilience.

> **Ethical use only.** Only scan domains you own or have explicit, written
> authorization to test. Unauthorized scanning of third-party infrastructure
> may be illegal in your jurisdiction.

## Features

- **Input validation** -- checks that the target looks like a real domain
  before doing any work.
- **Passive subdomain enumeration** -- uses the [Sublist3r](https://github.com/aboul3la/Sublist3r)
  library *in-process* (`import sublist3r`), not via shell commands. If
  Sublist3r isn't installed or returns no results, the tool aggregates
  results from **multiple fallback sources**:
  - **crt.sh** -- Certificate Transparency logs with retry logic and
    exponential backoff (3 retries, 30s timeout).
  - **AlienVault OTX** -- Open Threat Exchange passive DNS (no API key
    required).
  - **HackerTarget** -- Free host search API.
- **Concurrent DNS brute force** -- reads candidate prefixes from
  `wordlists/subdomains.txt` (109 entries covering common infrastructure
  patterns), builds `<word>.<domain>` candidates, and resolves them
  **concurrently** using `concurrent.futures.ThreadPoolExecutor`
  (configurable via `--workers`). Resolution uses `dnspython` (falling back
  to `socket` if unavailable). DNS record types (A / CNAME) are detected.
- **Real-time progress bar** -- `tqdm` displays a dynamic progress bar
  during DNS brute-force lookups.
- **Dual report formats** -- generates both HTML and PDF reports by default:
  - **HTML**: Self-contained dark-theme report with embedded CSS.
  - **PDF**: Print-friendly A4 report via `xhtml2pdf`.
  - Controlled via `--output-format` (html, pdf, or both).
- **Robust error handling** -- specific exception handlers for network
  errors, encoding issues, and I/O errors, with informative messages
  and graceful fallbacks. Sublist3r's noisy stderr warnings are
  suppressed.
- **Portable file paths** -- default wordlist and report paths are resolved
  relative to the script location using `pathlib`.
- **Colored terminal output** -- via `colorama`, with clear progress
  messages at each stage.

## Project Structure

```
recon-suite/
│
├── main.py                  # CLI entry point / orchestration
├── requirements.txt
├── README.md
├── .gitignore
├── reports/                 # Generated HTML + PDF reports land here
├── wordlists/
│   └── subdomains.txt       # DNS brute-force wordlist (109 entries)
└── modules/
    ├── __init__.py
    ├── subdomains.py        # Passive enumeration (Sublist3r + multi-source fallback)
    ├── dns_bruteforce.py    # Concurrent active DNS brute force
    ├── report.py            # HTML + PDF report generation
    └── utils.py             # Domain validation + colored output helpers
```

## Installation

Requires **Python 3.11+**.

```bash
git clone <this-repo>
cd recon-suite
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py example.com
```

Optional flags:

```bash
python main.py example.com --wordlist wordlists/subdomains.txt --threads 40 --workers 20 --output-format both
```

| Flag              | Description                                          | Default                      |
|-------------------|------------------------------------------------------|------------------------------|
| `domain`          | Target domain (positional, required)                 | --                           |
| `--wordlist`      | Path to the DNS brute-force wordlist                 | `wordlists/subdomains.txt`   |
| `--threads`       | Threads used internally by Sublist3r                 | `40`                         |
| `--workers`       | Concurrent workers for DNS brute-force lookups       | `20`                         |
| `--output-format` | Report format: `html`, `pdf`, or `both`              | `both`                       |

### Example output

```
==================================================
      Automated Recon Tool -- v2
==================================================
Target: example.com

[*] Running passive enumeration...
[*] Querying passive OSINT sources via Sublist3r (40 threads, this can take 10-60s)...
[!] Sublist3r returned no results.
[*] Falling back to multi-source passive lookup...
[*] Querying crt.sh Certificate Transparency logs...
[*] Querying AlienVault OTX...
[*] Querying HackerTarget...
[+] Found 23 subdomains (via crt.sh, AlienVault OTX, HackerTarget).

[*] Running DNS brute force...
[*] Loaded 109 candidate prefixes from 'wordlists/subdomains.txt'.
[*] Resolving with 20 concurrent workers...
DNS brute-force: 100%|##########| 109/109 [00:12<00:00, 8.74host/s]
[+] Found 6 additional hosts.

[*] Generating report...
[+] Done!

[*] Report(s):
  reports/example.com.html
  reports/example.com.pdf
```

## How it works

1. **`main.py`** validates the domain (`modules/utils.validate_domain`) and
   orchestrates the three stages below, printing colored progress messages
   throughout.
2. **`modules/subdomains.py`** calls `sublist3r.main()` directly as a Python
   function call (no subprocess), with Sublist3r's noisy stderr suppressed.
   If Sublist3r can't be imported, raises an error, or returns empty results,
   it falls back to an aggregated multi-source lookup (crt.sh with retry +
   AlienVault OTX + HackerTarget).
3. **`modules/dns_bruteforce.py`** loads `wordlists/subdomains.txt` (109
   entries), builds `<word>.<domain>` for each entry, and resolves them
   concurrently using `ThreadPoolExecutor` with `dnspython` (or `socket`
   fallback). A `tqdm` progress bar shows real-time progress.
4. **`modules/report.py`** renders results into:
   - A self-contained HTML file (dark theme, stat cards, two results tables).
   - A PDF file (A4, print-friendly light theme) using `xhtml2pdf`.

## Error Fixes in v2

The following issues from v1 have been addressed:

| Issue | Fix |
|-------|-----|
| `[!] Error: Coloring libraries not installed` | Sublist3r's stderr suppressed during import and execution |
| `Sublist3r engine 'DNSdumpster' failed` | Automatic fallback to multi-source passive lookup when Sublist3r returns no results |
| `crt.sh fallback lookup failed: Read timed out` | Timeout increased to 30s with 3 retries + exponential backoff |
| `Found 0 subdomains` | Added AlienVault OTX and HackerTarget as additional sources |
| Small wordlist (7 entries) | Expanded to 109 common infrastructure prefixes |
| No PDF output | Added xhtml2pdf-based PDF report generation |

## License

For educational and authorized security-testing purposes only.
