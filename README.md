# Automated Recon Tool (v1 -- MVP)

A clean, modular Python 3 command-line tool for basic domain reconnaissance.
This is **version 1**: a minimal, working MVP focused on passive subdomain
enumeration, DNS brute forcing, and HTML report generation. More advanced
features (Shodan, theHarvester, Wappalyzer, PDF reports) are intentionally
left out of this version and planned for later releases.

> **Ethical use only.** Only scan domains you own or have explicit, written
> authorization to test. Unauthorized scanning of third-party infrastructure
> may be illegal in your jurisdiction.

## Features

- **Input validation** -- checks that the target looks like a real domain
  before doing any work.
- **Passive subdomain enumeration** -- uses the [Sublist3r](https://github.com/aboul3la/Sublist3r)
  library *in-process* (`import sublist3r`), not via shell commands. If
  Sublist3r isn't installed or its lookup fails, the tool automatically
  falls back to a lightweight passive lookup against crt.sh Certificate
  Transparency logs so you still get a result. The discovery source
  ("Sublist3r" or "crt.sh") is reported in the terminal and in the HTML
  report.
- **Concurrent DNS brute force** -- reads candidate prefixes from
  `wordlists/subdomains.txt`, builds `<word>.<domain>` candidates, and
  resolves them **concurrently** using `concurrent.futures.ThreadPoolExecutor`
  (configurable via `--workers`). Resolution uses `dnspython` (falling back
  to `socket` if unavailable). Only hosts that actually resolve are kept;
  duplicates are removed automatically. DNS record types (A / CNAME) are
  detected and included in results.
- **Real-time progress bar** -- `tqdm` displays a dynamic progress bar
  during DNS brute-force lookups (gracefully degrades if `tqdm` is not
  installed).
- **Robust error handling** -- specific exception handlers for network
  errors (`requests.RequestException`), encoding issues
  (`UnicodeDecodeError`), and I/O errors (`OSError`), with informative
  messages and graceful fallbacks.
- **Portable file paths** -- default wordlist and report paths are resolved
  relative to the script location using `pathlib`, so the tool works
  correctly regardless of the working directory.
- **HTML report** -- generates a clean, styled `reports/<domain>.html`
  report (CSS only, no JavaScript) summarizing everything found, including
  a **Source** column for passive results and a **Record Type** column for
  brute-forced entries.
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
├── reports/                 # Generated HTML reports land here
├── wordlists/
│   └── subdomains.txt       # DNS brute-force wordlist
└── modules/
    ├── __init__.py
    ├── subdomains.py        # Passive enumeration (Sublist3r + crt.sh fallback)
    ├── dns_bruteforce.py    # Concurrent active DNS brute force
    ├── report.py            # HTML report generation
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
python main.py example.com --wordlist wordlists/subdomains.txt --threads 40 --workers 20
```

| Flag          | Description                                          | Default                      |
|---------------|------------------------------------------------------|------------------------------|
| `domain`      | Target domain (positional, required)                 | --                           |
| `--wordlist`  | Path to the DNS brute-force wordlist                 | `wordlists/subdomains.txt`   |
| `--threads`   | Threads used internally by Sublist3r                 | `40`                         |
| `--workers`   | Concurrent workers for DNS brute-force lookups       | `20`                         |

### Example output

```
==================================================
      Automated Recon Tool -- v1 (MVP)
==================================================
Target: example.com

[*] Running passive enumeration...
[*] Querying passive OSINT sources via Sublist3r (40 threads, this can take 10-60s)...
[+] Found 15 subdomains (via Sublist3r).

[*] Running DNS brute force...
[*] Loaded 7 candidate prefixes from 'wordlists/subdomains.txt'.
[*] Resolving with 20 concurrent workers...
DNS brute-force: 100%|##########| 7/7 [00:02<00:00, 3.41host/s]
[+] Found 4 additional hosts.

[*] Generating report...
[+] Done!

[*] Report:
reports/example.com.html
```

Open the generated file in any browser:

```bash
reports/example.com.html
```

## How it works

1. **`main.py`** validates the domain (`modules/utils.validate_domain`) and
   orchestrates the three stages below, printing colored progress messages
   throughout. Exception handling catches specific error types (network,
   I/O, encoding) for clearer diagnostics.
2. **`modules/subdomains.py`** calls `sublist3r.main()` directly as a Python
   function call (no subprocess), with its own bruteforce module disabled
   since this tool has its own dedicated brute-force stage. If Sublist3r
   can't be imported or raises an error, it falls back to a crt.sh-based
   lookup using `requests`. Returns both the results and the source label.
3. **`modules/dns_bruteforce.py`** loads `wordlists/subdomains.txt`, builds
   `<word>.<domain>` for each entry, and resolves them **concurrently**
   using `ThreadPoolExecutor` with `dnspython` (or `socket` as a fallback).
   Only resolving hosts are kept. Each result includes the DNS record type
   (A or CNAME). A `tqdm` progress bar shows real-time progress. Non-UTF-8
   wordlists are handled gracefully with an informative error message.
4. **`modules/report.py`** renders everything into a single self-contained
   HTML file with embedded CSS (dark theme, summary stat cards, and two
   results tables) and writes it to `reports/<domain>.html`. The passive
   table includes a Source column and the brute-force table includes a
   Record Type column.

## Notes on Sublist3r

Sublist3r is installed as a regular PyPI package:

```bash
pip install sublist3r
```

This exposes a `sublist3r.main(...)` function that this tool imports and
calls directly -- see `modules/subdomains.py`. Because Sublist3r queries a
number of public search engines and OSINT services over the network, results
(and runtime) will vary depending on your network environment and on those
services' current availability/rate limits. The built-in crt.sh fallback
ensures the tool still produces a result even if Sublist3r itself can't run.

## Not Included in v1 (Planned for Later)

The following are intentionally **out of scope** for this MVP and will be
added in future versions:

- Shodan integration
- theHarvester integration
- Wappalyzer / technology fingerprinting
- PDF report generation

## License

For educational and authorized security-testing purposes only.
