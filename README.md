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
  Transparency logs so you still get a result.
- **DNS brute force** -- reads candidate prefixes from `wordlists/subdomains.txt`,
  builds `<word>.<domain>` candidates, and resolves them with `dnspython`
  (falling back to the standard library `socket` module if dnspython isn't
  available). Only hosts that actually resolve are kept; duplicates are
  removed automatically.
- **HTML report** -- generates a clean, styled `reports/<domain>.html`
  report (CSS only, no JavaScript) summarizing everything that was found.
- **Colored terminal output** -- via `colorama`, with clear progress
  messages at each stage.

## Project Structure

```
Automated-Recon-Tool/
│
├── main.py                  # CLI entry point / orchestration
├── requirements.txt
├── README.md
├── reports/                 # Generated HTML reports land here
├── wordlists/
│   └── subdomains.txt       # DNS brute-force wordlist
└── modules/
    ├── __init__.py
    ├── subdomains.py        # Passive enumeration (Sublist3r + crt.sh fallback)
    ├── dns_bruteforce.py    # Active DNS brute force
    ├── report.py            # HTML report generation
    └── utils.py             # Domain validation + colored output helpers
```

## Installation

Requires **Python 3.11+**.

```bash
git clone <this-repo>
cd Automated-Recon-Tool
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
python main.py example.com --wordlist wordlists/subdomains.txt --threads 40
```

| Flag          | Description                                         | Default                      |
|---------------|------------------------------------------------------|-------------------------------|
| `domain`      | Target domain (positional, required)                 | --                            |
| `--wordlist`  | Path to the DNS brute-force wordlist                  | `wordlists/subdomains.txt`    |
| `--threads`   | Threads used internally by Sublist3r                  | `40`                          |

### Example output

```
Target: example.com

Running passive enumeration...
Found 15 subdomains.

Running DNS brute force...
Found 4 additional hosts.

Generating report...

Done!

Report:
reports/example.com.html
```

Open the generated file in any browser:

```bash
reports/example.com.html
```

## How it works

1. **`main.py`** validates the domain (`modules/utils.validate_domain`) and
   orchestrates the three stages below, printing colored progress messages
   throughout.
2. **`modules/subdomains.py`** calls `sublist3r.main()` directly as a Python
   function call (no subprocess), with its own bruteforce module disabled
   since this tool has its own dedicated brute-force stage. If Sublist3r
   can't be imported or raises an error, it falls back to a crt.sh-based
   lookup using `requests`.
3. **`modules/dns_bruteforce.py`** loads `wordlists/subdomains.txt`, builds
   `<word>.<domain>` for each entry, and resolves it with `dnspython` (or
   `socket` as a fallback). Only resolving hosts are kept, and a dict keyed
   by hostname removes duplicates automatically.
4. **`modules/report.py`** renders everything into a single self-contained
   HTML file with embedded CSS (dark theme, summary stat cards, and two
   results tables) and writes it to `reports/<domain>.html`.

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
