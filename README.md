# Automated Recon Suite (v3.0)

A modular, concurrent Python 3 External Attack-Surface Management (EASM), passive OSINT subdomain discovery, and defensive DNS hygiene auditing suite.

> **Ethical & Authorized Use Only.** Only scan domains you own or have explicit written authorization to audit.

## What's New in v3.0 (Hackathon Panel Upgrade)

| Panel Finding in v2 | v3.0 Engineering Upgrade |
| :--- | :--- |
| **Suffix Boundary Bug** (`badexample.com` matched `example.com`) | Fixed via `modules.utils.is_valid_subdomain()`, enforcing strict `candidate == domain or candidate.endswith("." + domain)` boundary checks across all feeds. |
| **No Wildcard DNS Detection** (100% false positives on `*.domain`) | Added `detect_wildcard_dns()` using 3 random UUID probes (`recon-wildcard-<uuid>.<domain>`) to baseline and filter out catch-all wildcard IPs and CNAMEs automatically. |
| **Lumped Passive Source Labels** (`crt.sh, AlienVault OTX...` stamped on every row) | Implemented per-subdomain provenance maps (`Dict[str, List[str]]`) so every discovered hostname displays the exact OSINT feed badges that found it. |
| **Sequential Passive Lookups** (`crt.sh` timeouts blocked all other feeds) | Upgraded `_aggregate_passive_sources_detailed()` to query all 5 OSINT APIs concurrently via `ThreadPoolExecutor` (`crt.sh`, `AlienVault OTX`, `HackerTarget`, `URLScan.io`, and `CertSpotter`). |
| **Unresolved Passive Subdomains & IPv4-Only Lookups** | Added `enrich_subdomains()` to resolve both passive and brute-forced subdomains across `A` (IPv4), `AAAA` (IPv6), and `CNAME` records using configurable `--nameservers`. |
| **No Security Hygiene or Dangling DNS Checks** | Added `check_dangling_cname()` (auditing unresolved CNAMEs against 23 cloud provider signatures), `audit_domain_dns()` (`NS`, `MX`, `SPF`, `DMARC`, `CAA`), and `--probe-http` (HTTP status, TLS expiry days, and `HSTS`/`CSP`/`XFO` headers). |
| **Static Reports & Missing Machine Exports** | Upgraded HTML report with live search, category filter pills, click-to-sort columns, and IP `/24` subnet clustering; added multi-engine PDF (`xhtml2pdf` / `reportlab` / `weasyprint`), JSON, CSV, and `--diff` snapshot comparison. |
| **Unsafe Stream Redirection & Missing Tests/Packaging** | Replaced bare `sys.stdout` mutation with `contextlib.redirect_stdout`/`redirect_stderr`, removed `.agents/`, added `pyproject.toml`, GitHub Actions CI, and a 22-test offline `unittest` suite. |

## Project Structure

```text
recon-suite/
├── main.py                        # CLI entry point & pipeline orchestrator
├── pyproject.toml                 # PEP 621 package metadata & `recon-suite` script entry point
├── requirements.txt               # Pinned runtime dependencies
├── README.md                      # Documentation
├── LICENSE                        # MIT License
├── .github/workflows/ci.yml       # GitHub Actions CI across Python 3.11 & 3.12
├── modules/
│   ├── __init__.py                # Package version (3.0.0)
│   ├── subdomains.py              # Concurrent 5-source passive OSINT + provenance tracking
│   ├── dns_bruteforce.py          # Wildcard detection, A/AAAA/CNAME brute-force & DNS posture audit
│   ├── http_probe.py              # Optional concurrent HTTPS/HTTP & TLS certificate health probe
│   ├── report.py                  # Interactive HTML, multi-engine PDF, JSON, CSV & snapshot diffing
│   └── utils.py                   # RFC domain/subdomain boundary validation & colored CLI output
├── wordlists/
│   └── subdomains.txt             # Curated 165-prefix infrastructure & cloud wordlist
├── tests/
│   └── test_recon_suite.py        # 22 offline unit & end-to-end integration tests
├── examples/                      # Pre-generated sample outputs (HTML, PDF, JSON, CSV)
└── reports/                       # Default output directory for generated reports
```

## Installation

Requires **Python 3.11+**.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Or install as a CLI package in editable mode:

```bash
pip install -e .
recon-suite example.com --output-format all
```

## Usage & CLI Flags

```bash
# Default scan (generates HTML + PDF reports in reports/)
python main.py example.com

# Full EASM & hygiene audit (HTML, PDF, JSON, CSV + HTTP/TLS probing + custom DNS)
python main.py example.com --output-format all --probe-http --nameservers 1.1.1.1,8.8.8.8

# Compare current attack surface against a previous JSON baseline
python main.py example.com --output-format all --diff reports/example.com_baseline.json
```

| Flag | Description | Default |
| :--- | :--- | :--- |
| `domain` | Target root domain to audit (positional, required) | — |
| `--wordlist` | Path to newline-delimited subdomain wordlist | `wordlists/subdomains.txt` |
| `--threads` | Worker threads for Sublist3r engine | `40` |
| `--workers` | Concurrent workers for DNS resolution and HTTP probing | `20` |
| `--output-format` | `html`, `pdf`, `json`, `csv`, `both` (html+pdf), or `all` | `both` |
| `--output-dir` | Destination directory for generated report files | `reports` |
| `--nameservers` | Comma-separated custom DNS resolver IPs (e.g. `1.1.1.1,8.8.8.8`) | System default |
| `--probe-http` | Probe resolved hosts over HTTPS/HTTP for status codes, TLS expiry & security headers | `False` |
| `--diff` | Path to a previous `.json` report to compute added/removed subdomain delta | `None` |
| `--timestamp` | Append UTC timestamp (`YYYYMMDD_HHMMSS`) to report filenames | `False` |

## Running the Test Suite

The test suite uses deterministic mocks for all external HTTP and DNS calls, running in under 2 seconds with zero network dependencies:

```bash
python3 -m unittest discover -s tests -v
```
