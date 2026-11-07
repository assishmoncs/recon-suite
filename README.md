# Automated Recon Suite

An enterprise-grade, concurrent command-line tool for External Attack Surface Management (EASM), passive OSINT subdomain enumeration, active DNS brute-forcing, and defensive DNS hygiene auditing.

> **Legal Disclaimer**: This tool is designed strictly for authorized security assessments, defensive asset discovery, and vulnerability management. Only audit domains you own or have explicit, documented authorization to test.

---

## Overview

The Automated Recon Suite provides security teams and penetration testers with a unified platform to map organization attack surfaces. It combines multi-source passive OSINT reconnaissance with concurrent active DNS resolution, wildcard catch-all filtering, dangling CNAME takeover auditing, HTTP/TLS posture probing, and multi-format reporting.

---

## Core Capabilities

- **Multi-Feed Passive OSINT Aggregation**: Queries five independent passive intelligence sources concurrently (`crt.sh`, `AlienVault OTX`, `HackerTarget`, `URLScan.io`, and `CertSpotter`), with optional integration for `Sublist3r`.
- **Per-Subdomain Provenance Attribution**: Retains source metadata per discovered host, detailing exactly which OSINT feeds identified each asset.
- **Strict Domain Boundary Validation**: Enforces RFC-compliant subdomain boundary validation to eliminate false positives and lookalike suffix matches.
- **Active Wildcard DNS Detection**: Baselines target domains using randomized UUID probes to identify and filter catch-all `*.domain` records before brute-forcing begins.
- **Comprehensive DNS Resolution**: Resolves discovered hosts across IPv4 (`A`), IPv6 (`AAAA`), and canonical names (`CNAME`) using configurable upstream nameservers.
- **Dangling CNAME Hygiene Auditing**: Cross-references unresolved CNAME targets against signatures across 23 cloud and hosting providers (including AWS S3, GitHub Pages, Heroku, Azure, Fastly, and Cloudflare) to flag potential subdomain takeover risks.
- **Root Domain Posture Assessment**: Inspects root-domain DNS configurations, auditing `NS`, `MX`, `SPF` (`v=spf1`), `DMARC` (`_dmarc`), and `CAA` records.
- **HTTP and TLS Security Probing**: Validates web surface reachability, capturing HTTP status codes, TLS certificate expiration timelines, and key defensive response headers (`HSTS`, `CSP`, `X-Frame-Options`).
- **Subnet Infrastructure Clustering**: Aggregates resolved hosts into IPv4 `/24` and IPv6 `/64` CIDR blocks to reveal shared hosting and network concentration.
- **Attack-Surface Snapshot Diffing**: Compares current audit results against previous JSON reports to identify newly introduced, unchanged, or decommissioned subdomains.
- **Multi-Format Enterprise Reporting**: Exports results to Interactive HTML, Print-Friendly A4 PDF, JSON, and CSV.

---

## Architecture and Project Structure

```text
recon-suite/
├── main.py                        # Primary CLI pipeline orchestrator
├── pyproject.toml                 # Package definition and console script entry point
├── requirements.txt               # Pinned runtime dependencies
├── README.md                      # Technical documentation
├── LICENSE                        # MIT License
├── .github/workflows/ci.yml       # Continuous integration workflow
├── modules/
│   ├── __init__.py                # Package version declaration (v3.0.0)
│   ├── subdomains.py              # Concurrent passive OSINT aggregation and provenance mapping
│   ├── dns_bruteforce.py          # Wildcard detection, active brute-force, and DNS posture checks
│   ├── http_probe.py              # Concurrent HTTPS/HTTP endpoint and TLS certificate audit
│   ├── report.py                  # HTML, PDF, JSON, and CSV generators and snapshot comparison
│   └── utils.py                   # RFC domain validation and terminal output formatters
├── wordlists/
│   └── subdomains.txt             # Curated 394-entry high-signal infrastructure wordlist
├── tests/
│   └── test_recon_suite.py        # Offline unit and end-to-end integration test suite
├── examples/                      # Reference report artifacts (HTML, PDF, JSON, CSV)
└── reports/                       # Default directory for generated audit artifacts
```

---

## Prerequisites and Installation

### Requirements

- **Python**: Version 3.11 or higher
- Operating Systems: Linux, macOS, or Windows

### Setup via Virtual Environment

```bash
# Clone the repository
git clone https://github.com/assishmoncs/recon-suite.git
cd recon-suite

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate       # On Windows: .\venv\Scripts\activate

# Install runtime dependencies
pip install -r requirements.txt
```

### Optional: Editable Package Installation

To install the executable directly into your PATH as the `recon-suite` command:

```bash
pip install -e .
recon-suite --help
```

---

## Usage and Command-Line Interface

### Common Examples

**Standard Scan (HTML and PDF Output)**:
```bash
python main.py example.com
```

**Full Audit with HTTP/TLS Probing and All Output Formats**:
```bash
python main.py example.com --output-format all --probe-http
```

**Custom Nameservers and Concurrency**:
```bash
python main.py example.com --nameservers 1.1.1.1,8.8.8.8 --workers 30
```

**Custom Wordlist**:
```bash
python main.py example.com --wordlist /path/to/custom_wordlist.txt
```

**Attack-Surface Delta Comparison against Baseline**:
```bash
python main.py example.com --output-format all --diff reports/example.com_baseline.json
```

**Timestamped Report Filenames**:
```bash
python main.py example.com --output-dir reports/audits --timestamp
```

---

## Command-Line Options Reference

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `domain` | Positional | Required | Target root domain to audit (e.g., `example.com`). |
| `--wordlist` | Option | `wordlists/subdomains.txt` | Path to newline-delimited subdomain wordlist for active brute-forcing. |
| `--threads` | Option | `40` | Worker threads allocated for passive search scrapers. |
| `--workers` | Option | `20` | Concurrent worker threads for DNS resolution and HTTP/TLS probing. |
| `--output-format` | Option | `both` | Output format: `html`, `pdf`, `json`, `csv`, `both` (HTML + PDF), or `all`. |
| `--output-dir` | Option | `reports` | Target filesystem directory for generated report artifacts. |
| `--nameservers` | Option | System Resolver | Comma-delimited list of DNS resolver IP addresses (e.g., `1.1.1.1,8.8.8.8`). |
| `--probe-http` | Flag | `False` | Probe resolved hosts over HTTPS/HTTP for status codes, TLS validity, and security headers. |
| `--diff` | Option | `None` | Path to a previous `.json` report to compute added, removed, and unchanged hosts. |
| `--timestamp` | Flag | `False` | Append UTC timestamp (`YYYYMMDD_HHMMSS`) to report filenames to preserve historical runs. |

---

## Output Formats and Deliverables

Generated reports are written to the directory specified by `--output-dir` (default: `reports/`):

1. **Interactive HTML (`<domain>.html`)**:
   - Modern, self-contained dashboard with real-time text search.
   - Filter pills for live resolved hosts, CNAME records, multi-source discoveries, and hygiene warnings.
   - Sortable columns, root-domain DNS posture cards, and IP `/24` subnet clustering tables.
2. **Executive PDF (`<domain>.pdf`)**:
   - Clean, print-ready document formatted for A4 pages.
   - Powered by a multi-engine fallback pipeline (`xhtml2pdf` -> `reportlab` -> `weasyprint`).
3. **Machine-Readable JSON (`<domain>.json`)**:
   - Fully structured schema containing asset metadata, source provenance, DNS posture details, HTTP probing data, and diff metrics.
   - Suitable for ingest into SIEM, SOAR, or asset management systems.
4. **Tabular CSV (`<domain>.csv`)**:
   - Flat tabular inventory compatible with spreadsheet applications, data pipelines, and reporting tools.

---

## Default Wordlist Strategy

The suite bundles a curated list of 394 high-signal subdomains in `wordlists/subdomains.txt`. This list is partitioned into 14 functional categories:

- Core Infrastructure, Cloud & Nameservers
- Mail, Exchange & Messaging
- APIs, Microservices & Integration
- Environments, Staging & Quality Assurance
- DevOps, CI/CD & Orchestration
- Authentication, Identity & Access Management
- Remote Access, Networking & Security
- Administration & Control Panels
- Databases, Caches & Data Platforms
- Monitoring, Observability & Health
- Storage, Static Assets & Content Delivery
- Customer Support & Enterprise SaaS
- E-Commerce & Billing
- Mobile, IoT, AI & Partner Portals

This curated size enables scans to complete in under five seconds with default concurrency settings while avoiding DNS rate-limiting. For exhaustive brute-force audits, larger external wordlists (such as SecLists) can be passed using the `--wordlist` option.

---

## Testing and Verification

The test suite runs completely offline using deterministic mocks for all external network, HTTP, and DNS calls.

```bash
# Execute the complete test suite
python3 -m unittest discover -s tests -v
```

The test suite validates:
- Domain and boundary validation logic
- Passive OSINT multi-source aggregation and per-host provenance attribution
- Wildcard DNS detection and false-positive filtering
- Dangling cloud CNAME hygiene auditing
- Snapshot diff computation
- End-to-end report generation across HTML, PDF, JSON, and CSV

---

## License

This project is licensed under the [MIT License](LICENSE).
