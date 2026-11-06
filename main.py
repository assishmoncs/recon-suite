#!/usr/bin/env python3
"""
Automated Recon Suite -- v3.0

A modular command-line external attack-surface discovery and DNS hygiene tool:
  1. Validates target domain and optional custom DNS nameservers
  2. Runs concurrent passive subdomain enumeration across 5+ OSINT feeds with
     per-subdomain provenance tracking
  3. Detects wildcard DNS records and runs concurrent active DNS brute-forcing
  4. Enriches all discovered subdomains with IPv4/IPv6/CNAME resolution,
     dangling CNAME hygiene checks, and root-domain DNS posture auditing
  5. Optionally probes HTTP/HTTPS and TLS certificate health (--probe-http)
  6. Generates interactive HTML, PDF, JSON, and CSV reports (plus --diff comparison)

Usage:
    python main.py example.com
    python main.py example.com --output-format all --probe-http
    python main.py example.com --nameservers 1.1.1.1,8.8.8.8 --diff reports/prev.json
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

import requests

from modules import dns_bruteforce, http_probe, report, subdomains
from modules.report import PDF_AVAILABLE
from modules.utils import (
    parse_nameservers,
    print_banner,
    print_error,
    print_info,
    print_success,
    print_warning,
    validate_domain,
)

_PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_WORDLIST = str(_PROJECT_ROOT / "wordlists" / "subdomains.txt")
DEFAULT_REPORT_DIR = str(_PROJECT_ROOT / "reports")
DEFAULT_THREADS = 40


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="recon-suite",
        description="Automated Recon Suite (v3.0) -- EASM, OSINT & DNS Hygiene Auditor.",
    )
    parser.add_argument(
        "domain",
        help="Target domain to scan, e.g. example.com",
    )
    parser.add_argument(
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help=f"Path to the DNS brute-force wordlist (default: {DEFAULT_WORDLIST})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Threads for passive enumeration (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent workers for DNS and HTTP lookups (default: 20)",
    )
    parser.add_argument(
        "--output-format",
        choices=["html", "pdf", "json", "csv", "both", "all"],
        default="both",
        help="Report output format: html, pdf, json, csv, both (html+pdf), or all (default: both)",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_REPORT_DIR,
        help=f"Directory to write generated reports into (default: {DEFAULT_REPORT_DIR})",
    )
    parser.add_argument(
        "--nameservers",
        default=None,
        help="Comma-separated custom DNS nameserver IPs, e.g. 1.1.1.1,8.8.8.8",
    )
    parser.add_argument(
        "--probe-http",
        action="store_true",
        help="Probe resolved hosts over HTTPS/HTTP for status codes, TLS expiry, and security headers",
    )
    parser.add_argument(
        "--diff",
        default=None,
        metavar="PREV_JSON",
        help="Path to a previous JSON report to compute added/removed subdomain delta",
    )
    parser.add_argument(
        "--timestamp",
        action="store_true",
        help="Append a UTC timestamp to generated report filenames to prevent overwriting",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the full recon workflow. Returns a process exit code."""
    args = parse_args(argv)
    domain = args.domain.strip().lower()

    if not validate_domain(domain):
        print_error(f"'{domain}' does not look like a valid domain name.")
        print_error("Example of a valid domain: example.com")
        return 1

    try:
        nameservers = parse_nameservers(args.nameservers)
    except ValueError as exc:
        print_error(str(exc))
        return 1

    print_banner(domain)

    # --- Step 1: Passive subdomain enumeration ----------------------------
    print_info("Running passive enumeration...")
    passive_source = "Sublist3r"
    passive_source_map: dict[str, list[str]] = {}
    try:
        if hasattr(subdomains, "enumerate_subdomains_detailed"):
            passive_subdomains, passive_source, passive_source_map = (
                subdomains.enumerate_subdomains_detailed(domain, threads=args.threads)
            )
        else:
            passive_subdomains, passive_source = subdomains.enumerate_subdomains(
                domain, threads=args.threads
            )
    except requests.RequestException as exc:
        print_error(f"Passive enumeration failed (network error): {exc}")
        passive_subdomains = []
        passive_source = "N/A"
    except (OSError, IOError) as exc:
        print_error(f"Passive enumeration failed (I/O error): {exc}")
        passive_subdomains = []
        passive_source = "N/A"
    except Exception as exc:
        print_error(f"Passive enumeration failed unexpectedly: {exc}")
        passive_subdomains = []
        passive_source = "N/A"
    print_success(f"Found {len(passive_subdomains)} subdomains (via {passive_source}).\n")

    # --- Step 2: Active DNS brute force (with wildcard filtering) ---------
    print_info("Running DNS brute force...")
    try:
        bruteforce_results = dns_bruteforce.brute_force(
            domain,
            wordlist_path=args.wordlist,
            max_workers=args.workers,
            nameservers=nameservers,
        )
    except UnicodeDecodeError as exc:
        print_error(f"DNS brute force failed (wordlist encoding error): {exc}")
        bruteforce_results = []
    except (OSError, IOError) as exc:
        print_error(f"DNS brute force failed (I/O error): {exc}")
        bruteforce_results = []
    except Exception as exc:
        print_error(f"DNS brute force failed unexpectedly: {exc}")
        bruteforce_results = []

    bruteforce_hosts = {entry["hostname"] for entry in bruteforce_results}
    newly_found_hosts = bruteforce_hosts - set(passive_subdomains)
    print_success(f"Found {len(newly_found_hosts)} additional hosts.\n")

    # --- Step 3: Unified DNS enrichment & root domain posture audit -------
    enriched_records = dns_bruteforce.enrich_subdomains(
        domain=domain,
        passive_subdomains=passive_subdomains,
        bruteforce_results=bruteforce_results,
        passive_source_map=passive_source_map,
        default_passive_source=passive_source,
        max_workers=args.workers,
        nameservers=nameservers,
    )
    dns_posture = dns_bruteforce.audit_domain_dns(domain, nameservers=nameservers)

    dangling_alerts = [r for r in enriched_records if r.get("hygiene_warning")]
    if dangling_alerts:
        print_warning(
            f"Detected {len(dangling_alerts)} potential dangling CNAME record(s) "
            "requiring defensive review!"
        )

    # --- Step 4: Optional HTTP / TLS health probing -----------------------
    if args.probe_http and enriched_records:
        enriched_records = http_probe.probe_hosts(
            enriched_records, max_workers=args.workers
        )

    # --- Step 5: Optional snapshot diffing --------------------------------
    diff_summary = None
    if args.diff:
        try:
            all_unique = [r["hostname"] for r in enriched_records]
            diff_summary = report.compute_diff(all_unique, args.diff)
            print_info(
                f"Snapshot diff vs '{args.diff}': "
                f"+{len(diff_summary['added'])} added, "
                f"-{len(diff_summary['removed'])} removed, "
                f"={len(diff_summary['unchanged'])} unchanged."
            )
        except Exception as exc:
            print_warning(f"Could not compute snapshot diff from '{args.diff}': {exc}")

    # --- Step 6: Report generation ----------------------------------------
    print_info("Generating report(s)...")
    output_format = args.output_format
    output_dir = args.output_dir
    filename_prefix = (
        f"{domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        if args.timestamp
        else domain
    )
    report_paths: list[str] = []

    want_html = output_format in ("html", "both", "all")
    want_pdf = output_format in ("pdf", "both", "all")
    want_json = output_format in ("json", "all")
    want_csv = output_format in ("csv", "all")

    if want_html:
        try:
            html_path = report.generate_report(
                domain=domain,
                passive_subdomains=passive_subdomains,
                bruteforce_results=bruteforce_results,
                output_dir=output_dir,
                passive_source=passive_source,
                passive_source_map=passive_source_map,
                enriched_records=enriched_records,
                dns_posture=dns_posture,
                diff_summary=diff_summary,
                filename_prefix=filename_prefix,
            )
            report_paths.append(html_path)
        except Exception as exc:
            print_error(f"HTML report generation failed: {exc}")
            return 1

    if want_pdf:
        if not PDF_AVAILABLE:
            print_warning(
                "PDF generation skipped: no PDF library installed (install xhtml2pdf, weasyprint, or reportlab)."
            )
        else:
            try:
                pdf_path = report.generate_pdf_report(
                    domain=domain,
                    passive_subdomains=passive_subdomains,
                    bruteforce_results=bruteforce_results,
                    output_dir=output_dir,
                    passive_source=passive_source,
                    passive_source_map=passive_source_map,
                    filename_prefix=filename_prefix,
                )
                report_paths.append(pdf_path)
            except Exception as exc:
                print_error(f"PDF report generation failed: {exc}")
                return 1

    if want_json:
        try:
            json_path = report.generate_json_report(
                domain=domain,
                passive_subdomains=passive_subdomains,
                bruteforce_results=bruteforce_results,
                output_dir=output_dir,
                passive_source=passive_source,
                passive_source_map=passive_source_map,
                enriched_records=enriched_records,
                dns_posture=dns_posture,
                diff_summary=diff_summary,
                filename_prefix=filename_prefix,
            )
            report_paths.append(json_path)
        except Exception as exc:
            print_error(f"JSON report generation failed: {exc}")
            return 1

    if want_csv:
        try:
            csv_path = report.generate_csv_report(
                domain=domain,
                passive_subdomains=passive_subdomains,
                bruteforce_results=bruteforce_results,
                output_dir=output_dir,
                passive_source=passive_source,
                passive_source_map=passive_source_map,
                enriched_records=enriched_records,
                filename_prefix=filename_prefix,
            )
            report_paths.append(csv_path)
        except Exception as exc:
            print_error(f"CSV report generation failed: {exc}")
            return 1

    print_success("Done!\n")
    print_info("Report(s):")
    for path in report_paths:
        print(f"  {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
