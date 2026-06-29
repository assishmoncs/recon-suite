#!/usr/bin/env python3
"""
Automated Recon Tool -- v2

A clean, modular command-line reconnaissance tool that:
  1. Validates a target domain
  2. Runs passive subdomain enumeration (Sublist3r + multi-source fallback)
  3. Runs active DNS brute-force enumeration against a wordlist
  4. Generates HTML and/or PDF reports of the results

Usage:
    python main.py example.com
    python main.py example.com --wordlist wordlists/subdomains.txt --threads 40
    python main.py example.com --output-format both
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import requests

from modules import dns_bruteforce, report, subdomains
from modules.report import PDF_AVAILABLE
from modules.utils import (
    print_banner,
    print_error,
    print_info,
    print_success,
    print_warning,
    validate_domain,
)

# Resolve paths relative to *this* file so the tool works correctly
# regardless of the caller's working directory.
_PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_WORDLIST = str(_PROJECT_ROOT / "wordlists" / "subdomains.txt")
DEFAULT_REPORT_DIR = str(_PROJECT_ROOT / "reports")
DEFAULT_THREADS = 40


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Automated Recon Tool -- passive + active subdomain recon (v2).",
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
        help="Concurrent workers for DNS brute-force lookups (default: 20)",
    )
    parser.add_argument(
        "--output-format",
        choices=["html", "pdf", "both"],
        default="both",
        help="Report output format: html, pdf, or both (default: both)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the full recon workflow. Returns a process exit code."""
    args = parse_args(argv)
    domain = args.domain.strip().lower()

    # --- Input validation -------------------------------------------------
    if not validate_domain(domain):
        print_error(f"'{domain}' does not look like a valid domain name.")
        print_error("Example of a valid domain: example.com")
        return 1

    print_banner(domain)

    # --- Step 1: Passive subdomain enumeration ----------------------------
    print_info("Running passive enumeration...")
    passive_source = "Sublist3r"
    try:
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

    # --- Step 2: DNS brute force -------------------------------------------
    print_info("Running DNS brute force...")
    try:
        bruteforce_results = dns_bruteforce.brute_force(
            domain,
            wordlist_path=args.wordlist,
            max_workers=args.workers,
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

    # --- Step 3: Report generation ------------------------------------------
    print_info("Generating report...")
    output_format = args.output_format
    report_paths: list[str] = []

    # Generate HTML report
    if output_format in ("html", "both"):
        try:
            html_path = report.generate_report(
                domain=domain,
                passive_subdomains=passive_subdomains,
                bruteforce_results=bruteforce_results,
                output_dir=DEFAULT_REPORT_DIR,
                passive_source=passive_source,
            )
            report_paths.append(html_path)
        except (OSError, IOError) as exc:
            print_error(f"HTML report generation failed (I/O error): {exc}")
            return 1
        except Exception as exc:
            print_error(f"HTML report generation failed: {exc}")
            return 1

    # Generate PDF report
    if output_format in ("pdf", "both"):
        if not PDF_AVAILABLE:
            print_warning(
                "PDF generation skipped: xhtml2pdf not installed. "
                "Install with: pip install xhtml2pdf"
            )
        else:
            try:
                pdf_path = report.generate_pdf_report(
                    domain=domain,
                    passive_subdomains=passive_subdomains,
                    bruteforce_results=bruteforce_results,
                    output_dir=DEFAULT_REPORT_DIR,
                    passive_source=passive_source,
                )
                report_paths.append(pdf_path)
            except (OSError, IOError) as exc:
                print_error(f"PDF report generation failed (I/O error): {exc}")
                return 1
            except Exception as exc:
                print_error(f"PDF report generation failed: {exc}")
                return 1

    print_success("Done!\n")
    print_info("Report(s):")
    for path in report_paths:
        print(f"  {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
