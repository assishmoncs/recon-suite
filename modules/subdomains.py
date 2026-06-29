"""
modules/subdomains.py

Passive subdomain enumeration.

This module enumerates subdomains *passively* (no DNS brute forcing) by
calling the Sublist3r library directly in-process -- i.e. `import sublist3r`
and call its `main()` function, rather than shelling out to
`sublist3r.py` as a subprocess.

Sublist3r aggregates results from search engines and OSINT sources
(Google, Bing, Baidu, Yahoo, Netcraft, VirusTotal, ThreatCrowd, crt.sh,
DNSdumpster, etc.) and returns a de-duplicated list of subdomains.

If the `sublist3r` package is not installed, or the call to it fails for
any reason (network restrictions, upstream API changes, etc.), this module
falls back to a small, dependency-light passive lookup against the
crt.sh Certificate Transparency log search engine so the tool still
produces a usable result instead of crashing.
"""

from __future__ import annotations

import io
import os
import sys
import time
from typing import List, Tuple

import requests

from modules.utils import print_info, print_warning

# Sublist3r is distributed on PyPI as the `sublist3r` package.
# Its import prints a noisy "coloring libraries not installed" warning
# to stderr when colorama isn't set up its way. We suppress that.
try:
    _devnull = open(os.devnull, "w")
    _old_stderr = sys.stderr
    sys.stderr = _devnull
    import sublist3r  # type: ignore
    sys.stderr = _old_stderr
    _devnull.close()
    SUBLIST3R_AVAILABLE = True
except ImportError:
    sys.stderr = _old_stderr if "_old_stderr" in dir() else sys.stderr
    SUBLIST3R_AVAILABLE = False

# Additional passive sources for resilience
_CRT_SH_TIMEOUT = 30  # seconds (increased from 15)
_CRT_SH_RETRIES = 3
_ALIENVAULT_TIMEOUT = 20
_HACKERTARGET_TIMEOUT = 20


def _crtsh_lookup(domain: str) -> List[str]:
    """
    Passive subdomain lookup using crt.sh Certificate Transparency logs
    with retry logic and exponential backoff.

    Args:
        domain: The target domain, e.g. "example.com".

    Returns:
        A sorted list of unique subdomains found in CT logs (may be empty).
    """
    found: set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    for attempt in range(1, _CRT_SH_RETRIES + 1):
        try:
            response = requests.get(url, timeout=_CRT_SH_TIMEOUT)
            response.raise_for_status()
            entries = response.json()
            break
        except (requests.RequestException, ValueError) as exc:
            if attempt < _CRT_SH_RETRIES:
                wait = 2 ** attempt
                print_warning(
                    f"crt.sh attempt {attempt}/{_CRT_SH_RETRIES} failed: {exc}. "
                    f"Retrying in {wait}s..."
                )
                time.sleep(wait)
            else:
                print_warning(f"crt.sh lookup failed after {_CRT_SH_RETRIES} attempts: {exc}")
                return []
    else:
        return []

    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain):
                found.add(name)

    return sorted(found)


def _alienvault_otx_lookup(domain: str) -> List[str]:
    """
    Passive subdomain lookup via AlienVault OTX (Open Threat Exchange).
    No API key required for basic queries.
    """
    found: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    try:
        response = requests.get(url, timeout=_ALIENVAULT_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"AlienVault OTX lookup failed: {exc}")
        return []

    for record in data.get("passive_dns", []):
        hostname = record.get("hostname", "").strip().lower()
        if hostname and hostname.endswith(domain):
            found.add(hostname)

    return sorted(found)


def _hackertarget_lookup(domain: str) -> List[str]:
    """
    Passive subdomain lookup via HackerTarget free API.
    Returns subdomains from their host search.
    """
    found: set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        response = requests.get(url, timeout=_HACKERTARGET_TIMEOUT)
        response.raise_for_status()
        text = response.text.strip()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"HackerTarget lookup failed: {exc}")
        return []

    if not text or "error" in text.lower():
        return []

    for line in text.splitlines():
        parts = line.split(",")
        if parts:
            hostname = parts[0].strip().lower()
            if hostname and hostname.endswith(domain):
                found.add(hostname)

    return sorted(found)


def _aggregate_passive_sources(domain: str) -> Tuple[List[str], str]:
    """
    Query multiple passive OSINT sources and combine results.

    Sources: crt.sh, AlienVault OTX, HackerTarget.
    Returns combined deduplicated results and a label of sources used.
    """
    all_found: set[str] = set()
    sources_used: List[str] = []

    print_info("Querying crt.sh Certificate Transparency logs...")
    crtsh_results = _crtsh_lookup(domain)
    if crtsh_results:
        all_found.update(crtsh_results)
        sources_used.append("crt.sh")

    print_info("Querying AlienVault OTX...")
    otx_results = _alienvault_otx_lookup(domain)
    if otx_results:
        all_found.update(otx_results)
        sources_used.append("AlienVault OTX")

    print_info("Querying HackerTarget...")
    ht_results = _hackertarget_lookup(domain)
    if ht_results:
        all_found.update(ht_results)
        sources_used.append("HackerTarget")

    source_label = ", ".join(sources_used) if sources_used else "N/A"
    return sorted(all_found), source_label


def enumerate_subdomains(
    domain: str, threads: int = 40
) -> Tuple[List[str], str]:
    """
    Run passive subdomain enumeration for ``domain``.

    Tries Sublist3r first; if it fails or returns nothing, aggregates
    results from multiple fallback passive sources (crt.sh, AlienVault
    OTX, HackerTarget) with retry logic for resilience.

    Args:
        domain: The target domain, e.g. ``"example.com"``.
        threads: Number of worker threads Sublist3r should use internally.

    Returns:
        A ``(subdomains, source)`` tuple where *subdomains* is a sorted
        list of unique discovered subdomains and *source* is a label
        describing which engine(s) produced the results.
    """
    if SUBLIST3R_AVAILABLE:
        print_info(
            f"Querying passive OSINT sources via Sublist3r ({threads} threads, "
            "this can take 10-60s)..."
        )
        try:
            # Suppress Sublist3r's noisy stdout/stderr during execution
            _captured = io.StringIO()
            _old_stdout = sys.stdout
            _old_stderr_run = sys.stderr
            sys.stdout = _captured
            sys.stderr = _captured
            results = sublist3r.main(
                domain,
                threads,
                savefile=None,
                ports=None,
                silent=True,
                verbose=False,
                enable_bruteforce=False,
                engines=None,
            )
            sys.stdout = _old_stdout
            sys.stderr = _old_stderr_run

            if results:
                return sorted(set(results)), "Sublist3r"
            else:
                print_warning("Sublist3r returned no results.")
                print_info("Falling back to multi-source passive lookup...")
                return _aggregate_passive_sources(domain)
        except Exception as exc:
            sys.stdout = _old_stdout
            sys.stderr = _old_stderr_run
            print_warning(f"Sublist3r enumeration failed ({exc}).")
            print_info("Falling back to multi-source passive lookup...")
            return _aggregate_passive_sources(domain)
    else:
        print_warning(
            "The 'sublist3r' package is not installed (pip install sublist3r)."
        )
        print_info("Running multi-source passive lookup...")
        return _aggregate_passive_sources(domain)
