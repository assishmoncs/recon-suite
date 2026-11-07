"""
modules/subdomains.py

Concurrent passive subdomain enumeration with granular source attribution.

Improvements in v3:
  1. Strict boundary validation via ``is_valid_subdomain`` (fixes the bug where
     ``badexample.com`` matched ``example.com``).
  2. Safe stream suppression via ``contextlib.redirect_stdout`` / ``redirect_stderr``
     so file descriptors and global streams are never leaked on exceptions.
  3. Concurrent OSINT querying via ``ThreadPoolExecutor`` across 5 keyless
     passive feeds:
       - crt.sh (Certificate Transparency logs with exponential backoff)
       - AlienVault OTX (Open Threat Exchange passive DNS)
       - HackerTarget (Host search API)
       - URLScan.io (Public domain scan index)
       - CertSpotter (SSLMate Certificate Transparency API)
  4. Per-subdomain provenance tracking (``Dict[str, List[str]]``) so reports
     show the exact OSINT sources that discovered each individual hostname.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import io
import time
from typing import Callable, Dict, List, Tuple

import requests

from modules.utils import is_valid_subdomain, print_info, print_warning

# Safely import Sublist3r while suppressing its stderr noise via contextlib
try:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        import sublist3r  # type: ignore
    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False

_CRT_SH_TIMEOUT = 25
_CRT_SH_RETRIES = 3
_DEFAULT_API_TIMEOUT = 15
_USER_AGENT = "ReconSuite/3.0 (+https://github.com/assishmoncs/recon-suite)"


def _extract_valid_subdomains(candidates: List[str], domain: str) -> List[str]:
    """Normalize and filter raw candidate strings down to valid subdomains of ``domain``."""
    valid: set[str] = set()
    target = domain.strip().lower()
    for raw in candidates:
        for line in raw.splitlines():
            cleaned = line.strip().lower().lstrip("*.")
            if is_valid_subdomain(cleaned, target):
                valid.add(cleaned)
    return sorted(valid)


def _crtsh_lookup(domain: str) -> List[str]:
    """
    Passive subdomain lookup using crt.sh Certificate Transparency logs
    with retry logic and exponential backoff.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": _USER_AGENT}
    entries = []

    for attempt in range(1, _CRT_SH_RETRIES + 1):
        try:
            response = requests.get(url, headers=headers, timeout=_CRT_SH_TIMEOUT)
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

    raw_names: List[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            name_val = entry.get("name_value", "")
            if name_val:
                raw_names.append(str(name_val))
            common_name = entry.get("common_name", "")
            if common_name:
                raw_names.append(str(common_name))

    return _extract_valid_subdomains(raw_names, domain)


def _alienvault_otx_lookup(domain: str) -> List[str]:
    """Passive subdomain lookup via AlienVault OTX passive DNS API."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"User-Agent": _USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=_DEFAULT_API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"AlienVault OTX lookup failed: {exc}")
        return []

    raw_names = [
        str(record.get("hostname", ""))
        for record in data.get("passive_dns", [])
        if isinstance(record, dict) and record.get("hostname")
    ]
    return _extract_valid_subdomains(raw_names, domain)


def _hackertarget_lookup(domain: str) -> List[str]:
    """Passive subdomain lookup via HackerTarget free hostsearch API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    headers = {"User-Agent": _USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=_DEFAULT_API_TIMEOUT)
        response.raise_for_status()
        text = response.text.strip()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"HackerTarget lookup failed: {exc}")
        return []

    if not text or "error" in text.lower() or "api count exceeded" in text.lower():
        return []

    raw_names = [line.split(",")[0] for line in text.splitlines() if line.strip()]
    return _extract_valid_subdomains(raw_names, domain)


def _urlscan_lookup(domain: str) -> List[str]:
    """Passive subdomain lookup via URLScan.io public search API."""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    headers = {"User-Agent": _USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=_DEFAULT_API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"URLScan.io lookup failed: {exc}")
        return []

    raw_names: List[str] = []
    for result in data.get("results", []):
        if isinstance(result, dict):
            page = result.get("page", {})
            if isinstance(page, dict) and page.get("domain"):
                raw_names.append(str(page["domain"]))
            task = result.get("task", {})
            if isinstance(task, dict) and task.get("domain"):
                raw_names.append(str(task["domain"]))

    return _extract_valid_subdomains(raw_names, domain)


def _certspotter_lookup(domain: str) -> List[str]:
    """Passive subdomain lookup via CertSpotter Certificate Transparency API."""
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    headers = {"User-Agent": _USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=_DEFAULT_API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"CertSpotter lookup failed: {exc}")
        return []

    raw_names: List[str] = []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                for dns_name in entry.get("dns_names", []):
                    raw_names.append(str(dns_name))

    return _extract_valid_subdomains(raw_names, domain)


def _aggregate_passive_sources_detailed(domain: str) -> Tuple[Dict[str, List[str]], str]:
    """
    Query all passive OSINT feeds concurrently and track per-subdomain provenance.

    Returns:
        A tuple ``(source_map, summary_label)`` where ``source_map`` maps each
        discovered subdomain to a sorted list of OSINT engines that found it,
        and ``summary_label`` is a comma-separated string of contributing sources.
    """
    providers: List[Tuple[str, Callable[[str], List[str]]]] = [
        ("crt.sh", _crtsh_lookup),
        ("AlienVault OTX", _alienvault_otx_lookup),
        ("HackerTarget", _hackertarget_lookup),
        ("URLScan.io", _urlscan_lookup),
        ("CertSpotter", _certspotter_lookup),
    ]

    print_info(
        f"Querying {len(providers)} passive OSINT feeds concurrently "
        f"({', '.join(name for name, _ in providers)})..."
    )

    source_map: Dict[str, List[str]] = {}
    sources_used: List[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(providers)) as executor:
        future_to_name = {
            executor.submit(func, domain): name for name, func in providers
        }
        # Collect in provider order for deterministic source labels
        provider_results: Dict[str, List[str]] = {}
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                provider_results[name] = future.result()
            except Exception as exc:
                print_warning(f"Passive source '{name}' raised an unexpected error: {exc}")
                provider_results[name] = []

    for name, _ in providers:
        subdomains_found = provider_results.get(name, [])
        if subdomains_found:
            sources_used.append(name)
            for sub in subdomains_found:
                if sub not in source_map:
                    source_map[sub] = []
                if name not in source_map[sub]:
                    source_map[sub].append(name)

    source_label = ", ".join(sources_used) if sources_used else "N/A"
    return source_map, source_label


def _aggregate_passive_sources(domain: str) -> Tuple[List[str], str]:
    """Backward-compatible wrapper returning ``(sorted_subdomains, source_label)``."""
    source_map, source_label = _aggregate_passive_sources_detailed(domain)
    return sorted(source_map.keys()), source_label


def enumerate_subdomains_detailed(
    domain: str, threads: int = 40
) -> Tuple[List[str], str, Dict[str, List[str]]]:
    """
    Run passive subdomain enumeration and return full per-subdomain provenance.

    Always combines Sublist3r (if installed and responsive) with the concurrent
    multi-source OSINT aggregator so no single engine failure limits coverage.

    Returns:
        ``(sorted_subdomains, source_label, source_map)`` where ``source_map``
        maps each subdomain to the list of sources that discovered it.
    """
    combined_map: Dict[str, List[str]] = {}
    sources_used: List[str] = []

    if SUBLIST3R_AVAILABLE:
        print_info(
            f"Querying passive OSINT sources via Sublist3r ({threads} threads)..."
        )
        try:
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                raw_results = sublist3r.main(
                    domain,
                    threads,
                    savefile=None,
                    ports=None,
                    silent=True,
                    verbose=False,
                    enable_bruteforce=False,
                    engines=None,
                )
            valid_sublist3r = _extract_valid_subdomains(list(raw_results or []), domain)
            if valid_sublist3r:
                sources_used.append("Sublist3r")
                for sub in valid_sublist3r:
                    combined_map.setdefault(sub, []).append("Sublist3r")
            else:
                print_warning("Sublist3r returned no results.")
        except Exception as exc:
            print_warning(f"Sublist3r enumeration failed ({exc}).")
    else:
        print_warning(
            "The 'sublist3r' package is not installed; using built-in concurrent OSINT feeds."
        )

    fallback_map, _ = _aggregate_passive_sources_detailed(domain)
    for sub, sub_sources in fallback_map.items():
        existing = combined_map.setdefault(sub, [])
        for src in sub_sources:
            if src not in existing:
                existing.append(src)
            if src not in sources_used:
                sources_used.append(src)

    source_label = ", ".join(sources_used) if sources_used else "N/A"
    return sorted(combined_map.keys()), source_label, combined_map


def enumerate_subdomains(
    domain: str, threads: int = 40
) -> Tuple[List[str], str]:
    """
    Backward-compatible passive enumeration entry point.

    Returns:
        ``(subdomains, source_label)`` tuple.
    """
    subdomains_list, source_label, _ = enumerate_subdomains_detailed(
        domain, threads=threads
    )
    return subdomains_list, source_label
