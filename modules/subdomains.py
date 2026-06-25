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

from typing import List

import requests

from modules.utils import print_info, print_warning

# Sublist3r is distributed on PyPI as the `sublist3r` package
# (see requirements.txt). It exposes a module-level `main()` function:
#
#   import sublist3r
#   subdomains = sublist3r.main(
#       domain, threads, savefile, ports, silent, verbose,
#       enable_bruteforce, engines,
#   )
#
# We import it once at module load time and remember whether it succeeded,
# so callers don't have to worry about the ImportError themselves.
try:
    import sublist3r  # type: ignore

    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False


def _crtsh_fallback(domain: str) -> List[str]:
    """
    Lightweight passive subdomain lookup using crt.sh Certificate
    Transparency logs.

    This is only used when the Sublist3r library is unavailable, or when
    calling it raised an exception. It uses the `requests` library
    directly -- no shell commands are executed here either.

    Args:
        domain: The target domain, e.g. "example.com".

    Returns:
        A sorted list of unique subdomains found in CT logs (may be empty).
    """
    found: set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        entries = response.json()
    except (requests.RequestException, ValueError) as exc:
        print_warning(f"crt.sh fallback lookup failed: {exc}")
        return []

    for entry in entries:
        name_value = entry.get("name_value", "")
        # A single certificate entry can list multiple hostnames,
        # separated by newlines (e.g. SANs on a multi-domain cert).
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain):
                found.add(name)

    return sorted(found)


def enumerate_subdomains(domain: str, threads: int = 40) -> List[str]:
    """
    Run passive subdomain enumeration for `domain`.

    Args:
        domain: The target domain, e.g. "example.com".
        threads: Number of worker threads Sublist3r should use internally.

    Returns:
        A sorted list of unique, discovered subdomains. Returns an empty
        list (rather than raising) if no sources could be reached -- the
        caller is responsible for deciding how to report that.
    """
    if SUBLIST3R_AVAILABLE:
        print_info(
            f"Querying passive OSINT sources via Sublist3r ({threads} threads, "
            "this can take 10-60s)..."
        )
        try:
            results = sublist3r.main(
                domain,
                threads,
                savefile=None,
                ports=None,
                silent=True,  # we handle our own progress/output formatting
                verbose=False,
                enable_bruteforce=False,  # our own dns_bruteforce module covers this
                engines=None,  # use Sublist3r's full default engine list
            )
            return sorted(set(results))
        except Exception as exc:  # Sublist3r can raise many different network errors
            print_warning(f"Sublist3r enumeration failed ({exc}).")
            print_info("Falling back to crt.sh passive lookup...")
            return _crtsh_fallback(domain)
    else:
        print_warning(
            "The 'sublist3r' package is not installed (pip install sublist3r)."
        )
        print_info("Falling back to crt.sh passive lookup...")
        return _crtsh_fallback(domain)
