"""
modules/dns_bruteforce.py

Active DNS brute-force enumeration.

Reads candidate subdomain prefixes from a wordlist file (one per line,
e.g. "api", "mail", "dev" ...), builds a candidate hostname for each
(`<word>.<domain>`), and checks whether it resolves to an IP address.

Resolution is done with `dnspython` if it is installed (preferred, since
it supports timeouts and more record types), falling back to Python's
built-in `socket` module otherwise. Only hostnames that actually resolve
are kept, and results are automatically de-duplicated.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Dict, List, Optional

from modules.utils import print_info, print_warning

try:
    import dns.resolver  # type: ignore

    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

# Sensible default wordlist used if the requested wordlist file is
# missing for some reason -- keeps the tool usable out of the box.
_DEFAULT_WORDS = ["api", "mail", "dev", "test", "admin", "vpn", "ftp"]

# How long (seconds) to wait for a single DNS resolution before giving up
# on that candidate and moving on to the next one.
_RESOLVE_TIMEOUT = 5.0


def _load_wordlist(wordlist_path: str) -> List[str]:
    """
    Read candidate subdomain prefixes from a wordlist file, one per line.

    Blank lines and lines starting with '#' (comments) are ignored.
    Falls back to a small built-in default list if the file can't be
    found, so the tool still does something useful.
    """
    path = Path(wordlist_path)

    if not path.is_file():
        print_warning(f"Wordlist not found at '{wordlist_path}'. Using built-in defaults.")
        return list(_DEFAULT_WORDS)

    words: List[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        word = raw_line.strip()
        if word and not word.startswith("#"):
            words.append(word)

    if not words:
        print_warning(f"Wordlist '{wordlist_path}' is empty. Using built-in defaults.")
        return list(_DEFAULT_WORDS)

    return words


def _resolve(hostname: str) -> Optional[str]:
    """
    Attempt to resolve `hostname` to an IPv4 address.

    Tries dnspython first (if available, since it supports timeouts),
    then falls back to the standard library `socket.gethostbyname`.

    Returns:
        The resolved IP address as a string, or None if it doesn't resolve.
    """
    if DNSPYTHON_AVAILABLE:
        try:
            answer = dns.resolver.resolve(hostname, "A", lifetime=_RESOLVE_TIMEOUT)
            return str(answer[0])
        except Exception:
            # Covers NXDOMAIN, NoAnswer, Timeout, NoNameservers, etc.
            # A failed lookup just means "not a valid host" -- not an error
            # worth surfacing to the user for every wordlist entry.
            return None
    else:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None


def brute_force(
    domain: str,
    wordlist_path: str = "wordlists/subdomains.txt",
) -> List[Dict[str, str]]:
    """
    Perform DNS brute-force enumeration against `domain`.

    For every prefix in the wordlist, builds `<prefix>.<domain>` and checks
    whether it resolves. Only hosts that successfully resolve are kept.

    Args:
        domain: The target domain, e.g. "example.com".
        wordlist_path: Path to a newline-delimited wordlist file.

    Returns:
        A de-duplicated, sorted list of dicts of the form
        {"hostname": "api.example.com", "ip": "93.184.216.34"}.
    """
    words = _load_wordlist(wordlist_path)
    print_info(f"Loaded {len(words)} candidate prefixes from '{wordlist_path}'.")

    # Using a dict keyed by hostname gives us de-duplication for free,
    # even if the wordlist contains repeated entries.
    found: Dict[str, str] = {}

    for index, word in enumerate(words, start=1):
        hostname = f"{word}.{domain}"
        print_info(f"  [{index}/{len(words)}] Checking {hostname} ...")

        ip_address = _resolve(hostname)
        if ip_address:
            found[hostname] = ip_address

    results = [{"hostname": host, "ip": ip} for host, ip in sorted(found.items())]
    return results
