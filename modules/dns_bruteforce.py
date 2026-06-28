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

DNS lookups are executed concurrently via ``ThreadPoolExecutor`` for
significantly faster throughput with large wordlists.  A ``tqdm``
progress bar gives real-time feedback during the brute-force stage.
"""

from __future__ import annotations

import concurrent.futures
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.utils import print_info, print_warning

try:
    import dns.resolver  # type: ignore

    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

try:
    from tqdm import tqdm  # type: ignore

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Resolve the project root relative to *this* file so that the default
# wordlist path works regardless of the caller's working directory.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_WORDLIST = _PROJECT_ROOT / "wordlists" / "subdomains.txt"

# Sensible default wordlist used if the requested wordlist file is
# missing for some reason -- keeps the tool usable out of the box.
_DEFAULT_WORDS = ["api", "mail", "dev", "test", "admin", "vpn", "ftp"]

# How long (seconds) to wait for a single DNS resolution before giving up
# on that candidate and moving on to the next one.
_RESOLVE_TIMEOUT = 5.0

# Default number of concurrent workers for DNS lookups.
_DEFAULT_WORKERS = 20


def _load_wordlist(wordlist_path: Path) -> List[str]:
    """
    Read candidate subdomain prefixes from a wordlist file, one per line.

    Blank lines and lines starting with '#' (comments) are ignored.
    Falls back to a small built-in default list if the file can't be
    found or cannot be decoded, so the tool still does something useful.
    """
    if not wordlist_path.is_file():
        print_warning(f"Wordlist not found at '{wordlist_path}'. Using built-in defaults.")
        return list(_DEFAULT_WORDS)

    try:
        raw_text = wordlist_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        print_warning(
            f"Could not decode wordlist '{wordlist_path}' as UTF-8 ({exc}). "
            "Re-save the file with UTF-8 encoding or use a different wordlist. "
            "Falling back to built-in defaults."
        )
        return list(_DEFAULT_WORDS)

    words: List[str] = []
    for raw_line in raw_text.splitlines():
        word = raw_line.strip()
        if word and not word.startswith("#"):
            words.append(word)

    if not words:
        print_warning(f"Wordlist '{wordlist_path}' is empty. Using built-in defaults.")
        return list(_DEFAULT_WORDS)

    return words


def _resolve(hostname: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Attempt to resolve ``hostname`` to an IPv4 address.

    Tries dnspython first (if available, since it supports timeouts and
    richer record-type information), then falls back to the standard
    library ``socket.gethostbyname``.

    Returns:
        A ``(ip_address, record_type)`` tuple on success, or
        ``(None, None)`` if the hostname does not resolve.
        ``record_type`` is ``"A"`` or ``"CNAME"`` when dnspython is
        available; ``"A"`` (assumed) when using the socket fallback.
    """
    if DNSPYTHON_AVAILABLE:
        try:
            answer = dns.resolver.resolve(hostname, "A", lifetime=_RESOLVE_TIMEOUT)
            # Determine whether the final answer came through a CNAME.
            record_type = "CNAME" if answer.canonical_name.to_text().rstrip(".").lower() != hostname.lower() else "A"
            return str(answer[0]), record_type
        except Exception:
            return None, None
    else:
        try:
            ip = socket.gethostbyname(hostname)
            return ip, "A"
        except socket.gaierror:
            return None, None


def brute_force(
    domain: str,
    wordlist_path: str | None = None,
    max_workers: int = _DEFAULT_WORKERS,
) -> List[Dict[str, str]]:
    """
    Perform DNS brute-force enumeration against ``domain``.

    For every prefix in the wordlist, builds ``<prefix>.<domain>`` and
    checks whether it resolves.  Lookups run concurrently via
    ``ThreadPoolExecutor`` for much better throughput on large wordlists.

    Args:
        domain: The target domain, e.g. ``"example.com"``.
        wordlist_path: Path to a newline-delimited wordlist file.  When
            *None*, the default wordlist shipped with the project is
            used (resolved relative to the script location).
        max_workers: Maximum number of threads for concurrent DNS
            lookups.

    Returns:
        A de-duplicated, sorted list of dicts of the form
        ``{"hostname": "api.example.com", "ip": "93.184.216.34",
        "record_type": "A"}``.
    """
    wl_path = Path(wordlist_path) if wordlist_path is not None else _DEFAULT_WORDLIST
    words = _load_wordlist(wl_path)
    print_info(f"Loaded {len(words)} candidate prefixes from '{wl_path}'.")
    print_info(f"Resolving with {max_workers} concurrent workers...")

    candidates = [f"{word}.{domain}" for word in words]

    # Using a dict keyed by hostname gives us de-duplication for free,
    # even if the wordlist contains repeated entries.
    found: Dict[str, Dict[str, str]] = {}

    def _check(hostname: str) -> Tuple[str, Optional[str], Optional[str]]:
        ip, rtype = _resolve(hostname)
        return hostname, ip, rtype

    if TQDM_AVAILABLE:
        progress = tqdm(total=len(candidates), desc="DNS brute-force", unit="host")
    else:
        progress = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check, h): h for h in candidates}
        for future in concurrent.futures.as_completed(futures):
            hostname, ip, rtype = future.result()
            if ip:
                found[hostname] = {"hostname": hostname, "ip": ip, "record_type": rtype or "A"}
            if progress is not None:
                progress.update(1)

    if progress is not None:
        progress.close()

    results = sorted(found.values(), key=lambda e: e["hostname"])
    return results
