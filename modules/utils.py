"""
modules/utils.py

Shared helper functions used across the Automated Recon Tool (v3):
  - RFC-compliant domain name validation
  - Strict subdomain boundary verification (prevents suffix-matching false positives)
  - Custom DNS nameserver IP validation
  - Colored / consistent terminal output (via colorama)
"""

from __future__ import annotations

import ipaddress
import re
from typing import List

from colorama import Fore, Style
from colorama import init as colorama_init

# autoreset=True resets terminal color automatically after every print() call.
colorama_init(autoreset=True)

# Strict RFC 1035 / RFC 1123 domain pattern:
# Rejects leading/trailing hyphens in each label and requires at least one dot
# with an alphabetic TLD of 2+ characters (e.g. "example.com", "sub.example.co.uk").
_DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.([A-Za-z]{2,63})$"
)


def validate_domain(domain: str) -> bool:
    """
    Validate that ``domain`` is a syntactically well-formed domain name.

    Checks RFC 1035 length limits (<= 253 chars overall, 1..63 chars per label),
    disallows leading/trailing hyphens, and requires at least one dot with a valid TLD.

    Args:
        domain: The raw domain string supplied by the user.

    Returns:
        True if the domain looks syntactically valid, False otherwise.
    """
    if not domain or not isinstance(domain, str):
        return False

    cleaned = domain.strip().lower()
    if len(cleaned) > 253:
        return False

    return bool(_DOMAIN_PATTERN.match(cleaned))


def is_valid_subdomain(candidate: str, target_domain: str) -> bool:
    """
    Verify that ``candidate`` is either ``target_domain`` itself or a true
    subdomain ending with ``.<target_domain>``, and is syntactically valid.

    This prevents the classic suffix-matching bug where ``badexample.com``
    falsely matches ``example.com`` via ``candidate.endswith(domain)``.

    Args:
        candidate: Discovered hostname (may include leading ``*.`` wildcard).
        target_domain: Normalized target root domain (e.g. ``"example.com"``).

    Returns:
        True if ``candidate`` is a valid hostname within ``target_domain``.
    """
    if not candidate or not target_domain:
        return False

    cleaned = candidate.strip().lower().lstrip("*.")
    target = target_domain.strip().lower().lstrip("*.")

    if cleaned != target and not cleaned.endswith(f".{target}"):
        return False

    return validate_domain(cleaned)


def parse_nameservers(raw_nameservers: str | None) -> List[str]:
    """
    Parse and validate a comma-separated list of IPv4/IPv6 DNS nameserver IPs.

    Args:
        raw_nameservers: Comma-separated string like ``"1.1.1.1,8.8.8.8"`` or None.

    Returns:
        A list of validated IP address strings.

    Raises:
        ValueError: If any entry is not a valid IPv4 or IPv6 address.
    """
    if not raw_nameservers:
        return []

    validated: List[str] = []
    for part in raw_nameservers.split(","):
        ip_str = part.strip()
        if not ip_str:
            continue
        try:
            ipaddress.ip_address(ip_str)
            validated.append(ip_str)
        except ValueError as exc:
            raise ValueError(f"Invalid DNS nameserver IP '{ip_str}': {exc}") from exc

    return validated


def print_banner(domain: str) -> None:
    """Print the tool's startup banner with the target domain."""
    line = "=" * 58
    print(Fore.CYAN + Style.BRIGHT + line)
    print(Fore.CYAN + Style.BRIGHT + "      Automated Recon Suite -- v3.0 (EASM & DNS Audit)")
    print(Fore.CYAN + Style.BRIGHT + line)
    print(Fore.WHITE + Style.BRIGHT + f"Target: {domain}\n")


def print_info(message: str) -> None:
    """Print a neutral, informational status message."""
    print(Fore.CYAN + f"[*] {message}")


def print_success(message: str) -> None:
    """Print a success message (e.g. a step completed)."""
    print(Fore.GREEN + Style.BRIGHT + f"[+] {message}")


def print_warning(message: str) -> None:
    """Print a non-fatal warning (e.g. a fallback was used)."""
    print(Fore.YELLOW + f"[!] {message}")


def print_error(message: str) -> None:
    """Print an error message (e.g. a step failed)."""
    print(Fore.RED + Style.BRIGHT + f"[-] {message}")
