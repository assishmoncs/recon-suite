"""
modules/utils.py

Shared helper functions used across the Automated Recon Tool:
  - Domain name validation
  - Colored / consistent terminal output (via colorama)

Keeping these in one place avoids duplicating formatting logic in every
module and makes it easy to change the tool's look-and-feel later.
"""

from __future__ import annotations

import re

from colorama import Fore, Style
from colorama import init as colorama_init

# autoreset=True means we don't have to manually reset the color after
# every single print() call.
colorama_init(autoreset=True)

# A reasonably strict (but not overly pedantic) regex for validating
# domain names. It rejects leading/trailing hyphens in each label and
# requires at least one dot (i.e. a TLD), e.g. "example.com",
# "sub.example.co.uk".
_DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain: str) -> bool:
    """
    Validate that `domain` is a syntactically well-formed domain name.

    This is a *format* check only (correct characters, label lengths,
    at least one dot for a TLD) -- it does not check whether the domain
    actually exists or resolves on the network.

    Args:
        domain: The raw domain string supplied by the user.

    Returns:
        True if the domain looks syntactically valid, False otherwise.
    """
    if not domain:
        return False

    domain = domain.strip().lower()

    # Overall domain length is capped at 253 characters per RFC 1035.
    if len(domain) > 253:
        return False

    return bool(_DOMAIN_PATTERN.match(domain))


def print_banner(domain: str) -> None:
    """Print the tool's startup banner with the target domain."""
    line = "=" * 50
    print(Fore.CYAN + Style.BRIGHT + line)
    print(Fore.CYAN + Style.BRIGHT + "      Automated Recon Tool -- v2")
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
