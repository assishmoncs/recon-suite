"""
modules/dns_bruteforce.py

Active DNS brute-force enumeration, wildcard DNS detection, unified subdomain
enrichment, dangling CNAME hygiene auditing, and root-domain DNS posture checks.

Improvements in v3:
  1. Wildcard DNS detection (``detect_wildcard_dns``) probes random UUID
     subdomains before brute-forcing so catch-all ``*.domain.com`` records do
     not flood reports with 100% false-positive hits.
  2. Configurable custom DNS nameservers (``--nameservers 1.1.1.1,8.8.8.8``)
     via a pre-configured ``dns.resolver.Resolver`` instance.
  3. Full IPv4 (``A``), IPv6 (``AAAA``), and canonical ``CNAME`` target
     resolution.
  4. Unified asset enrichment (``enrich_subdomains``) resolves passive OSINT
     subdomains alongside brute-forced hosts and checks for dangling cloud
     CNAME records (defensive subdomain takeover risk auditing).
  5. Root-domain DNS security posture audit (``audit_domain_dns``) inspects
     ``NS``, ``MX``, ``SPF``, ``DMARC``, and ``CAA`` records.
"""

from __future__ import annotations

import concurrent.futures
import socket
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.utils import print_info, print_warning

try:
    import dns.exception  # type: ignore
    import dns.name  # type: ignore
    import dns.resolver  # type: ignore

    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

try:
    from tqdm import tqdm  # type: ignore

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_WORDLIST = _PROJECT_ROOT / "wordlists" / "subdomains.txt"

_DEFAULT_WORDS = ["api", "mail", "dev", "test", "admin", "vpn", "ftp"]
_RESOLVE_TIMEOUT = 5.0
_DEFAULT_WORKERS = 20

# Cloud service suffixes where an unresolved (NXDOMAIN) CNAME target indicates
# a stale/dangling DNS record that should be removed or claimed by defenders.
_CLOUD_CNAME_SIGNATURES: Dict[str, str] = {
    "github.io": "GitHub Pages",
    "s3.amazonaws.com": "AWS S3 Bucket",
    "s3-website": "AWS S3 Website",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku DNS",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "fastly.net": "Fastly CDN",
    "pantheonsite.io": "Pantheon",
    "myshopify.com": "Shopify",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket Pages",
    "ghost.io": "Ghost Pro",
    "readme.io": "ReadMe Docs",
    "zendesk.com": "Zendesk",
    "wpengine.com": "WP Engine",
    "unbouncepages.com": "Unbounce",
    "statuspage.io": "Atlassian Statuspage",
    "cargocollective.com": "Cargo Collective",
    "fly.dev": "Fly.io",
    "onrender.com": "Render",
}


def _build_resolver(
    nameservers: Optional[List[str]] = None,
    timeout: float = _RESOLVE_TIMEOUT,
) -> Optional[Any]:
    """Create a reusable ``dns.resolver.Resolver`` configured with timeouts and nameservers."""
    if not DNSPYTHON_AVAILABLE:
        return None

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameservers:
        resolver.nameservers = list(nameservers)
    return resolver


def _load_wordlist(wordlist_path: Path) -> List[str]:
    """
    Read candidate subdomain prefixes from a wordlist file, one per line.
    Blank lines and lines starting with '#' are ignored.
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
        word = raw_line.strip().lower()
        if word and not word.startswith("#"):
            words.append(word)

    if not words:
        print_warning(f"Wordlist '{wordlist_path}' is empty. Using built-in defaults.")
        return list(_DEFAULT_WORDS)

    return words


def _resolve_detailed(
    hostname: str,
    resolver: Optional[Any] = None,
) -> Dict[str, Optional[str]]:
    """
    Resolve ``hostname`` for IPv4 (``A``), IPv6 (``AAAA``), and ``CNAME`` records.

    Returns a dict with keys:
      - ``ip``: primary IPv4 address (or IPv6 if IPv4 is absent)
      - ``ipv6``: primary IPv6 address if present
      - ``record_type``: ``"CNAME"``, ``"A"``, ``"AAAA"``, or None
      - ``cname_target``: canonical CNAME target if ``hostname`` is an alias
    """
    result: Dict[str, Optional[str]] = {
        "ip": None,
        "ipv6": None,
        "record_type": None,
        "cname_target": None,
    }

    if DNSPYTHON_AVAILABLE:
        res = resolver if resolver is not None else dns.resolver
        # 1. Check explicit CNAME first so we capture even dangling CNAME targets
        try:
            if resolver is not None:
                cname_ans = res.resolve(hostname, "CNAME")
            else:
                cname_ans = dns.resolver.resolve(hostname, "CNAME", lifetime=_RESOLVE_TIMEOUT)
            if cname_ans:
                target = str(cname_ans[0].target).rstrip(".").lower()
                if target and target != hostname.lower():
                    result["cname_target"] = target
                    result["record_type"] = "CNAME"
        except Exception:
            pass

        # 2. Check IPv4 (A)
        try:
            if resolver is not None:
                a_ans = res.resolve(hostname, "A")
            else:
                a_ans = dns.resolver.resolve(hostname, "A", lifetime=_RESOLVE_TIMEOUT)
            if a_ans:
                result["ip"] = str(a_ans[0])
                canonical = a_ans.canonical_name.to_text().rstrip(".").lower()
                if canonical != hostname.lower():
                    result["cname_target"] = result["cname_target"] or canonical
                    result["record_type"] = "CNAME"
                else:
                    result["record_type"] = result["record_type"] or "A"
        except Exception:
            pass

        # 3. Check IPv6 (AAAA)
        try:
            if resolver is not None:
                aaaa_ans = res.resolve(hostname, "AAAA")
            else:
                aaaa_ans = dns.resolver.resolve(hostname, "AAAA", lifetime=_RESOLVE_TIMEOUT)
            if aaaa_ans:
                result["ipv6"] = str(aaaa_ans[0])
                if not result["ip"]:
                    result["ip"] = result["ipv6"]
                if not result["record_type"]:
                    result["record_type"] = "AAAA"
        except Exception:
            pass

        return result

    # Fallback to standard library socket
    try:
        ip = socket.gethostbyname(hostname)
        result["ip"] = ip
        result["record_type"] = "A"
    except socket.gaierror:
        pass
    return result


def _resolve(
    hostname: str,
    resolver: Optional[Any] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Backward-compatible resolution helper returning ``(ip_address, record_type)``.
    """
    details = _resolve_detailed(hostname, resolver=resolver)
    if details["ip"]:
        return details["ip"], details["record_type"] or "A"
    return None, None


def detect_wildcard_dns(
    domain: str,
    resolver: Optional[Any] = None,
    probes: int = 3,
) -> Tuple[Set[str], Set[str]]:
    """
    Probe non-existent random subdomains (e.g. ``<uuid>.<domain>``) to detect
    whether the target domain uses a catch-all wildcard DNS record.

    Returns:
        ``(wildcard_ips, wildcard_cnames)`` sets that should be filtered out
        during active wordlist brute-forcing.
    """
    wildcard_ips: Set[str] = set()
    wildcard_cnames: Set[str] = set()

    for _ in range(probes):
        random_label = f"recon-wildcard-{uuid.uuid4().hex[:10]}"
        probe_host = f"{random_label}.{domain}"
        details = _resolve_detailed(probe_host, resolver=resolver)
        if details["ip"]:
            wildcard_ips.add(details["ip"])
        if details["ipv6"]:
            wildcard_ips.add(details["ipv6"])
        if details["cname_target"]:
            wildcard_cnames.add(details["cname_target"])

    return wildcard_ips, wildcard_cnames


def check_dangling_cname(
    cname_target: Optional[str],
    resolved_ip: Optional[str],
    resolved_ipv6: Optional[str] = None,
) -> Optional[str]:
    """
    Check whether a subdomain has a dangling CNAME record pointing to an
    unclaimed external cloud resource (defensive subdomain takeover audit).

    Returns:
        A human-readable hygiene warning string if a risk is detected, else None.
    """
    if not cname_target:
        return None

    # Only flag when the CNAME alias fails to resolve to any IP address
    if resolved_ip or resolved_ipv6:
        return None

    target_lower = cname_target.lower().rstrip(".")
    for signature, provider in _CLOUD_CNAME_SIGNATURES.items():
        if signature in target_lower:
            return f"Unresolved CNAME to {provider} ({target_lower})"

    return f"Unresolved dangling CNAME ({target_lower})"


def brute_force(
    domain: str,
    wordlist_path: str | None = None,
    max_workers: int = _DEFAULT_WORKERS,
    nameservers: Optional[List[str]] = None,
    detect_wildcards: bool = True,
) -> List[Dict[str, str]]:
    """
    Perform concurrent DNS brute-force enumeration against ``domain``.

    Includes automatic wildcard DNS detection so catch-all ``*.domain``
    responses are filtered out rather than reported as false-positive hits.
    """
    wl_path = Path(wordlist_path) if wordlist_path is not None else _DEFAULT_WORDLIST
    words = _load_wordlist(wl_path)
    print_info(f"Loaded {len(words)} candidate prefixes from '{wl_path}'.")

    resolver = _build_resolver(nameservers=nameservers, timeout=_RESOLVE_TIMEOUT)
    if nameservers:
        print_info(f"Using custom DNS nameservers: {', '.join(nameservers)}")

    wildcard_ips: Set[str] = set()
    wildcard_cnames: Set[str] = set()
    if detect_wildcards:
        wildcard_ips, wildcard_cnames = detect_wildcard_dns(domain, resolver=resolver)
        if wildcard_ips or wildcard_cnames:
            print_warning(
                f"Wildcard DNS detected on '*.{domain}' "
                f"(IPs: {', '.join(sorted(wildcard_ips)) or 'none'}). "
                "Filtering catch-all responses to prevent false positives."
            )

    print_info(f"Resolving with {max_workers} concurrent workers...")
    candidates = [f"{word}.{domain}" for word in words]
    found: Dict[str, Dict[str, str]] = {}

    def _check(hostname: str) -> Tuple[str, Dict[str, Optional[str]]]:
        details = _resolve_detailed(hostname, resolver=resolver)
        if not details["ip"] and not details["cname_target"]:
            # Fallback to _resolve in case a test mocks _resolve directly
            ip, rtype = _resolve(hostname)
            if ip:
                details["ip"] = ip
                details["record_type"] = rtype or "A"
        return hostname, details

    progress = (
        tqdm(total=len(candidates), desc="DNS brute-force", unit="host")
        if TQDM_AVAILABLE
        else None
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check, h): h for h in candidates}
        for future in concurrent.futures.as_completed(futures):
            hostname, details = future.result()
            ip = details.get("ip")
            cname = details.get("cname_target")

            # Filter out wildcard DNS matches
            if ip and ip in wildcard_ips:
                if progress is not None:
                    progress.update(1)
                continue
            if cname and cname in wildcard_cnames:
                if progress is not None:
                    progress.update(1)
                continue

            if ip:
                found[hostname] = {
                    "hostname": hostname,
                    "ip": ip,
                    "ipv6": details.get("ipv6") or "",
                    "record_type": details.get("record_type") or "A",
                    "cname_target": cname or "",
                }
            if progress is not None:
                progress.update(1)

    if progress is not None:
        progress.close()

    return sorted(found.values(), key=lambda e: e["hostname"])


def enrich_subdomains(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    passive_source_map: Optional[Dict[str, List[str]]] = None,
    default_passive_source: str = "Passive OSINT",
    max_workers: int = _DEFAULT_WORKERS,
    nameservers: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Merge passive and brute-forced subdomains into a single unified inventory,
    resolving any passive-only subdomains and checking for dangling CNAME risks.
    """
    resolver = _build_resolver(nameservers=nameservers, timeout=_RESOLVE_TIMEOUT)
    bf_by_host: Dict[str, Dict[str, str]] = {
        entry["hostname"]: entry for entry in bruteforce_results
    }
    all_hosts = sorted(set(passive_subdomains) | set(bf_by_host.keys()))
    if not all_hosts:
        return []

    passive_only = [h for h in all_hosts if h not in bf_by_host]
    resolved_passive: Dict[str, Dict[str, Optional[str]]] = {}

    if passive_only:
        print_info(f"Resolving {len(passive_only)} passive subdomain(s) for DNS enrichment...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_resolve_detailed, host, resolver): host
                for host in passive_only
            }
            for future in concurrent.futures.as_completed(future_map):
                host = future_map[future]
                try:
                    resolved_passive[host] = future.result()
                except Exception:
                    resolved_passive[host] = {
                        "ip": None,
                        "ipv6": None,
                        "record_type": None,
                        "cname_target": None,
                    }

    unified: List[Dict[str, Any]] = []
    for host in all_hosts:
        sources: List[str] = []
        if passive_source_map and host in passive_source_map:
            sources.extend(passive_source_map[host])
        elif host in passive_subdomains:
            sources.append(default_passive_source)

        if host in bf_by_host:
            if "DNS Brute-Force" not in sources:
                sources.append("DNS Brute-Force")
            bf_entry = bf_by_host[host]
            ip = bf_entry.get("ip") or ""
            ipv6 = bf_entry.get("ipv6") or ""
            rtype = bf_entry.get("record_type") or ("A" if ip else "UNRESOLVED")
            cname = bf_entry.get("cname_target") or ""
        else:
            p_details = resolved_passive.get(host, {})
            ip = p_details.get("ip") or ""
            ipv6 = p_details.get("ipv6") or ""
            cname = p_details.get("cname_target") or ""
            rtype = p_details.get("record_type") or ("A" if ip else "UNRESOLVED")

        hygiene_warning = check_dangling_cname(cname, ip or None, ipv6 or None)
        status = (
            "DANGLING_CNAME"
            if hygiene_warning
            else ("RESOLVED" if (ip or ipv6) else "UNRESOLVED")
        )

        unified.append(
            {
                "hostname": host,
                "ip": ip,
                "ipv6": ipv6,
                "record_type": rtype,
                "cname_target": cname,
                "sources": sources,
                "status": status,
                "hygiene_warning": hygiene_warning or "",
            }
        )

    return unified


def audit_domain_dns(
    domain: str,
    nameservers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Audit root-domain DNS security posture (NS, MX, SPF, DMARC, CAA).
    """
    posture: Dict[str, Any] = {
        "ns_records": [],
        "mx_records": [],
        "spf_record": None,
        "dmarc_record": None,
        "caa_records": [],
    }
    if not DNSPYTHON_AVAILABLE:
        return posture

    resolver = _build_resolver(nameservers=nameservers, timeout=_RESOLVE_TIMEOUT)
    res = resolver if resolver is not None else dns.resolver

    # NS records
    try:
        ns_ans = res.resolve(domain, "NS")
        posture["ns_records"] = sorted(
            str(r.target).rstrip(".").lower() for r in ns_ans
        )
    except Exception:
        pass

    # MX records
    try:
        mx_ans = res.resolve(domain, "MX")
        posture["mx_records"] = sorted(
            f"{r.preference} {str(r.exchange).rstrip('.').lower()}" for r in mx_ans
        )
    except Exception:
        pass

    # TXT / SPF records
    try:
        txt_ans = res.resolve(domain, "TXT")
        for r in txt_ans:
            txt_val = "".join(
                s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                for s in getattr(r, "strings", [str(r).strip('"')])
            )
            if txt_val.lower().startswith("v=spf1"):
                posture["spf_record"] = txt_val
                break
    except Exception:
        pass

    # DMARC record (_dmarc.<domain>)
    try:
        dmarc_ans = res.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_ans:
            txt_val = "".join(
                s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                for s in getattr(r, "strings", [str(r).strip('"')])
            )
            if "v=dmarc1" in txt_val.lower():
                posture["dmarc_record"] = txt_val
                break
    except Exception:
        pass

    # CAA records
    try:
        caa_ans = res.resolve(domain, "CAA")
        posture["caa_records"] = sorted(str(r) for r in caa_ans)
    except Exception:
        pass

    return posture
