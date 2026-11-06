"""
modules/http_probe.py

Defensive HTTP/HTTPS & TLS hygiene probing for discovered hosts.

When enabled via ``--probe-http``, concurrently inspects resolved subdomains
over HTTPS (and HTTP fallback) to record:
  - HTTP response status code (e.g. 200, 301, 403)
  - Server header banner
  - TLS certificate remaining validity in days
  - Defensive security headers present (HSTS, CSP, X-Frame-Options)
"""

from __future__ import annotations

import concurrent.futures
import datetime
import socket
import ssl
from typing import Any, Dict, List, Optional

import requests

from modules.utils import print_info

_PROBE_TIMEOUT = 4.0
_USER_AGENT = "ReconSuite/3.0 (Defensive Asset Inventory)"


def _get_tls_days_remaining(hostname: str, timeout: float = _PROBE_TIMEOUT) -> Optional[int]:
    """Return the number of days until the host's TLS certificate expires, or None."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert or "notAfter" not in cert:
                    return None
                not_after_str = str(cert["notAfter"])
                expiry_dt = datetime.datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=datetime.timezone.utc)
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                return (expiry_dt - now_dt).days
    except Exception:
        return None


def _probe_single_host(
    hostname: str,
    timeout: float = _PROBE_TIMEOUT,
) -> Dict[str, Any]:
    """Probe HTTPS (falling back to HTTP) for a single hostname."""
    result: Dict[str, Any] = {
        "http_status": None,
        "scheme": None,
        "server": "",
        "tls_days_remaining": None,
        "security_headers": [],
    }
    headers = {"User-Agent": _USER_AGENT}

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            )
            result["http_status"] = resp.status_code
            result["scheme"] = scheme.upper()
            result["server"] = resp.headers.get("Server", "")[:60]

            sec_headers: List[str] = []
            if "Strict-Transport-Security" in resp.headers:
                sec_headers.append("HSTS")
            if "Content-Security-Policy" in resp.headers:
                sec_headers.append("CSP")
            if "X-Frame-Options" in resp.headers:
                sec_headers.append("XFO")
            if "X-Content-Type-Options" in resp.headers:
                sec_headers.append("XCTO")
            result["security_headers"] = sec_headers

            if scheme == "https":
                result["tls_days_remaining"] = _get_tls_days_remaining(
                    hostname, timeout=timeout
                )
            break
        except requests.RequestException:
            continue

    return result


def probe_hosts(
    enriched_records: List[Dict[str, Any]],
    max_workers: int = 20,
    timeout: float = _PROBE_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    Concurrently probe all resolved hosts in ``enriched_records`` and attach
    HTTP/TLS metadata fields in-place.
    """
    live_records = [r for r in enriched_records if r.get("ip") or r.get("ipv6")]
    if not live_records:
        return enriched_records

    print_info(
        f"Probing HTTP/TLS posture across {len(live_records)} resolved host(s)..."
    )

    probe_map: Dict[str, Dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(_probe_single_host, rec["hostname"], timeout): rec["hostname"]
            for rec in live_records
        }
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                probe_map[host] = future.result()
            except Exception:
                probe_map[host] = {}

    for rec in enriched_records:
        info = probe_map.get(rec["hostname"], {})
        rec["http_status"] = info.get("http_status")
        rec["scheme"] = info.get("scheme") or ""
        rec["server"] = info.get("server") or ""
        rec["tls_days_remaining"] = info.get("tls_days_remaining")
        rec["security_headers"] = info.get("security_headers") or []

    return enriched_records
