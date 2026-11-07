"""
modules/report.py

Generates scan reports in Interactive HTML, Print-Friendly A4 PDF, JSON, and CSV
formats, and supports snapshot diffing against previous JSON scan reports.

Improvements in v3:
  1. Granular per-subdomain source badges (e.g. ``crt.sh``, ``AlienVault OTX``,
     ``DNS Brute-Force``) instead of stamping a single combined string on every row.
  2. Unified Enriched Asset Inventory table with client-side JavaScript search,
     category filter pills (All, Resolved, CNAME, Multi-Source, Hygiene Alerts),
     and click-to-sort column headers.
  3. Root-domain DNS Security Posture summary cards (SPF, DMARC, CAA, MX, NS).
  4. IP /24 Subnet Clustering breakdown to identify shared hosting infrastructure.
  5. Multi-engine PDF rendering (``xhtml2pdf`` -> ``weasyprint`` -> ``reportlab``)
     so PDF generation succeeds across diverse Python environments.
  6. Machine-readable JSON and CSV exports plus ``--diff`` snapshot comparison.
"""

from __future__ import annotations

import csv
import html
import ipaddress
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from xhtml2pdf import pisa  # type: ignore

    _XHTML2PDF_AVAILABLE = True
except ImportError:
    _XHTML2PDF_AVAILABLE = False

try:
    import weasyprint  # type: ignore

    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WEASYPRINT_AVAILABLE = False

try:
    from reportlab.lib import colors  # type: ignore
    from reportlab.lib.pagesizes import A4  # type: ignore
    from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
    from reportlab.platypus import (  # type: ignore
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False

PDF_AVAILABLE = (
    _XHTML2PDF_AVAILABLE or _WEASYPRINT_AVAILABLE or _REPORTLAB_AVAILABLE
)


def _table_rows(rows: List[List[str]], empty_message: str, colspan: int = 1) -> str:
    """
    Build ``<tr>`` HTML for a table body with strict ``html.escape()`` on every cell.
    """
    if not rows:
        return (
            f'<tr><td colspan="{colspan}" class="empty">'
            f"{html.escape(empty_message)}</td></tr>"
        )

    rendered_rows = []
    for row in rows:
        cells = "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row)
        rendered_rows.append(f"<tr>{cells}</tr>")
    return "\n".join(rendered_rows)


def _group_by_subnet(enriched_records: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Group resolved hostnames by their IPv4 /24 or IPv6 /64 network prefix."""
    subnets: Dict[str, List[str]] = defaultdict(list)
    for rec in enriched_records:
        ip_str = rec.get("ip") or ""
        if not ip_str:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip_str}/64", strict=False)
            subnets[str(net)].append(rec["hostname"])
        except ValueError:
            continue
    return dict(sorted(subnets.items(), key=lambda kv: (-len(kv[1]), kv[0])))


def compute_diff(
    current_subdomains: List[str],
    previous_json_path: str,
) -> Dict[str, List[str]]:
    """
    Compare ``current_subdomains`` against a previous scan's JSON report.

    Returns a dict with ``added``, ``removed``, and ``unchanged`` subdomain lists.
    """
    prev_file = Path(previous_json_path)
    data = json.loads(prev_file.read_text(encoding="utf-8"))

    prev_subs: set[str] = set()
    if "unified_assets" in data and isinstance(data["unified_assets"], list):
        for item in data["unified_assets"]:
            if isinstance(item, dict) and item.get("hostname"):
                prev_subs.add(str(item["hostname"]).lower())
    elif "passive_subdomains" in data:
        prev_subs.update(str(s).lower() for s in data.get("passive_subdomains", []))
        for bf in data.get("bruteforce_results", []):
            if isinstance(bf, dict) and bf.get("hostname"):
                prev_subs.add(str(bf["hostname"]).lower())

    curr_set = {s.lower() for s in current_subdomains}
    return {
        "added": sorted(curr_set - prev_subs),
        "removed": sorted(prev_subs - curr_set),
        "unchanged": sorted(curr_set & prev_subs),
    }


def _synthesize_enriched_records(
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    passive_source: str,
    passive_source_map: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    """Build fallback enriched records when ``enriched_records`` is not passed explicitly."""
    bf_by_host = {e["hostname"]: e for e in bruteforce_results}
    all_hosts = sorted(set(passive_subdomains) | set(bf_by_host.keys()))
    synthesized: List[Dict[str, Any]] = []

    for host in all_hosts:
        sources: List[str] = []
        if passive_source_map and host in passive_source_map:
            sources.extend(passive_source_map[host])
        elif host in passive_subdomains:
            sources.append(passive_source)

        if host in bf_by_host:
            if "DNS Brute-Force" not in sources:
                sources.append("DNS Brute-Force")
            bf = bf_by_host[host]
            ip = bf.get("ip", "")
            ipv6 = bf.get("ipv6", "")
            rtype = bf.get("record_type", "A")
            cname = bf.get("cname_target", "")
        else:
            ip = ""
            ipv6 = ""
            rtype = "PASSIVE"
            cname = ""

        synthesized.append(
            {
                "hostname": host,
                "ip": ip,
                "ipv6": ipv6,
                "record_type": rtype,
                "cname_target": cname,
                "sources": sources,
                "status": "RESOLVED" if ip else "UNRESOLVED",
                "hygiene_warning": "",
            }
        )
    return synthesized


def generate_report(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    output_dir: str = "reports",
    passive_source: str = "Sublist3r",
    passive_source_map: Optional[Dict[str, List[str]]] = None,
    enriched_records: Optional[List[Dict[str, Any]]] = None,
    dns_posture: Optional[Dict[str, Any]] = None,
    diff_summary: Optional[Dict[str, List[str]]] = None,
    filename_prefix: Optional[str] = None,
) -> str:
    """
    Build an interactive HTML recon & DNS hygiene report for ``domain``.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    bruteforce_hostnames = {entry["hostname"] for entry in bruteforce_results}
    total_unique_subdomains = sorted(set(passive_subdomains) | bruteforce_hostnames)

    records = (
        enriched_records
        if enriched_records is not None
        else _synthesize_enriched_records(
            passive_subdomains,
            bruteforce_results,
            passive_source,
            passive_source_map=passive_source_map,
        )
    )

    resolved_count = sum(1 for r in records if r.get("ip") or r.get("ipv6"))
    hygiene_warnings = [r for r in records if r.get("hygiene_warning")]

    # Per-row source attribution for Passive Enumeration table
    passive_rows_data: List[List[str]] = []
    for sub in passive_subdomains:
        if passive_source_map and sub in passive_source_map:
            src_str = ", ".join(passive_source_map[sub])
        else:
            src_str = passive_source
        passive_rows_data.append([sub, src_str])

    passive_rows_html = _table_rows(
        passive_rows_data,
        empty_message="No passive subdomains found.",
        colspan=2,
    )

    bruteforce_rows_html = _table_rows(
        [
            [entry["hostname"], entry["ip"], entry.get("record_type", "A")]
            for entry in bruteforce_results
        ],
        empty_message="No additional hosts found via DNS brute force.",
        colspan=3,
    )

    # Build Unified Interactive Inventory rows
    unified_rows_rendered: List[str] = []
    added_set = set(diff_summary.get("added", [])) if diff_summary else set()
    for rec in records:
        host = rec["hostname"]
        ip_display = rec.get("ip") or "—"
        if rec.get("ipv6") and rec.get("ipv6") != rec.get("ip"):
            ip_display = f"{ip_display} / {rec['ipv6']}"
        rtype = rec.get("record_type") or "—"
        cname = rec.get("cname_target") or "—"
        sources_list = rec.get("sources") or [passive_source]
        badges_html = " ".join(
            f'<span class="badge badge-source">{html.escape(s)}</span>'
            for s in sources_list
        )
        if host in added_set:
            badges_html += ' <span class="badge badge-new">NEW</span>'

        http_status = rec.get("http_status")
        if http_status:
            scheme = rec.get("scheme") or "HTTP"
            tls_days = rec.get("tls_days_remaining")
            tls_str = f" (TLS: {tls_days}d)" if tls_days is not None else ""
            sec_hdrs = ",".join(rec.get("security_headers") or [])
            hdr_str = f" [{sec_hdrs}]" if sec_hdrs else ""
            web_posture = f"{scheme} {http_status}{tls_str}{hdr_str}"
        else:
            web_posture = "—"

        warning = rec.get("hygiene_warning") or ""
        if warning:
            status_badge = (
                f'<span class="badge badge-danger">'
                f"{html.escape(warning)}</span>"
            )
        elif rec.get("ip") or rec.get("ipv6"):
            status_badge = '<span class="badge badge-ok">RESOLVED</span>'
        else:
            status_badge = '<span class="badge badge-muted">UNRESOLVED</span>'

        is_resolved = "1" if (rec.get("ip") or rec.get("ipv6")) else "0"
        is_cname = "1" if rtype == "CNAME" or cname != "—" else "0"
        is_multisource = "1" if len(sources_list) > 1 else "0"
        is_warning = "1" if warning else "0"

        unified_rows_rendered.append(
            f'<tr class="asset-row" '
            f'data-resolved="{is_resolved}" '
            f'data-cname="{is_cname}" '
            f'data-multisource="{is_multisource}" '
            f'data-warning="{is_warning}">'
            f"<td><strong>{html.escape(host)}</strong></td>"
            f"<td>{html.escape(ip_display)}</td>"
            f"<td>{html.escape(rtype)}</td>"
            f"<td>{html.escape(cname)}</td>"
            f"<td>{badges_html}</td>"
            f"<td>{html.escape(web_posture)}</td>"
            f"<td>{status_badge}</td>"
            f"</tr>"
        )

    unified_tbody = (
        "\n".join(unified_rows_rendered)
        if unified_rows_rendered
        else '<tr><td colspan="7" class="empty">No subdomains discovered.</td></tr>'
    )

    # Build Subnet Clustering rows
    subnet_groups = _group_by_subnet(records)
    subnet_rows_html = _table_rows(
        [
            [cidr, str(len(hosts)), ", ".join(hosts)]
            for cidr, hosts in subnet_groups.items()
        ],
        empty_message="No resolved IPv4/IPv6 subnets to cluster.",
        colspan=3,
    )

    # Build Root Domain DNS Posture section
    posture = dns_posture or {}
    spf_val = posture.get("spf_record") or "Missing (No v=spf1 TXT record)"
    dmarc_val = posture.get("dmarc_record") or "Missing (No _dmarc TXT record)"
    ns_val = ", ".join(posture.get("ns_records") or []) or "Not detected"
    mx_val = ", ".join(posture.get("mx_records") or []) or "Not detected"
    caa_val = ", ".join(posture.get("caa_records") or []) or "None configured"

    # Optional Diff Banner
    diff_section_html = ""
    if diff_summary is not None:
        added_str = ", ".join(diff_summary.get("added", [])) or "None"
        removed_str = ", ".join(diff_summary.get("removed", [])) or "None"
        diff_section_html = f"""
    <section>
        <h2>Attack-Surface Delta (Snapshot Diff)</h2>
        <table>
            <thead>
                <tr><th>Change Type</th><th>Count</th><th>Hostnames</th></tr>
            </thead>
            <tbody>
                <tr><td>Added (+)</td><td>{len(diff_summary.get("added", []))}</td><td>{html.escape(added_str)}</td></tr>
                <tr><td>Removed (-)</td><td>{len(diff_summary.get("removed", []))}</td><td>{html.escape(removed_str)}</td></tr>
                <tr><td>Unchanged (=)</td><td>{len(diff_summary.get("unchanged", []))}</td><td>{len(diff_summary.get("unchanged", []))} host(s)</td></tr>
            </tbody>
        </table>
    </section>
"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report - {html.escape(domain)}</title>
<style>
    :root {{
        --bg: #0f172a;
        --panel: #1e293b;
        --border: #334155;
        --text: #e2e8f0;
        --muted: #94a3b8;
        --accent: #38bdf8;
        --accent-2: #34d399;
        --warning: #fbbf24;
        --danger: #f87171;
        --row-alt: #16213a;
    }}

    * {{
        box-sizing: border-box;
    }}

    body {{
        margin: 0;
        padding: 0;
        background-color: var(--bg);
        color: var(--text);
        font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.5;
    }}

    .container {{
        max-width: 1120px;
        margin: 0 auto;
        padding: 40px 20px 60px;
    }}

    header.report-header {{
        border-bottom: 2px solid var(--accent);
        padding-bottom: 20px;
        margin-bottom: 30px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        flex-wrap: wrap;
        gap: 12px;
    }}

    header.report-header h1 {{
        margin: 0 0 6px 0;
        font-size: 28px;
        color: var(--accent);
    }}

    header.report-header p {{
        margin: 0;
        color: var(--muted);
        font-size: 14px;
    }}

    .stats {{
        display: flex;
        gap: 14px;
        flex-wrap: wrap;
        margin-bottom: 32px;
    }}

    .stat-card {{
        flex: 1;
        min-width: 155px;
        background-color: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 16px 18px;
    }}

    .stat-card .value {{
        font-size: 28px;
        font-weight: 700;
        color: var(--accent-2);
    }}

    .stat-card .value.warn {{
        color: var(--danger);
    }}

    .stat-card .label {{
        font-size: 12px;
        color: var(--muted);
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }}

    section {{
        margin-bottom: 36px;
    }}

    section h2 {{
        font-size: 18px;
        color: var(--text);
        border-left: 4px solid var(--accent);
        padding-left: 10px;
        margin-bottom: 14px;
    }}

    .controls-bar {{
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
        margin-bottom: 14px;
    }}

    .search-input {{
        flex: 1;
        min-width: 220px;
        background-color: var(--panel);
        border: 1px solid var(--border);
        color: var(--text);
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 14px;
    }}

    .filter-btn {{
        background-color: var(--panel);
        color: var(--muted);
        border: 1px solid var(--border);
        padding: 7px 12px;
        border-radius: 6px;
        font-size: 12px;
        cursor: pointer;
        font-weight: 600;
    }}

    .filter-btn.active, .filter-btn:hover {{
        border-color: var(--accent);
        color: var(--accent);
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
        background-color: var(--panel);
        border: 1px solid var(--border);
        border-radius: 8px;
        overflow: hidden;
    }}

    th, td {{
        text-align: left;
        padding: 10px 14px;
        font-size: 13px;
        border-bottom: 1px solid var(--border);
        vertical-align: middle;
    }}

    th {{
        background-color: #273449;
        color: var(--accent);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 0.05em;
        cursor: pointer;
        user-select: none;
    }}

    tr:nth-child(even) td {{
        background-color: var(--row-alt);
    }}

    td.empty {{
        color: var(--muted);
        font-style: italic;
        text-align: center;
    }}

    .badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        margin: 1px 2px;
    }}

    .badge-source {{
        background-color: rgba(56, 189, 248, 0.15);
        color: var(--accent);
        border: 1px solid rgba(56, 189, 248, 0.35);
    }}

    .badge-ok {{
        background-color: rgba(52, 211, 153, 0.15);
        color: var(--accent-2);
        border: 1px solid rgba(52, 211, 153, 0.35);
    }}

    .badge-new {{
        background-color: rgba(251, 191, 36, 0.2);
        color: var(--warning);
        border: 1px solid rgba(251, 191, 36, 0.45);
    }}

    .badge-danger {{
        background-color: rgba(248, 113, 113, 0.18);
        color: var(--danger);
        border: 1px solid rgba(248, 113, 113, 0.45);
    }}

    .badge-muted {{
        background-color: rgba(148, 163, 184, 0.12);
        color: var(--muted);
        border: 1px solid rgba(148, 163, 184, 0.25);
    }}

    footer {{
        color: var(--muted);
        font-size: 12px;
        text-align: center;
        margin-top: 40px;
        border-top: 1px solid var(--border);
        padding-top: 16px;
    }}
</style>
</head>
<body>
<div class="container">

    <header class="report-header">
        <div>
            <h1>Automated Recon Suite (v3) &mdash; Scan Report</h1>
            <p>Target domain: <strong>{html.escape(domain)}</strong> &nbsp;|&nbsp; Scanned: {html.escape(scan_time)}</p>
        </div>
        <p>Passive Engine(s): <strong>{html.escape(passive_source)}</strong></p>
    </header>

    <div class="stats">
        <div class="stat-card">
            <div class="value">{len(total_unique_subdomains)}</div>
            <div class="label">Total Subdomains</div>
        </div>
        <div class="stat-card">
            <div class="value">{resolved_count}</div>
            <div class="label">Resolved Live Hosts</div>
        </div>
        <div class="stat-card">
            <div class="value">{len(passive_subdomains)}</div>
            <div class="label">Passive Results</div>
        </div>
        <div class="stat-card">
            <div class="value">{len(bruteforce_results)}</div>
            <div class="label">DNS Brute-Force Hits</div>
        </div>
        <div class="stat-card">
            <div class="value {'warn' if hygiene_warnings else ''}">{len(hygiene_warnings)}</div>
            <div class="label">Dangling DNS Alerts</div>
        </div>
    </div>

{diff_section_html}

    <section>
        <h2>Unified Attack-Surface &amp; DNS Hygiene Inventory</h2>
        <div class="controls-bar">
            <input type="text" id="assetSearch" class="search-input" placeholder="Search hostname, IP, CNAME, or OSINT source..." onkeyup="filterAssets()">
            <button class="filter-btn active" onclick="setCategoryFilter('all', this)">All ({len(records)})</button>
            <button class="filter-btn" onclick="setCategoryFilter('resolved', this)">Resolved ({resolved_count})</button>
            <button class="filter-btn" onclick="setCategoryFilter('cname', this)">CNAMEs</button>
            <button class="filter-btn" onclick="setCategoryFilter('multisource', this)">Multi-Source</button>
            <button class="filter-btn" onclick="setCategoryFilter('warning', this)">Hygiene Alerts ({len(hygiene_warnings)})</button>
        </div>
        <table id="unifiedTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Hostname &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(1)">IP Address (v4 / v6) &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(2)">Record &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(3)">CNAME Target &#x25B4;&#x25BE;</th>
                    <th>Discovery Sources</th>
                    <th>HTTP / TLS Posture</th>
                    <th>Hygiene Status</th>
                </tr>
            </thead>
            <tbody>
{unified_tbody}
            </tbody>
        </table>
    </section>

    <section>
        <h2>Root Domain DNS Security Posture ({html.escape(domain)})</h2>
        <table>
            <thead>
                <tr><th>Control / Record</th><th>Observed Configuration</th></tr>
            </thead>
            <tbody>
                <tr><td>Name Servers (NS)</td><td>{html.escape(ns_val)}</td></tr>
                <tr><td>Mail Servers (MX)</td><td>{html.escape(mx_val)}</td></tr>
                <tr><td>SPF Policy (TXT)</td><td>{html.escape(spf_val)}</td></tr>
                <tr><td>DMARC Policy (_dmarc)</td><td>{html.escape(dmarc_val)}</td></tr>
                <tr><td>Certificate Authority Auth (CAA)</td><td>{html.escape(caa_val)}</td></tr>
            </tbody>
        </table>
    </section>

    <section>
        <h2>IP Subnet &amp; Infrastructure Clustering</h2>
        <table>
            <thead>
                <tr><th>Subnet CIDR</th><th>Host Count</th><th>Associated Subdomains</th></tr>
            </thead>
            <tbody>
{subnet_rows_html}
            </tbody>
        </table>
    </section>

    <section>
        <h2>Passive Enumeration Results</h2>
        <table>
            <thead>
                <tr><th>Subdomain</th><th>Source</th></tr>
            </thead>
            <tbody>
{passive_rows_html}
            </tbody>
        </table>
    </section>

    <section>
        <h2>DNS Brute-Force Results</h2>
        <table>
            <thead>
                <tr><th>Hostname</th><th>IP Address</th><th>Record Type</th></tr>
            </thead>
            <tbody>
{bruteforce_rows_html}
            </tbody>
        </table>
    </section>

    <footer>
        Generated by Automated Recon Suite (v3.0) &mdash; for authorized security testing and defensive asset management only.
    </footer>

</div>
<script>
let currentFilter = 'all';

function setCategoryFilter(filterName, btnEl) {{
    currentFilter = filterName;
    const buttons = document.querySelectorAll('.filter-btn');
    buttons.forEach(b => b.classList.remove('active'));
    btnEl.classList.add('active');
    filterAssets();
}}

function filterAssets() {{
    const query = (document.getElementById('assetSearch').value || '').toLowerCase();
    const rows = document.querySelectorAll('#unifiedTable tbody tr.asset-row');
    rows.forEach(row => {{
        const textMatch = row.innerText.toLowerCase().includes(query);
        let catMatch = true;
        if (currentFilter === 'resolved') catMatch = row.dataset.resolved === '1';
        else if (currentFilter === 'cname') catMatch = row.dataset.cname === '1';
        else if (currentFilter === 'multisource') catMatch = row.dataset.multisource === '1';
        else if (currentFilter === 'warning') catMatch = row.dataset.warning === '1';
        row.style.display = (textMatch && catMatch) ? '' : 'none';
    }});
}}

let sortDirection = true;
function sortTable(colIdx) {{
    const tbody = document.querySelector('#unifiedTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr.asset-row'));
    if (!rows.length) return;
    sortDirection = !sortDirection;
    rows.sort((a, b) => {{
        const aText = a.children[colIdx].innerText.trim().toLowerCase();
        const bText = b.children[colIdx].innerText.trim().toLowerCase();
        return sortDirection ? aText.localeCompare(bText) : bText.localeCompare(aText);
    }});
    rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>
"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stem = filename_prefix or domain
    report_file = output_path / f"{stem}.html"
    report_file.write_text(html_content, encoding="utf-8")
    return str(report_file)


def _render_reportlab_pdf(
    pdf_file: Path,
    domain: str,
    scan_time: str,
    total_unique_subdomains: List[str],
    passive_rows_data: List[List[str]],
    bruteforce_results: List[Dict[str, str]],
) -> None:
    """Fallback PDF generator using ReportLab Platypus tables."""
    doc = SimpleDocTemplate(
        str(pdf_file),
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    story: List[Any] = []

    story.append(Paragraph(f"Automated Recon Suite (v3) - Scan Report: {html.escape(domain)}", styles["Title"]))
    story.append(Paragraph(f"Scanned: {html.escape(scan_time)} | Total Unique Subdomains: {len(total_unique_subdomains)}", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Passive Enumeration Results", styles["Heading2"]))
    p_table_data = [["Subdomain", "Source(s)"]]
    if passive_rows_data:
        p_table_data.extend(passive_rows_data)
    else:
        p_table_data.append(["No passive subdomains found.", "-"])

    p_table = Table(p_table_data, colWidths=[280, 220])
    p_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]
        )
    )
    story.append(p_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("DNS Brute-Force Results", styles["Heading2"]))
    bf_table_data = [["Hostname", "IP Address", "Record Type"]]
    if bruteforce_results:
        for entry in bruteforce_results:
            bf_table_data.append(
                [
                    entry["hostname"],
                    entry["ip"],
                    entry.get("record_type", "A"),
                ]
            )
    else:
        bf_table_data.append(["No additional hosts found via DNS brute force.", "-", "-"])

    bf_table = Table(bf_table_data, colWidths=[230, 160, 110])
    bf_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]
        )
    )
    story.append(bf_table)
    doc.build(story)


def generate_pdf_report(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    output_dir: str = "reports",
    passive_source: str = "Sublist3r",
    passive_source_map: Optional[Dict[str, List[str]]] = None,
    filename_prefix: Optional[str] = None,
) -> str:
    """
    Build a print-friendly A4 PDF recon report for ``domain``.

    Supports ``xhtml2pdf``, ``weasyprint``, and ``reportlab`` so PDF output
    works reliably across environments.
    """
    if not PDF_AVAILABLE:
        raise RuntimeError(
            "No PDF engine installed. Install xhtml2pdf, weasyprint, or reportlab."
        )

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    bruteforce_hostnames = {entry["hostname"] for entry in bruteforce_results}
    total_unique_subdomains = sorted(set(passive_subdomains) | bruteforce_hostnames)

    passive_rows_data: List[List[str]] = []
    for sub in passive_subdomains:
        if passive_source_map and sub in passive_source_map:
            src_str = ", ".join(passive_source_map[sub])
        else:
            src_str = passive_source
        passive_rows_data.append([sub, src_str])

    passive_rows_html = _table_rows(
        passive_rows_data,
        empty_message="No passive subdomains found.",
        colspan=2,
    )

    bruteforce_rows_html = _table_rows(
        [
            [entry["hostname"], entry["ip"], entry.get("record_type", "A")]
            for entry in bruteforce_results
        ],
        empty_message="No additional hosts found via DNS brute force.",
        colspan=3,
    )

    pdf_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - {html.escape(domain)}</title>
<style>
    @page {{
        size: A4;
        margin: 2cm;
    }}
    body {{
        font-family: Helvetica, Arial, sans-serif;
        font-size: 11px;
        color: #1a1a1a;
        line-height: 1.4;
    }}
    h1 {{
        font-size: 22px;
        color: #1e40af;
        border-bottom: 2px solid #3b82f6;
        padding-bottom: 8px;
        margin-bottom: 4px;
    }}
    .meta {{
        color: #6b7280;
        font-size: 11px;
        margin-bottom: 20px;
    }}
    .stats-table {{
        width: 100%;
        margin-bottom: 20px;
    }}
    .stats-table td {{
        text-align: center;
        padding: 12px;
        background-color: #f0f9ff;
        border: 1px solid #bfdbfe;
    }}
    .stat-value {{
        font-size: 24px;
        font-weight: bold;
        color: #059669;
    }}
    .stat-label {{
        font-size: 10px;
        color: #6b7280;
        text-transform: uppercase;
    }}
    h2 {{
        font-size: 14px;
        color: #1e40af;
        border-left: 3px solid #3b82f6;
        padding-left: 8px;
        margin-top: 20px;
        margin-bottom: 10px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 16px;
    }}
    th {{
        background-color: #1e40af;
        color: white;
        padding: 8px 10px;
        text-align: left;
        font-size: 10px;
        text-transform: uppercase;
    }}
    td {{
        padding: 6px 10px;
        border-bottom: 1px solid #e5e7eb;
        font-size: 10px;
    }}
    tr:nth-child(even) td {{
        background-color: #f9fafb;
    }}
    .empty {{
        color: #9ca3af;
        font-style: italic;
        text-align: center;
    }}
    .footer {{
        color: #9ca3af;
        font-size: 9px;
        text-align: center;
        margin-top: 30px;
        border-top: 1px solid #e5e7eb;
        padding-top: 10px;
    }}
</style>
</head>
<body>
    <h1>Automated Recon Suite (v3) &mdash; Scan Report</h1>
    <p class="meta">Target: <strong>{html.escape(domain)}</strong> | Scanned: {html.escape(scan_time)}</p>

    <table class="stats-table">
        <tr>
            <td>
                <div class="stat-value">{len(total_unique_subdomains)}</div>
                <div class="stat-label">Total Subdomains</div>
            </td>
            <td>
                <div class="stat-value">{len(passive_subdomains)}</div>
                <div class="stat-label">Passive Results</div>
            </td>
            <td>
                <div class="stat-value">{len(bruteforce_results)}</div>
                <div class="stat-label">DNS Brute-Force Hits</div>
            </td>
        </tr>
    </table>

    <h2>Passive Enumeration Results</h2>
    <table>
        <thead>
            <tr><th>Subdomain</th><th>Source</th></tr>
        </thead>
        <tbody>
{passive_rows_html}
        </tbody>
    </table>

    <h2>DNS Brute-Force Results</h2>
    <table>
        <thead>
            <tr><th>Hostname</th><th>IP Address</th><th>Record Type</th></tr>
        </thead>
        <tbody>
{bruteforce_rows_html}
        </tbody>
    </table>

    <p class="footer">
        Generated by Automated Recon Suite (v3.0) &mdash; for authorized security testing only.
    </p>
</body>
</html>
"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stem = filename_prefix or domain
    pdf_file = output_path / f"{stem}.pdf"

    if _XHTML2PDF_AVAILABLE:
        with open(pdf_file, "wb") as f:
            pisa_status = pisa.CreatePDF(pdf_html, dest=f)
        if pisa_status.err:
            raise RuntimeError(f"PDF generation failed with {pisa_status.err} error(s).")
    elif _REPORTLAB_AVAILABLE:
        _render_reportlab_pdf(
            pdf_file=pdf_file,
            domain=domain,
            scan_time=scan_time,
            total_unique_subdomains=total_unique_subdomains,
            passive_rows_data=passive_rows_data,
            bruteforce_results=bruteforce_results,
        )
    elif _WEASYPRINT_AVAILABLE:
        weasyprint.HTML(string=pdf_html).write_pdf(str(pdf_file))

    return str(pdf_file)


def generate_json_report(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    output_dir: str = "reports",
    passive_source: str = "Sublist3r",
    passive_source_map: Optional[Dict[str, List[str]]] = None,
    enriched_records: Optional[List[Dict[str, Any]]] = None,
    dns_posture: Optional[Dict[str, Any]] = None,
    diff_summary: Optional[Dict[str, List[str]]] = None,
    filename_prefix: Optional[str] = None,
) -> str:
    """Export machine-readable JSON recon report for CI/CD pipelines and SIEMs."""
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    records = (
        enriched_records
        if enriched_records is not None
        else _synthesize_enriched_records(
            passive_subdomains,
            bruteforce_results,
            passive_source,
            passive_source_map=passive_source_map,
        )
    )

    payload = {
        "schema_version": "3.0",
        "domain": domain,
        "scanned_at": scan_time,
        "passive_source_summary": passive_source,
        "statistics": {
            "total_unique_subdomains": len(records),
            "resolved_hosts": sum(1 for r in records if r.get("ip") or r.get("ipv6")),
            "passive_count": len(passive_subdomains),
            "bruteforce_count": len(bruteforce_results),
            "dangling_cname_alerts": sum(1 for r in records if r.get("hygiene_warning")),
        },
        "dns_security_posture": dns_posture or {},
        "diff_summary": diff_summary,
        "unified_assets": records,
        "passive_subdomains": passive_subdomains,
        "bruteforce_results": bruteforce_results,
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stem = filename_prefix or domain
    json_file = output_path / f"{stem}.json"
    json_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(json_file)


def generate_csv_report(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    output_dir: str = "reports",
    passive_source: str = "Sublist3r",
    passive_source_map: Optional[Dict[str, List[str]]] = None,
    enriched_records: Optional[List[Dict[str, Any]]] = None,
    filename_prefix: Optional[str] = None,
) -> str:
    """Export unified subdomain asset inventory to a CSV file."""
    records = (
        enriched_records
        if enriched_records is not None
        else _synthesize_enriched_records(
            passive_subdomains,
            bruteforce_results,
            passive_source,
            passive_source_map=passive_source_map,
        )
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stem = filename_prefix or domain
    csv_file = output_path / f"{stem}.csv"

    fieldnames = [
        "hostname",
        "ip",
        "ipv6",
        "record_type",
        "cname_target",
        "sources",
        "status",
        "http_status",
        "tls_days_remaining",
        "hygiene_warning",
    ]
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow(
                {
                    "hostname": rec.get("hostname", ""),
                    "ip": rec.get("ip", ""),
                    "ipv6": rec.get("ipv6", ""),
                    "record_type": rec.get("record_type", ""),
                    "cname_target": rec.get("cname_target", ""),
                    "sources": "; ".join(rec.get("sources") or []),
                    "status": rec.get("status", ""),
                    "http_status": rec.get("http_status") or "",
                    "tls_days_remaining": (
                        rec.get("tls_days_remaining")
                        if rec.get("tls_days_remaining") is not None
                        else ""
                    ),
                    "hygiene_warning": rec.get("hygiene_warning", ""),
                }
            )
    return str(csv_file)
