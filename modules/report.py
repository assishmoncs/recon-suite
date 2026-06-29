"""
modules/report.py

Generates scan reports in HTML and/or PDF format.

The report includes DNS record types (A / CNAME) for brute-forced
entries and labels passive subdomains with their discovery source
(e.g. "Sublist3r", "crt.sh").
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from modules.utils import print_info, print_success, print_warning

try:
    from xhtml2pdf import pisa  # type: ignore
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


def _table_rows(rows: List[List[str]], empty_message: str, colspan: int = 1) -> str:
    """
    Build <tr> HTML for a table body. All cell content is HTML-escaped
    to keep the report safe even if a "subdomain" turned out to contain
    unexpected characters.
    """
    if not rows:
        return f'<tr><td colspan="{colspan}" class="empty">{html.escape(empty_message)}</td></tr>'

    rendered_rows = []
    for row in rows:
        cells = "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row)
        rendered_rows.append(f"<tr>{cells}</tr>")
    return "\n".join(rendered_rows)


def generate_report(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    output_dir: str = "reports",
    passive_source: str = "Sublist3r",
) -> str:
    """
    Build an HTML recon report for ``domain`` and write it to disk.

    Args:
        domain: The target domain that was scanned.
        passive_subdomains: Subdomains found via passive enumeration
            (Sublist3r / crt.sh fallback).
        bruteforce_results: List of dicts with keys ``"hostname"``,
            ``"ip"``, and optionally ``"record_type"`` found via DNS
            brute forcing.
        output_dir: Directory the report should be written into.
        passive_source: Label for the passive enumeration engine that
            produced results (e.g. ``"Sublist3r"``, ``"crt.sh"``).

    Returns:
        The path (as a string) to the generated ``.html`` report file.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    bruteforce_hostnames = {entry["hostname"] for entry in bruteforce_results}
    total_unique_subdomains = sorted(set(passive_subdomains) | bruteforce_hostnames)

    passive_rows_html = _table_rows(
        [[sub, passive_source] for sub in passive_subdomains],
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

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
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
        max-width: 900px;
        margin: 0 auto;
        padding: 40px 20px 60px;
    }}

    header.report-header {{
        border-bottom: 2px solid var(--accent);
        padding-bottom: 20px;
        margin-bottom: 30px;
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
        gap: 16px;
        flex-wrap: wrap;
        margin-bottom: 36px;
    }}

    .stat-card {{
        flex: 1;
        min-width: 160px;
        background-color: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 18px 20px;
    }}

    .stat-card .value {{
        font-size: 28px;
        font-weight: 700;
        color: var(--accent-2);
    }}

    .stat-card .label {{
        font-size: 13px;
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
        font-size: 14px;
        border-bottom: 1px solid var(--border);
    }}

    th {{
        background-color: #273449;
        color: var(--accent);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 12px;
        letter-spacing: 0.05em;
    }}

    tr:nth-child(even) td {{
        background-color: var(--row-alt);
    }}

    td.empty {{
        color: var(--muted);
        font-style: italic;
        text-align: center;
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
        <h1>Automated Recon Tool &mdash; Scan Report</h1>
        <p>Target domain: <strong>{html.escape(domain)}</strong> &nbsp;|&nbsp; Scanned: {html.escape(scan_time)}</p>
    </header>

    <div class="stats">
        <div class="stat-card">
            <div class="value">{len(total_unique_subdomains)}</div>
            <div class="label">Total Subdomains</div>
        </div>
        <div class="stat-card">
            <div class="value">{len(passive_subdomains)}</div>
            <div class="label">Passive Results</div>
        </div>
        <div class="stat-card">
            <div class="value">{len(bruteforce_results)}</div>
            <div class="label">DNS Brute-Force Hits</div>
        </div>
    </div>

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
        Generated by Automated Recon Tool (v2) &mdash; for authorized security testing only.
    </footer>

</div>
</body>
</html>
"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report_file = output_path / f"{domain}.html"
    report_file.write_text(html_content, encoding="utf-8")

    return str(report_file)


def generate_pdf_report(
    domain: str,
    passive_subdomains: List[str],
    bruteforce_results: List[Dict[str, str]],
    output_dir: str = "reports",
    passive_source: str = "Sublist3r",
) -> str:
    """
    Build a PDF recon report for ``domain`` using xhtml2pdf.

    Generates a print-friendly version of the HTML report as a PDF file.
    Requires xhtml2pdf to be installed.

    Args:
        domain: The target domain that was scanned.
        passive_subdomains: Subdomains found via passive enumeration.
        bruteforce_results: List of dicts with brute-force results.
        output_dir: Directory the report should be written into.
        passive_source: Label for the passive enumeration engine.

    Returns:
        The path (as a string) to the generated ``.pdf`` report file.

    Raises:
        RuntimeError: If xhtml2pdf is not installed.
    """
    if not PDF_AVAILABLE:
        raise RuntimeError(
            "xhtml2pdf is not installed. Install it with: pip install xhtml2pdf"
        )

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    bruteforce_hostnames = {entry["hostname"] for entry in bruteforce_results}
    total_unique_subdomains = sorted(set(passive_subdomains) | bruteforce_hostnames)

    passive_rows_html = _table_rows(
        [[sub, passive_source] for sub in passive_subdomains],
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

    # PDF-friendly HTML (light theme, simpler CSS for xhtml2pdf compatibility)
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

    <h1>Automated Recon Tool &mdash; Scan Report</h1>
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
        Generated by Automated Recon Tool (v2) &mdash; for authorized security testing only.
    </p>

</body>
</html>
"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    pdf_file = output_path / f"{domain}.pdf"

    with open(pdf_file, "wb") as f:
        pisa_status = pisa.CreatePDF(pdf_html, dest=f)

    if pisa_status.err:
        raise RuntimeError(f"PDF generation failed with {pisa_status.err} error(s).")

    return str(pdf_file)
