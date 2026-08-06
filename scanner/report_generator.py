"""HTML security report generator.

Provides the HTMLReportGenerator class that creates a professional,
mobile-responsive HTML report from one or more ScanResult objects.
"""

import html
from datetime import datetime
from pathlib import Path
from typing import List

from scanner.models.scan_result import ScanResult


class HTMLReportGenerator:
    """Generates a professional HTML security report from ScanResults.

    Supports multiple scanners/tools. Uses only inline CSS for portability
    and requires no external libraries.
    """

    # Severity color mapping.
    SEVERITY_COLORS = {
        "CRITICAL": "#8B0000",  # Dark red
        "HIGH": "#DC3545",      # Red
        "MEDIUM": "#FD7E14",    # Orange
        "LOW": "#0D6EFD",       # Blue
    }

    # Severity background colors (lighter variants for table rows).
    SEVERITY_BG = {
        "CRITICAL": "#FFE0E0",
        "HIGH": "#FFE0E0",
        "MEDIUM": "#FFF3CD",
        "LOW": "#E2F0FF",
    }

    #: Tool name recognised as the flat-file dependency scanner.
    TRIVY_TOOL_NAME: str = "Trivy"

    def generate(
        self,
        results: List[ScanResult],
        passed: bool,
        reason: str,
        output_path: Path,
    ) -> Path:
        """Generate an HTML report file.

        Args:
            results: A list of ScanResult objects containing findings.
            passed: Whether the scans passed the policy.
            reason: Human-readable reason for the policy decision.
            output_path: Where to write the HTML file.

        Returns:
            The path to the generated HTML file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_text = "PASSED" if passed else "FAILED"
        status_color = "#28A745" if passed else "#DC3545"
        tool_names = ", ".join(r.tool for r in results)

        html_content = self._build_html(
            results=results,
            passed=passed,
            reason=reason,
            timestamp=timestamp,
            status_text=status_text,
            status_color=status_color,
            tool_names=tool_names,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _build_html(
        self,
        results: List[ScanResult],
        passed: bool,
        reason: str,
        timestamp: str,
        status_text: str,
        status_color: str,
        tool_names: str,
    ) -> str:
        """Build the complete HTML document as a string."""
        summary_cards = self._render_summary_cards(results)
        sections = self._render_tool_sections(results)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {html.escape(tool_names)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
                         Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: #fff;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-left h1 {{
            font-size: 24px;
            color: #1a1a2e;
            margin-bottom: 4px;
        }}
        .header-left .subtitle {{
            font-size: 14px;
            color: #6c757d;
        }}
        .status-badge {{
            display: inline-block;
            padding: 8px 24px;
            border-radius: 20px;
            font-size: 18px;
            font-weight: 700;
            color: #fff;
            background: {status_color};
            text-align: center;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #fff;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            text-align: center;
        }}
        .card .card-value {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        .card .card-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #6c757d;
        }}
        .card .card-tool {{
            font-size: 11px;
            color: #adb5bd;
            margin-top: 2px;
        }}
        .card-critical .card-value {{ color: #8B0000; }}
        .card-high .card-value {{ color: #DC3545; }}
        .card-medium .card-value {{ color: #FD7E14; }}
        .card-low .card-value {{ color: #0D6EFD; }}
        .card-total .card-value {{ color: #1a1a2e; }}
        .section {{
            background: #fff;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }}
        .section h2 {{
            font-size: 18px;
            color: #1a1a2e;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #f0f0f0;
        }}
        .reason {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 14px;
            color: #856404;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            background: #f8f9fa;
            text-align: left;
            padding: 12px 8px;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 10px 8px;
            border-bottom: 1px solid #e9ecef;
            vertical-align: top;
        }}
        tr:hover {{ background: #f8f9fa; }}
        .severity-tag {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            color: #fff;
        }}
        .finding-file {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 13px;
            color: #6c757d;
            word-break: break-all;
        }}
        .finding-id {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 12px;
            color: #6c757d;
            word-break: break-all;
        }}
        .pkg-name {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 13px;
        }}
        .version {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 12px;
            color: #6c757d;
        }}
        .footer {{
            text-align: center;
            font-size: 13px;
            color: #6c757d;
            padding: 20px 0;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px 20px;
            color: #6c757d;
            font-size: 16px;
        }}
        .no-findings .icon {{ font-size: 48px; margin-bottom: 12px; }}
        @media (max-width: 600px) {{
            .header {{ flex-direction: column; text-align: center; }}
            .cards {{ grid-template-columns: repeat(2, 1fr); }}
            table {{ font-size: 13px; }}
            th, td {{ padding: 8px 4px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h1>Security Scan Report</h1>
                <div class="subtitle">
                    Tools: {html.escape(tool_names)} &nbsp;|&nbsp;
                    Scan Date: {html.escape(timestamp)}
                </div>
            </div>
            <div class="status-badge">{html.escape(status_text)}</div>
        </div>

        <!-- Policy Reason -->
        <div class="reason">
            <strong>Policy Result:</strong> {html.escape(reason)}
        </div>

        <!-- Summary Cards -->
        <div class="cards">
            {summary_cards}
        </div>

        <!-- Per-tool Sections -->
        {sections}

        <!-- Footer -->
        <div class="footer">
            Generated by SAST SCA Pipeline &mdash; {html.escape(timestamp)}
        </div>
    </div>
</body>
</html>"""

    def _render_summary_cards(self, results: List[ScanResult]) -> str:
        """Render the summary statistics cards for all tools."""
        cards_html = ""
        for result in results:
            metrics = [
                ("Critical", result.critical, "card-critical"),
                ("High", result.high, "card-high"),
                ("Medium", result.medium, "card-medium"),
                ("Low", result.low, "card-low"),
                ("Total", result.total, "card-total"),
            ]
            for label, value, css_class in metrics:
                cards_html += f"""
            <div class="card {css_class}">
                <div class="card-value">{value}</div>
                <div class="card-label">{label}</div>
                <div class="card-tool">{html.escape(result.tool)}</div>
            </div>"""
        return cards_html

    def _render_tool_sections(self, results: List[ScanResult]) -> str:
        """Render a findings section for each scan tool."""
        sections = ""
        for result in results:
            if result.tool == self.TRIVY_TOOL_NAME:
                sections += self._render_trivy_section(result)
            else:
                sections += self._render_generic_section(result)
        return sections

    def _render_trivy_section(self, result: ScanResult) -> str:
        """Render the Dependency Vulnerabilities section for Trivy."""
        heading = "Dependency Vulnerabilities (Trivy)"
        table = self._render_trivy_table(result.findings)
        return f"""<div class="section">
            <h2>{html.escape(heading)}</h2>
            {table}
        </div>"""

    def _render_trivy_table(self, findings: List[dict]) -> str:
        """Render a table of Trivy dependency vulnerabilities."""
        if not findings:
            return (
                '<div class="no-findings">'
                '<div class="icon">&#9989;</div>'
                "<div>No dependency vulnerabilities detected.</div>"
                "</div>"
            )

        rows = ""
        for idx, f in enumerate(findings, 1):
            severity = f.get("severity", "LOW").upper()
            sev_color = self.SEVERITY_COLORS.get(severity, "#6c757d")
            sev_bg = self.SEVERITY_BG.get(severity, "#f8f9fa")

            cve = html.escape(f.get("id", "unknown"))
            package = html.escape(f.get("package", "unknown"))
            installed = html.escape(f.get("installed_version", "unknown"))
            fixed = html.escape(f.get("fixed_version", "N/A"))
            title = html.escape(f.get("title", ""))
            description = html.escape(f.get("description", ""))
            target = html.escape(f.get("file", "unknown"))

            message = title or description

            rows += f"""
            <tr style="background: {sev_bg};">
                <td>{idx}</td>
                <td>
                    <span class="severity-tag" style="background: {sev_color};">
                        {severity}
                    </span>
                </td>
                <td>
                    <div class="finding-id">{cve}</div>
                    <div style="font-size: 12px; color: #6c757d;">{target}</div>
                </td>
                <td><div class="pkg-name">{package}</div></td>
                <td><div class="version">{installed}</div></td>
                <td><div class="version">{fixed}</div></td>
                <td>
                    <div>{message}</div>
                </td>
            </tr>"""

        return f"""<div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px;">#</th>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 200px;">CVE</th>
                        <th>Package</th>
                        <th style="width: 130px;">Installed</th>
                        <th style="width: 130px;">Fixed</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"""

    def _render_generic_section(self, result: ScanResult) -> str:
        """Render a generic findings section (e.g. Semgrep)."""
        heading = f"{result.tool} Findings"
        table = self._render_findings_table(result.findings)
        return f"""<div class="section">
            <h2>{html.escape(heading)}</h2>
            {table}
        </div>"""

    def _render_findings_table(self, findings: List[dict]) -> str:
        """Render the generic findings detail table or a no-findings message."""
        if not findings:
            return (
                '<div class="no-findings">'
                '<div class="icon">&#9989;</div>'
                "<div>No security findings detected.</div>"
                "</div>"
            )

        rows = ""
        for idx, f in enumerate(findings, 1):
            severity = f.get("severity", "LOW").upper()
            sev_color = self.SEVERITY_COLORS.get(severity, "#6c757d")
            sev_bg = self.SEVERITY_BG.get(severity, "#f8f9fa")

            file_path = html.escape(f.get("file", "unknown"))
            message = html.escape(f.get("message", ""))
            finding_id = html.escape(f.get("id", "unknown"))
            line = f.get("line", 0)
            owasp = html.escape(f.get("owasp", "N/A"))
            cwe = html.escape(f.get("cwe", "N/A"))

            rows += f"""
            <tr style="background: {sev_bg};">
                <td>{idx}</td>
                <td>
                    <span class="severity-tag" style="background: {sev_color};">
                        {severity}
                    </span>
                </td>
                <td style="font-size: 13px;">{owasp}</td>
                <td style="font-size: 13px;">{cwe}</td>
                <td>
                    <div>{message}</div>
                    <div class="finding-id">{finding_id}</div>
                </td>
                <td>
                    <div class="finding-file">{file_path}</div>
                    <div style="font-size: 12px; color: #6c757d;">Line {line}</div>
                </td>
            </tr>"""

        return f"""<div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px;">#</th>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 140px;">OWASP</th>
                        <th style="width: 180px;">CWE</th>
                        <th>Message</th>
                        <th style="width: 280px;">Location</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"""
