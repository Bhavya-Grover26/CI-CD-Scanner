"""HTML security report generator.

Provides the HTMLReportGenerator class that creates a professional,
mobile-responsive HTML report from scan results.
"""

import html
from datetime import datetime
from pathlib import Path
from typing import List

from scanner.models.scan_result import ScanResult


class HTMLReportGenerator:
    """Generates a professional HTML security report from a ScanResult.

    Uses only inline CSS for portability and requires no external libraries.
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

    def generate(
        self,
        result: ScanResult,
        passed: bool,
        reason: str,
        output_path: Path,
    ) -> Path:
        """Generate an HTML report file.

        Args:
            result: The ScanResult containing all findings.
            passed: Whether the scan passed the policy.
            reason: Human-readable reason for the policy decision.
            output_path: Where to write the HTML file.

        Returns:
            The path to the generated HTML file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_text = "PASSED" if passed else "FAILED"
        status_color = "#28A745" if passed else "#DC3545"

        html_content = self._build_html(
            result=result,
            passed=passed,
            reason=reason,
            timestamp=timestamp,
            status_text=status_text,
            status_color=status_color,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _build_html(
        self,
        result: ScanResult,
        passed: bool,
        reason: str,
        timestamp: str,
        status_text: str,
        status_color: str,
    ) -> str:
        """Build the complete HTML document as a string."""
        summary_cards = self._render_summary_cards(result)
        findings_table = self._render_findings_table(result.findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {html.escape(result.tool)}</title>
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
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        .card .card-label {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #6c757d;
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
                    Tool: {html.escape(result.tool)} &nbsp;|&nbsp;
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

        <!-- Findings Detail -->
        <div class="section">
            <h2>Detailed Findings</h2>
            {findings_table}
        </div>

        <!-- Footer -->
        <div class="footer">
            Generated by SAST SCA Pipeline &mdash; {html.escape(timestamp)}
        </div>
    </div>
</body>
</html>"""

    def _render_summary_cards(self, result: ScanResult) -> str:
        """Render the summary statistics cards."""
        metrics = [
            ("Critical", result.critical, "card-critical"),
            ("High", result.high, "card-high"),
            ("Medium", result.medium, "card-medium"),
            ("Low", result.low, "card-low"),
            ("Total", result.total, "card-total"),
        ]
        cards_html = ""
        for label, value, css_class in metrics:
            cards_html += f"""
            <div class="card {css_class}">
                <div class="card-value">{value}</div>
                <div class="card-label">{label}</div>
            </div>"""
        return cards_html

    def _render_findings_table(self, findings: List[dict]) -> str:
        """Render the findings detail table or a no-findings message."""
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

