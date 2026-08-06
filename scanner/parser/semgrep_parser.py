"""Semgrep JSON results parser.

Provides the SemgrepParser class that reads Semgrep JSON output
and converts it to a ScanResult model.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from scanner.models.scan_result import ScanResult


class SemgrepParserError(Exception):
    """Custom exception for SemgrepParser failures."""

    pass


# Mapping from Semgrep severity levels to our normalized levels.
SEVERITY_MAP: Dict[str, str] = {
    "ERROR": "CRITICAL",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class SemgrepParser:
    """Parses Semgrep JSON output into a ScanResult model.

    Usage:
        parser = SemgrepParser()
        result = parser.parse(Path("reports/results.json"))
    """

    def parse(self, results_path: Path) -> ScanResult:
        """Read and parse a Semgrep JSON results file.

        Args:
            results_path: Path to the Semgrep results.json file.

        Returns:
            A ScanResult instance with normalised findings.

        Raises:
            SemgrepParserError: If the file is missing, contains invalid JSON,
                                or is not valid Semgrep output.
        """
        if not results_path.exists():
            raise SemgrepParserError(
                f"Results file not found: {results_path}"
            )

        try:
            with open(results_path, "r", encoding="utf-8") as f:
                data: Dict[str, Any] = json.load(f)
        except json.JSONDecodeError as exc:
            raise SemgrepParserError(
                f"Invalid JSON in results file: {exc}"
            ) from None

        if "results" not in data:
            raise SemgrepParserError(
                "The JSON file does not appear to be valid Semgrep output "
                "(missing 'results' key)."
            )

        raw_results: List[Dict[str, Any]] = data.get("results", [])

        findings: List[Dict] = []
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for item in raw_results:
            # Extract raw severity from Semgrep output.
            extra: Dict[str, Any] = item.get("extra", {})
            raw_severity: str = extra.get("severity", "INFO")

            # Normalise: ERROR → CRITICAL, WARNING → MEDIUM, INFO → LOW.
            normalized: str = SEVERITY_MAP.get(raw_severity.upper(), "LOW")

            if normalized == "CRITICAL":
                severity_counts["CRITICAL"] += 1
            elif normalized == "MEDIUM":
                severity_counts["MEDIUM"] += 1
            else:
                severity_counts["LOW"] += 1

            # Extract metadata for OWASP and CWE.
            # Semgrep may return these as a list or as a single string.
            metadata: Dict[str, Any] = extra.get("metadata", {})
            raw_owasp = metadata.get("owasp", "N/A")
            raw_cwe = metadata.get("cwe", "N/A")

            owasp: str = raw_owasp[0] if isinstance(raw_owasp, list) and raw_owasp else (
                raw_owasp if isinstance(raw_owasp, str) else "N/A"
            )
            cwe: str = raw_cwe[0] if isinstance(raw_cwe, list) and raw_cwe else (
                raw_cwe if isinstance(raw_cwe, str) else "N/A"
            )

            finding: Dict = {
                "id": item.get("check_id", "unknown"),
                "severity": normalized,
                "owasp": owasp,
                "cwe": cwe,
                "message": extra.get("message", "No description provided."),
                "file": item.get("path", "unknown"),
                "line": item.get("start", {}).get("line", 0),
            }
            findings.append(finding)

        total = len(findings)

        return ScanResult(
            tool="Semgrep",
            total=total,
            critical=severity_counts["CRITICAL"],
            high=severity_counts["HIGH"],
            medium=severity_counts["MEDIUM"],
            low=severity_counts["LOW"],
            findings=findings,
        )

