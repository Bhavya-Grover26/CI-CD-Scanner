"""Trivy JSON results parser.

Provides the TrivyParser class that reads Trivy JSON output
and converts it to a ScanResult model.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from scanner.models.scan_result import ScanResult


class TrivyParserError(Exception):
    """Custom exception for TrivyParser failures."""

    pass


class TrivyParser:
    """Parses Trivy JSON output into a ScanResult model.

    Usage:
        parser = TrivyParser()
        result = parser.parse(Path("reports/trivy_results.json"))
    """

    def parse(self, results_path: Path) -> ScanResult:
        """Read and parse a Trivy JSON results file.

        Args:
            results_path: Path to the Trivy JSON results file.

        Returns:
            A ScanResult instance with normalised dependency findings.

        Raises:
            TrivyParserError: If the file is missing, contains invalid JSON,
                              or is not valid Trivy output.
        """
        if not results_path.exists():
            raise TrivyParserError(
                f"Results file not found: {results_path}"
            )

        try:
            with open(results_path, "r", encoding="utf-8") as f:
                data: List[Dict[str, Any]] = json.load(f)
        except json.JSONDecodeError as exc:
            raise TrivyParserError(
                f"Invalid JSON in results file: {exc}"
            ) from None

        if not isinstance(data, list):
            raise TrivyParserError(
                "The JSON file does not appear to be valid Trivy output "
                "(expected a top-level list of results)."
            )

        findings: List[Dict] = []
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        results: List[Dict[str, Any]] = data

        for result_item in results:
            target: str = result_item.get("Target", "unknown")

            vulnerabilities: List[Dict[str, Any]] = result_item.get(
                "Vulnerabilities", []
            )

            for vuln in vulnerabilities:
                severity: str = vuln.get("Severity", "LOW").upper()
                if severity not in severity_counts:
                    severity = "LOW"

                severity_counts[severity] += 1

                title: str = vuln.get("Title", "") or ""
                description: str = vuln.get("Description", "") or ""

                finding: Dict = {
                    "id": vuln.get("VulnerabilityID", "unknown"),
                    "severity": severity,
                    "package": vuln.get("PkgName", "unknown"),
                    "installed_version": vuln.get("InstalledVersion", "unknown"),
                    "fixed_version": vuln.get("FixedVersion", "N/A"),
                    "title": title,
                    "description": description,
                    "file": target,
                }
                findings.append(finding)

        total = len(findings)

        return ScanResult(
            tool="Trivy",
            total=total,
            critical=severity_counts["CRITICAL"],
            high=severity_counts["HIGH"],
            medium=severity_counts["MEDIUM"],
            low=severity_counts["LOW"],
            findings=findings,
        )
