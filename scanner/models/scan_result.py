from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ScanResult:
    """Represents the normalized result of a security scan.

    Attributes:
        tool: Name of the security tool that produced the results.
        total: Total number of findings.
        critical: Number of critical severity findings.
        high: Number of high severity findings.
        medium: Number of medium severity findings.
        low: Number of low severity findings.
        findings: List of individual finding dictionaries with keys:
                 id, severity, message, file, line.
    """

    tool: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    findings: List[Dict]
