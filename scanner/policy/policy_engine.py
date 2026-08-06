"""Policy evaluation engine for security scan results.

Provides the PolicyEngine class that evaluates a ScanResult
against defined security policies and returns a pass/fail decision.
"""

from typing import Tuple

from scanner.models.scan_result import ScanResult


class PolicyEngine:
    """Evaluates scan results against security policies.

    Current policy rules:
        - FAIL if critical severity findings > 0
        - FAIL if high severity findings > 0
        - PASS otherwise
    """

    def evaluate(self, result: ScanResult) -> Tuple[bool, str]:
        """Evaluate a ScanResult against the security policy.

        Args:
            result: A ScanResult instance to evaluate.

        Returns:
            A tuple of (passed, reason):
                - passed: True if the scan passes policy, False otherwise.
                - reason: A human-readable explanation of the decision.
        """
        if result.critical > 0 and result.high > 0:
            return (
                False,
                f"Critical ({result.critical}) and High ({result.high}) "
                f"severity findings detected.",
            )

        if result.critical > 0:
            return (
                False,
                f"Critical severity findings detected ({result.critical}).",
            )

        if result.high > 0:
            return (
                False,
                f"High severity findings detected ({result.high}).",
            )

        return (
            True,
            "No critical or high severity findings. Scan passed.",
        )

