"""Policy evaluation engine for security scan results.

Provides the PolicyEngine class that evaluates one or more ScanResult
objects against defined security policies and returns a pass/fail decision.
"""

from typing import List, Tuple

from scanner.models.scan_result import ScanResult


class PolicyEngine:
    """Evaluates scan results against security policies.

    Current policy rules:
        - FAIL if critical severity findings > 0 (any scanner)
        - FAIL if high severity findings > 5 (any scanner)
        - PASS otherwise

    The engine is scanner-agnostic: it operates purely on the normalised
    ScanResult model, so it works for any number and type of scanners.
    """

    #: Maximum allowed high-severity findings per scanner.
    HIGH_THRESHOLD: int = 5

    def evaluate(self, results: List[ScanResult]) -> Tuple[bool, str]:
        """Evaluate a list of ScanResults against the security policy.

        Args:
            results: A list of ScanResult instances to evaluate.

        Returns:
            A tuple of (passed, reason):
                - passed: True if all scans pass policy, False otherwise.
                - reason: A human-readable explanation of the decision.
        """
        if not results:
            return (
                True,
                "No scan results provided. Scan passed by default.",
            )

        reasons: List[str] = []

        for result in results:
            if result.critical > 0:
                reasons.append(
                    f"{result.tool}: {result.critical} critical "
                    f"severity finding(s) detected."
                )

            if result.high > self.HIGH_THRESHOLD:
                reasons.append(
                    f"{result.tool}: {result.high} high severity "
                    f"finding(s) exceed the threshold of "
                    f"{self.HIGH_THRESHOLD}."
                )

        if reasons:
            return (False, "; ".join(reasons))

        return (
            True,
            "No critical findings and no high-severity threshold "
            "exceeded. Scan passed.",
        )
