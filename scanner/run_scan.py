"""SAST SCA Pipeline - Phase 2 orchestration script.

Runs Semgrep and Trivy scans, parses results, evaluates policy,
generates an HTML report, and prints a console summary.

Usage:
    python scanner/run_scan.py
"""

import sys
from pathlib import Path
from typing import List, Tuple

from scanner.models.scan_result import ScanResult
from scanner.tools.semgrep_runner import SemgrepRunner, SemgrepRunnerError
from scanner.tools.trivy_runner import TrivyRunner, TrivyRunnerError
from scanner.parser.semgrep_parser import SemgrepParser, SemgrepParserError
from scanner.parser.trivy_parser import TrivyParser, TrivyParserError
from scanner.policy.policy_engine import PolicyEngine
from scanner.report_generator import HTMLReportGenerator

# ── Paths (relative to project root) ──────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = PROJECT_ROOT / "app"
REPORTS_DIR = PROJECT_ROOT / "reports"
SEMGREP_JSON = REPORTS_DIR / "results.json"
TRIVY_JSON = REPORTS_DIR / "trivy_results.json"
REPORT_HTML = REPORTS_DIR / "security_report.html"


def _run_semgrep() -> ScanResult:
    """Run and parse a Semgrep scan."""
    runner = SemgrepRunner(
        target_dir=APP_DIR,
        output_path=SEMGREP_JSON,
    )
    runner.run()

    parser = SemgrepParser()
    return parser.parse(SEMGREP_JSON)


def _run_trivy() -> ScanResult:
    """Run and parse a Trivy scan."""
    runner = TrivyRunner(
        target_dir=APP_DIR,
        output_path=TRIVY_JSON,
    )
    runner.run()

    parser = TrivyParser()
    return parser.parse(TRIVY_JSON)


def main() -> None:
    """Run the complete DevSecOps pipeline for Phase 2.

    Steps:
        1. Run Semgrep and Trivy scans on app/ directory.
        2. Parse the JSON results into ScanResult models.
        3. Evaluate the scan results against security policy.
        4. Generate a professional HTML report.
        5. Print a console summary.
        6. Exit with code 0 (pass) or 1 (fail).
    """
    # Ensure reports directory exists.
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    results: List[ScanResult] = []

    # ── Step 1 & 2: Run and parse scans ────────────────────────────────
    try:
        results.append(_run_semgrep())
    except (SemgrepRunnerError, SemgrepParserError) as exc:
        print(f"[ERROR] Semgrep: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        results.append(_run_trivy())
    except (TrivyRunnerError, TrivyParserError) as exc:
        print(f"[ERROR] Trivy: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Step 3: Evaluate policy ────────────────────────────────────────
    engine = PolicyEngine()
    passed, reason = engine.evaluate(results)

    # ── Step 4: Generate HTML report ───────────────────────────────────
    try:
        generator = HTMLReportGenerator()
        generator.generate(
            results=results,
            passed=passed,
            reason=reason,
            output_path=REPORT_HTML,
        )
    except OSError as exc:
        print(f"[ERROR] Failed to write HTML report: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Step 5: Print console summary ──────────────────────────────────
    status = "PASSED" if passed else "FAILED"

    print()
    print("=" * 50)
    print("         Security Scan Summary")
    print("=" * 50)
    for result in results:
        print(f"  {'Tool':12}: {result.tool}")
        print(f"  {'Total':12}: {result.total}")
        print(f"  {'Critical':12}: {result.critical}")
        print(f"  {'High':12}: {result.high}")
        print(f"  {'Medium':12}: {result.medium}")
        print(f"  {'Low':12}: {result.low}")
        print("-" * 50)
    print(f"  {'Status':12}: {status}")
    print(f"  {'Report':12}: {REPORT_HTML}")
    print(f"  {'Reason':12}: {reason}")
    print("=" * 50)
    print()

    # ── Step 6: Exit with appropriate code ─────────────────────────────
    if not passed:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
