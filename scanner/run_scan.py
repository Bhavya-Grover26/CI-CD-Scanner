"""SAST SCA Pipeline - Phase 1 orchestration script.

Runs Semgrep scan, parses results, evaluates policy,
generates an HTML report, and prints a console summary.

Usage:
    python scanner/run_scan.py
"""

import sys
from pathlib import Path

from scanner.models.scan_result import ScanResult
from scanner.tools.semgrep_runner import SemgrepRunner, SemgrepRunnerError
from scanner.parser.semgrep_parser import SemgrepParser, SemgrepParserError
from scanner.policy.policy_engine import PolicyEngine
from scanner.report_generator import HTMLReportGenerator

# ── Paths (relative to project root) ──────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = PROJECT_ROOT / "app"
REPORTS_DIR = PROJECT_ROOT / "reports"
RESULTS_JSON = REPORTS_DIR / "results.json"
REPORT_HTML = REPORTS_DIR / "security_report.html"


def main() -> None:
    """Run the complete DevSecOps pipeline for Phase 1.

    Steps:
        1. Run Semgrep scan on app/ directory.
        2. Parse the JSON results into a ScanResult model.
        3. Evaluate the scan results against security policy.
        4. Generate a professional HTML report.
        5. Print a console summary.
        6. Exit with code 0 (pass) or 1 (fail).
    """
    # Ensure reports directory exists.
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Run Semgrep ──────────────────────────────────────────────
    try:
        runner = SemgrepRunner(
            target_dir=APP_DIR,
            output_path=RESULTS_JSON,
        )
        runner.run()
    except SemgrepRunnerError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Step 2: Parse results ────────────────────────────────────────────
    try:
        parser = SemgrepParser()
        result: ScanResult = parser.parse(RESULTS_JSON)
    except SemgrepParserError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Step 3: Evaluate policy ──────────────────────────────────────────
    engine = PolicyEngine()
    passed, reason = engine.evaluate(result)

    # ── Step 4: Generate HTML report ─────────────────────────────────────
    try:
        generator = HTMLReportGenerator()
        generator.generate(
            result=result,
            passed=passed,
            reason=reason,
            output_path=REPORT_HTML,
        )
    except OSError as exc:
        print(f"[ERROR] Failed to write HTML report: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Step 5: Print console summary ────────────────────────────────────
    status = "PASSED" if passed else "FAILED"

    print()
    print("=" * 45)
    print("         Security Scan Summary")
    print("=" * 45)
    print(f"  {'Tool':12}: {result.tool}")
    print(f"  {'Total':12}: {result.total}")
    print(f"  {'Critical':12}: {result.critical}")
    print(f"  {'High':12}: {result.high}")
    print(f"  {'Medium':12}: {result.medium}")
    print(f"  {'Low':12}: {result.low}")
    print(f"  {'Status':12}: {status}")
    print(f"  {'Report':12}: {REPORT_HTML}")
    print(f"  {'Reason':12}: {reason}")
    print("=" * 45)
    print()

    # ── Step 6: Exit with appropriate code ───────────────────────────────
    if not passed:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()

