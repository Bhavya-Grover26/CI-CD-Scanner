"""Semgrep runner module.

Provides the SemgrepRunner class to execute Semgrep scans
and save results to a JSON file.
"""

import subprocess
from pathlib import Path
from typing import Optional


class SemgrepRunnerError(Exception):
    """Custom exception for SemgrepRunner failures."""

    pass


class SemgrepRunner:
    """Runs Semgrep scans on a target directory and saves JSON output.

    Attributes:
        target_dir: Path to the directory to scan.
        output_path: Path where the JSON results will be saved.
        config: Semgrep rule configuration to use (default: p/security-audit).
    """

    def __init__(
        self,
        target_dir: Path,
        output_path: Path,
        config: str = "p/security-audit",
    ) -> None:
        """Initialise the SemgrepRunner.

        Args:
            target_dir: Directory to scan.
            output_path: Path to save the JSON results file.
            config: Semgrep config identifier (default: p/security-audit).
        """
        self.target_dir = target_dir
        self.output_path = output_path
        self.config = config

    def run(self) -> Path:
        """Execute the Semgrep scan.

        Builds and runs the command:
            semgrep scan --config=<config> --json <target_dir>

        Returns:
            Path to the saved JSON results file.

        Raises:
            SemgrepRunnerError: If Semgrep is not installed or the scan fails.
        """
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            "semgrep",
            "scan",
            f"--config={self.config}",
            "--json",
            str(self.target_dir),
        ]

        print(f"[*] Running: {' '.join(command)}\n")

        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except FileNotFoundError:
            raise SemgrepRunnerError(
                "Semgrep is not installed or not found in PATH. "
                "Install it with: pip install semgrep"
            ) from None

        if completed.returncode not in (0, 1):
            error_msg = completed.stderr.strip() or "Unknown error occurred."
            raise SemgrepRunnerError(
                f"Semgrep scan failed with exit code {completed.returncode}: {error_msg}"
            )

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(completed.stdout)

        if completed.stderr:
            print(completed.stderr)

        return self.output_path


def _get_project_root() -> Path:
    """Return the project root directory (two levels up from this file)."""
    return Path(__file__).resolve().parent.parent.parent


def run_semgrep(output_file: Optional[Path] = None) -> Path:
    """Convenience function to run a Semgrep scan with default settings.

    Args:
        output_file: Path to save results. Defaults to reports/results.json.

    Returns:
        Path to the saved JSON results file.
    """
    project_root = _get_project_root()
    app_dir = project_root / "app"

    if output_file is None:
        output_file = project_root / "reports" / "results.json"

    runner = SemgrepRunner(
        target_dir=app_dir,
        output_path=output_file,
    )
    return runner.run()

