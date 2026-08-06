"""Trivy runner module.

Provides the TrivyRunner class to execute Trivy filesystem scans
and save results to a JSON file.
"""

import subprocess
from pathlib import Path
from typing import Optional


class TrivyRunnerError(Exception):
    """Custom exception for TrivyRunner failures."""

    pass


class TrivyRunner:
    """Runs Trivy filesystem scans on a target directory and saves JSON output.

    Attributes:
        target_dir: Path to the directory to scan.
        output_path: Path where the JSON results will be saved.
        severity: Comma-separated severity levels to include in the scan.
        timeout: Optional timeout in seconds for the Trivy command.
    """

    def __init__(
        self,
        target_dir: Path,
        output_path: Path,
        severity: str = "CRITICAL,HIGH,MEDIUM,LOW",
        timeout: Optional[int] = None,
    ) -> None:
        """Initialise the TrivyRunner.

        Args:
            target_dir: Directory to scan.
            output_path: Path to save the JSON results file.
            severity: Comma-separated severity levels to include.
            timeout: Optional timeout in seconds for the scan.
        """
        self.target_dir = target_dir
        self.output_path = output_path
        self.severity = severity
        self.timeout = timeout

    def run(self) -> Path:
        """Execute the Trivy filesystem scan.

        Builds and runs the command:
            trivy fs <target_dir> --format json --output <output_path>
                    --severity <severity>

        Returns:
            Path to the saved JSON results file.

        Raises:
            TrivyRunnerError: If Trivy is not installed or the scan fails.
        """
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            "trivy",
            "fs",
            str(self.target_dir),
            "--format",
            "json",
            "--output",
            str(self.output_path),
            "--severity",
            self.severity,
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
                timeout=self.timeout,
            )
        except FileNotFoundError:
            raise TrivyRunnerError(
                "Trivy is not installed or not found in PATH. "
                "Install it from: https://github.com/aquasecurity/trivy"
            ) from None
        except subprocess.TimeoutExpired:
            raise TrivyRunnerError(
                f"Trivy scan timed out after {self.timeout} seconds."
            ) from None

        if completed.returncode != 0:
            error_msg = completed.stderr.strip() or "Unknown error occurred."
            raise TrivyRunnerError(
                f"Trivy scan failed with exit code {completed.returncode}: {error_msg}"
            )

        if completed.stderr:
            print(completed.stderr)

        return self.output_path


def _get_project_root() -> Path:
    """Return the project root directory (two levels up from this file)."""
    return Path(__file__).resolve().parent.parent.parent


def run_trivy(output_file: Optional[Path] = None) -> Path:
    """Convenience function to run a Trivy scan with default settings.

    Args:
        output_file: Path to save results. Defaults to reports/trivy_results.json.

    Returns:
        Path to the saved JSON results file.
    """
    project_root = _get_project_root()
    app_dir = project_root / "app"

    if output_file is None:
        output_file = project_root / "reports" / "trivy_results.json"

    runner = TrivyRunner(
        target_dir=app_dir,
        output_path=output_file,
    )
    return runner.run()
