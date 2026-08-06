# Phase 2 DevSecOps Pipeline - Trivy Integration TODO

## Steps

- [x] Plan confirmed with user
- [x] **Step 1**: Create `scanner/tools/trivy_runner.py` - TrivyRunner class
- [x] **Step 2**: Create `scanner/parser/trivy_parser.py` - TrivyParser class
- [x] **Step 3**: Refactor `scanner/policy/policy_engine.py` - Accept list of ScanResult, multi-scanner policy
- [x] **Step 4**: Refactor `scanner/report_generator.py` - Accept list of ScanResult, add Trivy section
- [x] **Step 5**: Update `scanner/run_scan.py` - Orchestrate both Semgrep + Trivy
- [x] **Step 6**: Update `requirements.txt`
- [x] **Step 7**: Verify and test the pipeline

## Results

- Phase 1 (Semgrep) completed successfully.
- Phase 2 (Trivy) integration completed.
- **TrivyRunner**: executes `trivy fs .` with JSON output to `reports/trivy_results.json`.
- **TrivyParser**: parses CVE ID, package, installed/fixed version, severity, title/description into ScanResult.
- **PolicyEngine**: refactored to accept a list of `ScanResult`; fails if critical > 0 or high > 5 (any scanner).
- **HTMLReportGenerator**: accepts multiple ScanResults; adds "Dependency Vulnerabilities (Trivy)" section.
- **run_scan.py**: orchestrates both Semgrep + Trivy, passes all results to policy + report.
- Tested with sample Trivy JSON: parser + policy + report generation all verified.
- Note: Trivy binary is not installed on this system; run `trivy --version` after installing from https://github.com/aquasecurity/trivy.
