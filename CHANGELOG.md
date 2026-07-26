# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-07-26

### Added
- Rule-first triage pipeline with LLM fallback.
- Seven detection rules (`SOC-R001` to `SOC-R006`, `SOC-R100`).
- Sysmon event coverage for process, network, and registry telemetry (EID 1, 3, 12, 13).
- MITRE ATT&CK mapping with direct ATT&CK links in dashboard.
- Analyst feedback loop for severity override, disposition, and notes.
- Labeled evaluation metrics (accuracy, precision, recall, F1).
- Benchmark workflow for model/runtime quality reporting.
- Portfolio summary report generation.
- CI workflow for validation on pull requests and pushes.

### Changed
- Project reorganized to `src/soc_copilot` package structure.
- Demo data and labels formalized for deterministic portfolio runs.
- Dashboard expanded with filters, event details, and evaluation panel.

### Notes
- Demo metrics are from sanitized sample telemetry and are for showcase purposes.
- Live environment results depend on Sysmon configuration and endpoint behavior.
