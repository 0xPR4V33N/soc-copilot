# Release Notes - v1.0.0-lab

## Highlights

- End-to-end local SOC triage workflow for Windows Sysmon telemetry.
- Rule-first detection with LLM fallback and ATT&CK mapping.
- Analyst feedback loop with override/disposition tracking.
- Labeled evaluation metrics (accuracy, precision, recall, F1).
- Benchmark and portfolio report generation scripts.
- CI workflow for repeatable validation.

## Detection content

- Process abuse, recon behavior, temp execution, network web-protocol behavior, and registry run-key persistence.
- Known-benign baseline rule for common service chain behavior.

## Portfolio assets

- `reports/portfolio_summary.md`
- `reports/model_benchmark.json`
- `docs/INTERVIEW_GUIDE.md`
- `docs/APPLICATION_SNIPPETS.md`

## Known limits

- Demo metrics are sample-based and not production-ground truth.
- Rule set is intentionally compact for explainability.
- LLM fallback quality depends on local model performance.
