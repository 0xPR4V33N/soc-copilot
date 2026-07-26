# Interview Guide

## 30-second pitch

I built a local SOC copilot for Windows endpoints that ingests Sysmon telemetry, applies explainable detection rules first, falls back to a local LLM for unmatched events, maps findings to MITRE ATT&CK, and tracks analyst feedback with measurable quality metrics.

## Architecture talking points

- **Ingest:** Sysmon event IDs `1`, `3`, `12`, `13` (process, network, registry).
- **Parse:** normalize event messages into structured fields.
- **Detect:** rule-first triage for deterministic patterns, then LLM fallback.
- **Map:** convert technique guesses to ATT&CK IDs and links.
- **Review:** analyst can confirm, override severity, and mark false positives.
- **Measure:** severity accuracy plus suspicious-class precision/recall/F1.

## Why rule-first + LLM fallback

- Rules reduce obvious false positives and explain high-confidence detections.
- LLM covers behavior outside deterministic rule coverage.
- Combined approach gives better operational control than LLM-only triage.

## Current rule coverage

- `SOC-R001` encoded PowerShell (`T1059.001`) - critical
- `SOC-R002` `cmd.exe -> powershell.exe` chain (`T1059.001`) - high
- `SOC-R003` scripted recon tools (`T1033`, `T1082`, `T1016`) - high
- `SOC-R004` executable from Temp/Downloads (`T1204`) - high
- `SOC-R005` script engine web connection (`T1071.001`) - medium
- `SOC-R006` Run key persistence (`T1547.001`) - high
- `SOC-R100` known-benign service chain baseline - low

## Metrics interpretation

- **Severity accuracy:** exact severity label match against sample labels.
- **Precision/Recall/F1:** suspicious class where high/critical = positive.
- **Analyst overrides:** quality feedback signal for tuning thresholds/rules.

## Common follow-up questions

### How did you control hallucinations?
- Rules are evaluated before LLM.
- LLM output schema is normalized and confidence-clamped.
- Analyst feedback captures corrections for future tuning.

### Why local inference?
- Keeps telemetry on-device and avoids external API dependency.
- Predictable cost profile for lab and portfolio demonstrations.

### What would you improve next?
- Expand rule corpus (LOLBins, Office-to-script chains, startup folder persistence).
- Add calibrated confidence and trend tracking over larger labeled datasets.
- Add alert suppression windows and entity-level correlation.
