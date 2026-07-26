# Application Snippets

## Resume bullet options

- Built a local AI-assisted SOC triage pipeline for Windows Sysmon telemetry with rule-first detection, LLM fallback, and MITRE ATT&CK mapping.
- Implemented analyst-in-the-loop feedback workflow (severity overrides, false-positive disposition, notes) with persistent review tracking.
- Added measurable evaluation layer (severity accuracy, precision, recall, F1) and automated reporting/benchmark artifacts for repeatable validation.
- Designed CI validation pipeline (tests + sample artifact checks + compile checks) to keep security-lab portfolio reproducible.

## LinkedIn project summary

I built an AI-Powered SOC Copilot lab project that ingests Sysmon events, triages them with explainable rules first and local LLM fallback, maps detections to MITRE ATT&CK, and tracks analyst feedback. The project includes benchmark and reporting automation with quality metrics (accuracy, precision, recall, F1) and a Streamlit dashboard for incident review.

## Cover letter short paragraph

To strengthen my transition into security operations, I built a hands-on SOC copilot that processes live Windows telemetry (Sysmon), applies deterministic threat rules, and uses a local language model only when rules are inconclusive. I also implemented ATT&CK mapping, analyst override workflows, and quantitative evaluation so detection quality can be measured and iterated rather than guessed.

## Interview opener (60 seconds)

This project simulates a practical SOC triage flow. It ingests Sysmon process, network, and registry events; normalizes logs into structured fields; runs high-signal rules first; then uses local LLM triage for unknown patterns. Every event is mapped to MITRE ATT&CK and reviewed in a dashboard where analysts can confirm or override outcomes. I added evaluation metrics and benchmark/report scripts so improvements are measurable over time.
