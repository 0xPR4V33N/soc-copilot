# AI SOC Copilot

Local, AI-assisted security event triage pipeline for Windows Sysmon logs. Built as a portfolio lab project demonstrating SOC analyst workflows, MITRE ATT&CK mapping, measurable detection performance, and privacy-preserving LLM inference.

## What it does

```
Sysmon (EID 1/3/12/13)  →  export  →  parse  →  rules  →  LLM fallback  →  MITRE map  →  dashboard
```

1. **Export** configured Sysmon process, network, and registry events from the Windows Event Log
2. **Parse** raw messages into event-specific structured fields
3. **Triage** high-signal patterns with explainable rules, then use a local Phi-3 model for unmatched events
4. **Map** LLM technique guesses to MITRE ATT&CK IDs
5. **Visualize** results, evaluation metrics, and analyst decisions in an interactive dashboard

## Project structure

```
soc-copilot/
├── config/settings.yaml       # Paths, model, export settings
├── src/soc_copilot/           # Application package
│   ├── export/                # Sysmon log export
│   ├── parse/                 # Sysmon message parser
│   ├── triage/                # Explainable rules + LLM fallback
│   ├── mitre/                 # MITRE ATT&CK mapper
│   ├── evaluation.py          # Accuracy, precision, recall, F1
│   ├── feedback.py            # Analyst overrides and disposition
│   └── dashboard/             # Streamlit UI
├── scripts/                   # CLI entry points
├── data/samples/              # Sanitized demo dataset (safe to publish)
├── data/raw/                  # Live exported events (gitignored)
├── data/processed/            # Live triage output (gitignored)
└── assets/mitre_techniques.json  # Slim MITRE index (~800 KB)
```

## Quick start (two paths)

```powershell
cd C:\soc-copilot
python -m venv venv
.\venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
$env:PYTHONPATH = "src"

# Optional: run validation tests
python -m unittest discover -s tests -v
```

### Path A: Demo mode (no Sysmon, no model required)

```powershell
python scripts/run_pipeline.py --demo-static
streamlit run src/soc_copilot/dashboard/app.py
```

### Path B: Live mode (actual Sysmon telemetry)

Prerequisites:
- Sysmon installed
- local model file at `models/phi3-mini-q4.gguf`

```powershell
python scripts/run_pipeline.py
streamlit run src/soc_copilot/dashboard/app.py
```

### Path B.1: Live mode with manual attack trigger (Atomic Red Team)

```powershell
Import-Module Invoke-AtomicRedTeam -Force
$atomics = "C:\AtomicRedTeam\atomics"

Invoke-AtomicTest T1059.001 -TestNumbers 1 -PathToAtomicsFolder $atomics
Invoke-AtomicTest T1033 -TestNumbers 1 -PathToAtomicsFolder $atomics
Invoke-AtomicTest T1071.001 -TestNumbers 1 -PathToAtomicsFolder $atomics
Invoke-AtomicTest T1547.001 -TestNumbers 1 -PathToAtomicsFolder $atomics

cd C:\soc-copilot
python scripts/run_pipeline.py
streamlit run src/soc_copilot/dashboard/app.py
```

### One-command helper (PowerShell)

```powershell
.\scripts\setup_and_run.ps1 -Mode demo -RunTests -GenerateBenchmark -GenerateReport -StartDashboard
```

## Full pipeline options

```powershell
# Build MITRE index (one-time; if mitre_attack.json is available)
python scripts/build_mitre_index.py

# Use demo events but run hybrid triage code path
python scripts/run_pipeline.py --demo
```

## Configuration

Edit `config/settings.yaml` to change:

- Event export limits and types (`max_events`, `event_ids`)
- Model path and inference settings (`n_threads`, `temperature`)
- Input/output file paths

## Design notes

- **Local-first:** Logs and LLM inference stay on your machine — useful for sensitive environments
- **Hybrid triage:** Deterministic, high-confidence rules handle known patterns before the LLM is called
- **Explainable decisions:** Rule verdicts include rule IDs, confidence, and matched indicators
- **Human in the loop:** Analysts can confirm alerts, mark false positives, override severity, and record notes
- **Measured behavior:** Labeled samples expose severity accuracy, precision, recall, and F1
- **Structured parsing:** Sysmon messages are parsed once into reusable fields instead of fragile string splits
- **Structured triage schema:** Verdicts are stored as JSON objects (not double-encoded strings)
- **Slim MITRE index:** The full STIX bundle is not committed; a pre-built index loads in milliseconds
- **Demo dataset:** Sanitized events include both benign activity and simulated attack patterns (encoded PowerShell, recon chain, Temp execution)

## Detection rules

- `SOC-R001` — encoded PowerShell command (`T1059.001`), critical
- `SOC-R002` — `cmd.exe` spawning PowerShell (`T1059.001`), high
- `SOC-R003` — reconnaissance tools launched by a script host or from a user-writable path, high
- `SOC-R004` — executable launched from Temp or Downloads (`T1204`), high
- `SOC-R005` — scripting engine making a remote web connection (`T1071.001`), medium
- `SOC-R006` — registry Run-key modification (`T1547.001`), high
- `SOC-R100` — expected `services.exe` → `svchost.exe` SYSTEM chain, low

If no rule matches, the event is sent to the local LLM. This reduces unnecessary inference and avoids asking the model to identify patterns that can be detected deterministically.

## Safe attack simulations

The repository contains inert, sanitized Sysmon-style JSON records in `data/samples/`. They model:

1. Encoded PowerShell spawned by `cmd.exe`
2. `whoami /all` launched by PowerShell
3. An executable launched from a user Temp directory
4. PowerShell making a remote HTTPS connection
5. Registry Run-key persistence
6. Expected Windows service and interactive application control cases

These samples are telemetry only; the repository does not execute the represented commands. Use `python scripts/run_pipeline.py --demo-static` to present them without Sysmon or a model.

## Tests

Run the parser, rule engine, evaluation, feedback, MITRE mapper, and hybrid pipeline tests:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

## Model benchmark (optional)

Compare your default model against another local GGUF model on the same labeled sample set:

```powershell
$env:PYTHONPATH = "src"
python scripts/benchmark_models.py --primary-name phi3 --secondary-model models\other-model.gguf --secondary-name other
```

This writes `reports/model_benchmark.json` with per-model runtime and quality metrics.

If you do not have a second model yet, you can still produce benchmark-style metrics from precomputed sample triage:

```powershell
$env:PYTHONPATH = "src"
python scripts/benchmark_models.py --primary-name sample-baseline --use-triaged data\samples\triaged.json
```

## Portfolio summary report

Generate a markdown report that summarizes triage volume, MITRE coverage, labeled metrics, analyst feedback, and optional benchmark results:

```powershell
$env:PYTHONPATH = "src"
python scripts/generate_report.py
```

This writes `reports/portfolio_summary.md`.

## Build a shareable portfolio bundle

```powershell
$env:PYTHONPATH = "src"
python scripts/build_portfolio_bundle.py --zip
```

This collects key artifacts into `portfolio/bundle_*` and optionally creates a zip archive.

## Continuous integration

GitHub Actions workflow at `.github/workflows/ci.yml` runs on pushes and pull requests:

- Install dependencies
- Validate sample JSON artifacts
- Execute the full unit test suite
- Compile Python sources for syntax checks

## Publication and interview docs

- Release checklist: `docs/GITHUB_RELEASE_CHECKLIST.md`
- Interview prep: `docs/INTERVIEW_GUIDE.md`
- Resume/LinkedIn snippets: `docs/APPLICATION_SNIPPETS.md`
- Release notes template: `docs/RELEASE_NOTES_v1.0.0.md`

## Known limitations

- Rule coverage and the eight-event evaluation set are intentionally small; reported metrics are demonstrative, not production benchmarks
- LLM fallback can still hallucinate on unfamiliar or ambiguous system processes
- Rule confidence is a design-time heuristic, not a calibrated probability
- Analyst feedback is local JSON storage and does not support concurrent multi-user writes
- Model-to-model comparison requires a second local model and is not enabled by default
- Not a replacement for enterprise SIEM/EDR tooling

## License

Portfolio / educational use.
