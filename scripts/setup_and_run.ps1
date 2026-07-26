param(
    [ValidateSet("demo", "live")]
    [string]$Mode = "demo",
    [switch]$RunTests,
    [switch]$GenerateReport,
    [switch]$GenerateBenchmark,
    [switch]$StartDashboard
)

$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")
Write-Host "Working directory: $(Get-Location)"

if (-not (Test-Path ".\venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
}

& .\venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

$env:PYTHONPATH = "src"

if ($RunTests) {
    python -m unittest discover -s tests -v
}

if ($Mode -eq "demo") {
    python scripts/run_pipeline.py --demo-static
} else {
    python scripts/run_pipeline.py
}

if ($GenerateBenchmark) {
    if ($Mode -eq "demo") {
        python scripts/benchmark_models.py --primary-name sample-baseline --use-triaged data\samples\triaged.json
    } else {
        python scripts/benchmark_models.py --primary-name primary
    }
}

if ($GenerateReport) {
    python scripts/generate_report.py
}

if ($StartDashboard) {
    streamlit run src/soc_copilot/dashboard/app.py
}

Write-Host "Setup and run complete."
