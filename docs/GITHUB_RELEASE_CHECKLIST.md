# GitHub Release Checklist

## Pre-publish hygiene

- [ ] `.gitignore` excludes `venv/`, `data/raw/`, `data/processed/`, model files.
- [ ] No personal telemetry in tracked files.
- [ ] `README.md` quick start works from zero.
- [ ] `VERSION` and `CHANGELOG.md` updated.

## Validation checks

- [ ] `python -m unittest discover -s tests -v` passes.
- [ ] `python -m compileall -q src scripts tests` passes.
- [ ] `python scripts/run_pipeline.py --demo-static` works.
- [ ] `streamlit run src/soc_copilot/dashboard/app.py` opens with demo data.
- [ ] `python scripts/generate_report.py` updates report.

## Artifact generation

- [ ] `python scripts/benchmark_models.py --primary-name sample-baseline --use-triaged data\\samples\\triaged.json`
- [ ] `python scripts/generate_report.py`
- [ ] `python scripts/build_portfolio_bundle.py --zip`

## Repo presentation

- [ ] Add 2-4 dashboard screenshots under `portfolio/` or release assets.
- [ ] Link report and benchmark files in README.
- [ ] Ensure architecture diagram is visible in README.

## Release creation

- [ ] Tag version: `v1.0.0-lab`
- [ ] Release title: `AI SOC Copilot v1.0.0-lab`
- [ ] Include highlights, metrics, and known limitations in release notes.
- [ ] Attach bundle zip from `portfolio/`.
