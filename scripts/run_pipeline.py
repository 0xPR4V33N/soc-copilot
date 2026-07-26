#!/usr/bin/env python3
"""Run the SOC Copilot triage pipeline."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_copilot.config import load_settings  # noqa: E402
from soc_copilot.export.sysmon import export_sysmon_events  # noqa: E402
from soc_copilot.triage.pipeline import run_triage  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="AI SOC Copilot pipeline")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use sanitized sample events instead of live Sysmon export",
    )
    parser.add_argument(
        "--demo-static",
        action="store_true",
        help="Copy pre-built sample triage output (no Sysmon, no LLM)",
    )
    parser.add_argument(
        "--skip-triage",
        action="store_true",
        help="Export events only, skip LLM triage",
    )
    args = parser.parse_args()

    settings = load_settings()

    if args.demo_static:
        sample_triaged = settings.root / "data" / "samples" / "triaged.json"
        if not sample_triaged.exists():
            print(f"Sample triage file not found: {sample_triaged}")
            sys.exit(1)
        settings.events_processed.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sample_triaged, settings.events_processed)
        print(f"Copied demo triage -> {settings.events_processed}")
        print("\nRun dashboard:")
        print("  set PYTHONPATH=src && streamlit run src/soc_copilot/dashboard/app.py")
        return

    if args.demo:
        if not settings.events_sample.exists():
            print(f"Sample events not found: {settings.events_sample}")
            sys.exit(1)
        settings.events_raw.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(settings.events_sample, settings.events_raw)
        print(f"Using demo events -> {settings.events_raw}")
        input_file = settings.events_raw
    else:
        print("Exporting Sysmon events...")
        input_file = export_sysmon_events(settings=settings)

    if args.skip_triage:
        print(f"Events ready at {input_file}")
        return

    print("Running hybrid rule + LLM triage...")
    run_triage(input_file=input_file, output_file=settings.events_processed, settings=settings)

    print("\nPipeline complete.")
    print("Run dashboard:")
    print("  set PYTHONPATH=src && streamlit run src/soc_copilot/dashboard/app.py")


if __name__ == "__main__":
    main()
