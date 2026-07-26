#!/usr/bin/env python3
"""Build a shareable portfolio artifact bundle."""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_copilot.config import load_settings


def copy_if_exists(source: Path, destination: Path) -> None:
    if source.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build SOC Copilot portfolio bundle")
    parser.add_argument(
        "--zip",
        action="store_true",
        help="Create a zip archive next to the bundle directory.",
    )
    args = parser.parse_args()

    settings = load_settings()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_dir = settings.portfolio_bundle / f"bundle_{stamp}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    files = {
        settings.root / "README.md": bundle_dir / "README.md",
        settings.root / "CHANGELOG.md": bundle_dir / "CHANGELOG.md",
        settings.root / "VERSION": bundle_dir / "VERSION",
        settings.summary_report: bundle_dir / "reports" / "portfolio_summary.md",
        settings.benchmark_output: bundle_dir / "reports" / "model_benchmark.json",
        settings.root / "data" / "samples" / "events.json": bundle_dir / "data" / "samples" / "events.json",
        settings.root / "data" / "samples" / "triaged.json": bundle_dir / "data" / "samples" / "triaged.json",
        settings.root / "data" / "samples" / "labels.json": bundle_dir / "data" / "samples" / "labels.json",
        settings.root / "docs" / "INTERVIEW_GUIDE.md": bundle_dir / "docs" / "INTERVIEW_GUIDE.md",
        settings.root / "docs" / "APPLICATION_SNIPPETS.md": bundle_dir / "docs" / "APPLICATION_SNIPPETS.md",
        settings.root / "docs" / "GITHUB_RELEASE_CHECKLIST.md": bundle_dir / "docs" / "GITHUB_RELEASE_CHECKLIST.md",
    }
    for source, destination in files.items():
        copy_if_exists(source, destination)

    print(f"Created portfolio bundle directory -> {bundle_dir}")

    if args.zip:
        archive_base = settings.portfolio_bundle / f"soc_copilot_portfolio_{stamp}"
        archive_path = shutil.make_archive(str(archive_base), "zip", root_dir=bundle_dir)
        print(f"Created zip archive -> {archive_path}")


if __name__ == "__main__":
    main()
