#!/usr/bin/env python3
"""Build a slim MITRE ATT&CK technique index from the full STIX bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_copilot.config import load_settings  # noqa: E402


def build_index(stix_path: Path, out_path: Path) -> int:
    with open(stix_path, encoding="utf-8") as f:
        data = json.load(f)

    entries = []
    seen_ids: set[str] = set()

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
            continue

        ext_id = next(
            (
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ext_id or ext_id in seen_ids:
            continue

        seen_ids.add(ext_id)
        entries.append(
            {
                "id": ext_id,
                "name": obj.get("name", ""),
                "aliases": obj.get("x_mitre_aliases", []) or [],
            }
        )

    entries.sort(key=lambda item: item["id"])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

    return len(entries)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build slim MITRE technique index")
    parser.add_argument(
        "--stix",
        type=Path,
        default=None,
        help="Path to mitre_attack.json STIX bundle",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path for mitre_techniques.json",
    )
    args = parser.parse_args()

    settings = load_settings()
    stix_path = args.stix or settings.mitre_stix
    out_path = args.out or settings.mitre_index

    if not stix_path.exists():
        print(
            f"STIX bundle not found: {stix_path}\n"
            "Download enterprise-attack.json from https://attack.mitre.org/ "
            "and save it as mitre_attack.json, then re-run this script."
        )
        sys.exit(1)

    count = build_index(stix_path, out_path)
    print(f"Wrote {count} techniques -> {out_path}")


if __name__ == "__main__":
    main()
