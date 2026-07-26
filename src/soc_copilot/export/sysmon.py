from __future__ import annotations

import json
import subprocess
from pathlib import Path

from soc_copilot.config import Settings, load_settings


def export_sysmon_events(
    out_file: Path | None = None,
    max_events: int | None = None,
    event_ids: tuple[int, ...] | list[int] | None = None,
    settings: Settings | None = None,
) -> Path:
    """Export configured Sysmon event types to JSON."""
    cfg = settings or load_settings()
    output = out_file or cfg.events_raw
    limit = max_events if max_events is not None else cfg.max_events
    selected_ids = tuple(event_ids) if event_ids is not None else cfg.event_ids
    if not selected_ids:
        raise ValueError("At least one Sysmon event ID must be configured")
    id_filter = ",".join(str(int(event_id)) for event_id in selected_ids)

    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "powershell",
        "-Command",
        (
            "Get-WinEvent -FilterHashtable "
            f"@{{LogName='Microsoft-Windows-Sysmon/Operational'; Id={id_filter}}} "
            f"-MaxEvents {limit} | "
            "ForEach-Object { [PSCustomObject]@{Id=$_.Id; TimeCreated=$_.TimeCreated; "
            "Message=$_.Message} } | ConvertTo-Json -Depth 3"
        ),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to export Sysmon events (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(
            "No Sysmon events returned. Is Sysmon installed and the Operational log available?"
        )

    # Validate JSON before writing.
    json.loads(stdout)

    output.write_text(stdout, encoding="utf-8")
    print(f"Exported Sysmon events -> {output}")
    return output
