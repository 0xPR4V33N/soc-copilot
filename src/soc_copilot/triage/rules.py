from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath

from soc_copilot.parse.sysmon_event import SysmonEvent, parse_sysmon_message


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
RECON_TECHNIQUES = {
    "whoami.exe": ("System Owner/User Discovery", "T1033"),
    "hostname.exe": ("System Name Discovery", "T1033"),
    "systeminfo.exe": ("System Information Discovery", "T1082"),
    "ipconfig.exe": ("System Network Configuration Discovery", "T1016"),
}


@dataclass(frozen=True)
class RuleFinding:
    rule_id: str
    severity: str
    technique: str
    mitre_id: str
    summary: str
    confidence: float
    indicator: str


def _basename(path: str) -> str:
    return PureWindowsPath(path.strip('"')).name.lower()


def _is_user_writable_path(path: str) -> bool:
    normalized = path.lower().replace("/", "\\")
    return any(
        segment in normalized
        for segment in (
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\downloads\\",
        )
    )


def evaluate_rules(event: dict | SysmonEvent) -> list[RuleFinding]:
    """Return explainable findings for deterministic high-signal patterns."""
    parsed = event if isinstance(event, SysmonEvent) else parse_sysmon_message(event)
    image = _basename(parsed.image)
    parent = _basename(parsed.parent_image)
    command = parsed.command_line.lower()
    findings: list[RuleFinding] = []

    if parsed.event_id == 1 and image in {"powershell.exe", "pwsh.exe"} and any(
        flag in command for flag in ("-encodedcommand", "-enc ", "-e ")
    ):
        findings.append(
            RuleFinding(
                rule_id="SOC-R001",
                severity="critical",
                technique="PowerShell",
                mitre_id="T1059.001",
                summary="PowerShell executed an encoded command.",
                confidence=0.99,
                indicator="Encoded PowerShell command-line flag",
            )
        )

    if parsed.event_id == 1 and image in {"powershell.exe", "pwsh.exe"} and parent == "cmd.exe":
        findings.append(
            RuleFinding(
                rule_id="SOC-R002",
                severity="high",
                technique="PowerShell",
                mitre_id="T1059.001",
                summary="PowerShell was spawned by cmd.exe.",
                confidence=0.92,
                indicator="Unusual cmd.exe to PowerShell process chain",
            )
        )

    if parsed.event_id == 1 and image in RECON_TECHNIQUES and (
        parent in SCRIPT_HOSTS or _is_user_writable_path(parsed.current_directory)
    ):
        technique, mitre_id = RECON_TECHNIQUES[image]
        findings.append(
            RuleFinding(
                rule_id="SOC-R003",
                severity="high",
                technique=technique,
                mitre_id=mitre_id,
                summary=f"{image} reconnaissance ran from a script host or user-writable path.",
                confidence=0.93,
                indicator=f"Reconnaissance utility {image} launched by {parent or 'unknown parent'}",
            )
        )

    if (
        parsed.event_id == 1
        and parsed.image.lower().endswith(".exe")
        and _is_user_writable_path(parsed.image)
    ):
        findings.append(
            RuleFinding(
                rule_id="SOC-R004",
                severity="high",
                technique="User Execution",
                mitre_id="T1204",
                summary="An executable launched from a user-writable Temp or Downloads path.",
                confidence=0.88,
                indicator=f"Executable in user-writable path: {parsed.image}",
            )
        )

    if (
        parsed.event_id == 1
        and
        parsed.image.lower() == r"c:\windows\system32\svchost.exe"
        and parsed.parent_image.lower() == r"c:\windows\system32\services.exe"
        and parsed.user.upper() == r"NT AUTHORITY\SYSTEM"
    ):
        findings.append(
            RuleFinding(
                rule_id="SOC-R100",
                severity="low",
                technique="Not applicable",
                mitre_id="",
                summary="Expected Windows service-host process chain running as SYSTEM.",
                confidence=0.97,
                indicator="Trusted services.exe to svchost.exe system chain",
            )
        )

    if (
        parsed.event_id == 3
        and image in {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
        and parsed.destination_port in {"80", "443", "8080", "8443"}
        and parsed.destination_ip not in {"", "127.0.0.1", "::1"}
    ):
        findings.append(
            RuleFinding(
                rule_id="SOC-R005",
                severity="medium",
                technique="Application Layer Protocol: Web Protocols",
                mitre_id="T1071.001",
                summary="A scripting engine initiated a web connection to a remote host.",
                confidence=0.78,
                indicator=(
                    f"{image} connected to "
                    f"{parsed.destination_hostname or parsed.destination_ip}:"
                    f"{parsed.destination_port}"
                ),
            )
        )

    if (
        parsed.event_id in {12, 13}
        and r"\software\microsoft\windows\currentversion\run" in parsed.target_object.lower()
    ):
        findings.append(
            RuleFinding(
                rule_id="SOC-R006",
                severity="high",
                technique="Registry Run Keys / Startup Folder",
                mitre_id="T1547.001",
                summary="A process modified a registry Run key used for persistence.",
                confidence=0.96,
                indicator=f"Autorun registry target: {parsed.target_object}",
            )
        )

    return findings


def rule_triage(event: dict | SysmonEvent) -> dict | None:
    """Return a structured verdict for rule matches, otherwise None for LLM fallback."""
    findings = evaluate_rules(event)
    if not findings:
        return None

    primary = max(findings, key=lambda finding: SEVERITY_RANK[finding.severity])
    return {
        "severity": primary.severity,
        "technique_guess": primary.technique,
        "summary": primary.summary,
        "source": "rule",
        "confidence": primary.confidence,
        "rule_ids": [finding.rule_id for finding in findings],
        "indicators": [finding.indicator for finding in findings],
        "mitre": (
            f"{primary.mitre_id} ({primary.technique})"
            if primary.mitre_id
            else "Unmapped"
        ),
    }
