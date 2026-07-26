from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SysmonEvent:
    event_id: int
    event_type: str
    time_created: str
    image: str
    command_line: str
    parent_image: str
    parent_command_line: str
    user: str
    current_directory: str
    integrity_level: str
    process_id: str
    parent_process_id: str
    utc_time: str
    destination_ip: str
    destination_hostname: str
    destination_port: str
    protocol: str
    target_object: str
    details: str

    def to_prompt_text(self) -> str:
        """Compact, structured text for LLM triage prompts."""
        fields = {
            "EventType": self.event_type,
            "Image": self.image,
            "CommandLine": self.command_line,
            "ParentImage": self.parent_image,
            "ParentCommandLine": self.parent_command_line,
            "User": self.user,
            "CurrentDirectory": self.current_directory,
            "IntegrityLevel": self.integrity_level,
            "DestinationIp": self.destination_ip,
            "DestinationHostname": self.destination_hostname,
            "DestinationPort": self.destination_port,
            "Protocol": self.protocol,
            "TargetObject": self.target_object,
            "Details": self.details,
        }
        return "\n".join(f"{name}: {value}" for name, value in fields.items() if value)


_FIELD_PATTERN = re.compile(r"^([A-Za-z]+):\s*(.*)$")
EVENT_TYPES = {
    1: "Process Create",
    3: "Network Connect",
    12: "Registry Object Create/Delete",
    13: "Registry Value Set",
}


def _parse_message_fields(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in message.splitlines():
        match = _FIELD_PATTERN.match(line.strip())
        if match:
            fields[match.group(1)] = match.group(2)
    return fields


def parse_sysmon_message(event: dict) -> SysmonEvent:
    """Parse a raw Sysmon JSON event into structured fields."""
    message = event.get("Message", "")
    fields = _parse_message_fields(message)

    event_id = int(event.get("Id", fields.get("Id", 0)) or 0)
    return SysmonEvent(
        event_id=event_id,
        event_type=EVENT_TYPES.get(event_id, f"Sysmon Event {event_id}"),
        time_created=str(event.get("TimeCreated", "")),
        image=fields.get("Image", "N/A"),
        command_line=fields.get("CommandLine", ""),
        parent_image=fields.get("ParentImage", ""),
        parent_command_line=fields.get("ParentCommandLine", ""),
        user=fields.get("User", ""),
        current_directory=fields.get("CurrentDirectory", ""),
        integrity_level=fields.get("IntegrityLevel", ""),
        process_id=fields.get("ProcessId", ""),
        parent_process_id=fields.get("ParentProcessId", ""),
        utc_time=fields.get("UtcTime", ""),
        destination_ip=fields.get("DestinationIp", ""),
        destination_hostname=fields.get("DestinationHostname", ""),
        destination_port=fields.get("DestinationPort", ""),
        protocol=fields.get("Protocol", ""),
        target_object=fields.get("TargetObject", ""),
        details=fields.get("Details", ""),
    )


def parse_event_record(event: dict) -> SysmonEvent:
    """Alias for pipeline code clarity."""
    return parse_sysmon_message(event)
