def make_event(
    *,
    image: str = r"C:\Windows\System32\notepad.exe",
    command_line: str = "notepad.exe notes.txt",
    parent_image: str = r"C:\Windows\explorer.exe",
    parent_command_line: str = r"C:\Windows\explorer.exe",
    current_directory: str = r"C:\Users\analyst\Documents",
    user: str = r"CORP\analyst",
) -> dict:
    message = "\r\n".join(
        [
            "Process Create:",
            "UtcTime: 2026-01-15 10:00:00.000",
            "ProcessId: 4000",
            f"Image: {image}",
            f"CommandLine: {command_line}",
            f"CurrentDirectory: {current_directory}",
            f"User: {user}",
            "IntegrityLevel: Medium",
            "ParentProcessId: 2000",
            f"ParentImage: {parent_image}",
            f"ParentCommandLine: {parent_command_line}",
            f"ParentUser: {user}",
        ]
    )
    return {"Id": 1, "TimeCreated": "/Date(1785000000000)/", "Message": message}
