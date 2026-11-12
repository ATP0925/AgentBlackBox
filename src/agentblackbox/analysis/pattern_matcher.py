"""Pattern matching for known dangerous operations."""

import re
from typing import List, Optional

from agentblackbox.storage.models import Event, EventType


# Dangerous command patterns
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"rm\s+(-[rRf]+\s+|--recursive|--force)"),
    re.compile(r"git\s+push\s+.*(-f|--force)"),
    re.compile(r"git\s+reset\s+--hard"),
    re.compile(r"git\s+clean\s+-[fFdDxX]"),
    re.compile(r"chmod\s+777"),
    re.compile(r"curl\s.*\|\s*(ba)?sh"),
    re.compile(r"wget\s.*\|\s*(ba)?sh"),
    re.compile(r"dd\s+if=.*of="),
    re.compile(r"mkfs\.", re.IGNORECASE),
    re.compile(r":()\{\s*:\|\s*:&\s*\};\s*:"),  # fork bomb
]


def is_destructive_command(command: str) -> bool:
    """Check if a shell command matches known destructive patterns.

    Args:
        command: The command string to check.

    Returns:
        True if the command is potentially destructive.
    """
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return True
    return False


def classify_event(event: Event) -> List[str]:
    """Add classification tags to an event based on its content.

    Args:
        event: Event to classify.

    Returns:
        List of tags added.
    """
    added_tags: List[str] = []

    if event.event_type == EventType.CMD_EXECUTE:
        cmd = event.payload.get("command", "")
        if is_destructive_command(cmd):
            added_tags.append("destructive")

    if event.event_type in (EventType.GIT_FORCE_PUSH, EventType.GIT_RESET):
        added_tags.append("destructive")

    if event.event_type == EventType.FILE_DELETE:
        added_tags.append("deletion")

    if event.source_path and any(
        s in event.source_path.lower()
        for s in [".env", ".key", ".pem", "secret", "credential", "token"]
    ):
        added_tags.append("sensitive_file")

    event.tags = list(set(event.tags + added_tags))
    return added_tags

