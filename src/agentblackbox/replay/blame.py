"""Blame analysis — trace which events changed a specific file."""

from dataclasses import dataclass
from typing import List, Optional

from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event


@dataclass
class BlameEntry:
    """A blame result showing which event last touched a file.

    Attributes:
        file_path: The file being blamed.
        event: The event that touched this file.
        action: What happened (created, modified, deleted, renamed).
        session_id: Which session this occurred in.
    """

    file_path: str
    event: Event
    action: str
    session_id: str


def blame_file(store: EventStore, file_path: str, session_id: Optional[str] = None) -> List[BlameEntry]:
    """Find all events that touched a specific file.

    Returns results in reverse chronological order (most recent first).

    Args:
        store: EventStore to query.
        file_path: File path to look up.
        session_id: Optional session filter.

    Returns:
        List of BlameEntry objects, newest first.
    """
    events = store.get_events_for_file(file_path)

    if session_id:
        events = [e for e in events if e.session_id == session_id]

    action_map = {
        "file_create": "created",
        "file_modify": "modified",
        "file_delete": "deleted",
        "file_rename": "renamed",
        "git_add": "staged",
    }

    entries = [
        BlameEntry(
            file_path=file_path,
            event=e,
            action=action_map.get(e.event_type, e.event_type),
            session_id=e.session_id,
        )
        for e in events
    ]

    # Reverse to get most recent first
    entries.reverse()
    return entries


def last_modifier(store: EventStore, file_path: str) -> Optional[BlameEntry]:
    """Find the single most recent event that modified a file.

    Args:
        store: EventStore to query.
        file_path: File path to look up.

    Returns:
        Most recent BlameEntry, or None if file has no events.
    """
    entries = blame_file(store, file_path)
    return entries[0] if entries else None

