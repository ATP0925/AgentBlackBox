"""Timeline builder — reconstructs chronological event sequences for replay."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, Severity


@dataclass
class TimelineEntry:
    """A single entry in a session timeline.

    Attributes:
        event: The underlying event.
        relative_ms: Milliseconds since session start.
        label: Human-readable one-line description.
    """

    event: Event
    relative_ms: int
    label: str


@dataclass
class Timeline:
    """A complete session timeline for replay.

    Attributes:
        session_id: The session this timeline belongs to.
        entries: Ordered list of timeline entries.
        duration_ms: Total duration in milliseconds.
        stats: Summary statistics.
    """

    session_id: str
    entries: List[TimelineEntry] = field(default_factory=list)
    duration_ms: int = 0
    stats: Dict[str, int] = field(default_factory=dict)


def _event_label(event: Event) -> str:
    """Generate a human-readable label for an event.

    Args:
        event: The event to label.

    Returns:
        Short description string.
    """
    path = event.source_path or ""
    short_path = path.split("/")[-1] if "/" in path else path.split("\\")[-1] if "\\" in path else path

    labels = {
        "file_create": f"📄 Created {short_path}",
        "file_modify": f"✏️ Modified {short_path}",
        "file_delete": f"🗑️ Deleted {short_path}",
        "file_rename": f"📁 Renamed {short_path} → {event.payload.get('dest_path', '?').split('/')[-1]}",
        "cmd_execute": f"💻 Ran: {event.payload.get('command', '?')[:60]}",
        "cmd_output": f"📤 Output ({len(event.payload.get('output', ''))} chars)",
        "git_add": f"➕ git add {short_path}",
        "git_commit": f"📝 git commit: {event.payload.get('message', '?')[:40]}",
        "git_push": f"🚀 git push",
        "git_force_push": f"⚠️ git push --force",
        "git_reset": f"⏪ git reset",
        "process_spawn": f"🔧 Process started: {event.payload.get('name', '?')}",
        "process_exit": f"⏹️ Process exited (code {event.payload.get('exit_code', '?')})",
        "secret_detected": f"🔴 SECRET: {event.payload.get('secret_type', 'unknown')} in {short_path}",
    }
    return labels.get(event.event_type, f"❓ {event.event_type}")


def _parse_iso_ms(iso_str: str) -> int:
    """Parse ISO 8601 timestamp to milliseconds since epoch.

    Args:
        iso_str: ISO 8601 formatted timestamp.

    Returns:
        Milliseconds since Unix epoch.
    """
    from datetime import datetime, timezone
    try:
        # Handle both Z suffix and +00:00
        clean = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return 0


def build_timeline(
    store: EventStore,
    session_id: str,
    event_type: Optional[str] = None,
    min_severity: Optional[str] = None,
) -> Timeline:
    """Build a complete timeline for a session.

    Args:
        store: EventStore to query.
        session_id: Session to build timeline for.
        event_type: Optional filter by event type.
        min_severity: Optional minimum severity to include.

    Returns:
        Timeline with ordered entries and statistics.
    """
    events = store.query_events(
        session_id=session_id,
        event_type=event_type,
        limit=10000,
    )

    # Filter by severity if requested
    severity_order = {
        Severity.INFO: 0,
        Severity.WARNING: 1,
        Severity.DANGER: 2,
        Severity.CRITICAL: 3,
    }
    if min_severity and min_severity in severity_order:
        min_level = severity_order[min_severity]
        events = [e for e in events if severity_order.get(e.severity, 0) >= min_level]

    if not events:
        return Timeline(session_id=session_id)

    # Calculate relative timestamps
    start_ms = _parse_iso_ms(events[0].timestamp)
    entries = []
    for event in events:
        event_ms = _parse_iso_ms(event.timestamp)
        entries.append(TimelineEntry(
            event=event,
            relative_ms=max(0, event_ms - start_ms),
            label=_event_label(event),
        ))

    # Compute stats
    type_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    for e in events:
        type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

    duration_ms = (entries[-1].relative_ms - entries[0].relative_ms) if len(entries) > 1 else 0

    return Timeline(
        session_id=session_id,
        entries=entries,
        duration_ms=duration_ms,
        stats={**type_counts, **severity_counts, "total": len(entries)},
    )

