# PHASE 3: Investigation Tools + CLI
# ====================================
# Prerequisites: Phase 2 complete, 34 tests passing.
# After this phase: Timeline replay, blame analysis, search, full CLI work.
# New tests: 18 (total: 52)
#
# READ AGENTS.md FIRST.

## STEP 1: Create src/agentblackbox/replay/timeline.py

```python
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
```

## STEP 2: Create src/agentblackbox/replay/blame.py

```python
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
```

## STEP 3: Create src/agentblackbox/storage/export.py

```python
"""Export session data to JSON, CSV, or HTML formats."""

import csv
import io
import json
from pathlib import Path
from typing import Optional

from agentblackbox.replay.timeline import build_timeline
from agentblackbox.storage.event_store import EventStore


def export_json(store: EventStore, session_id: str) -> str:
    """Export a session and its events as JSON.

    Args:
        store: EventStore to query.
        session_id: Session to export.

    Returns:
        JSON string of session data.
    """
    session = store.get_session(session_id)
    if not session:
        return json.dumps({"error": f"Session {session_id} not found"})

    events = store.query_events(session_id=session_id, limit=100000)

    data = {
        "session": {
            "id": session.id,
            "name": session.name,
            "workspace_path": session.workspace_path,
            "agent_hint": session.agent_hint,
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "status": session.status,
            "total_events": session.total_events,
            "risk_score": session.risk_score,
        },
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "severity": e.severity,
                "risk_score": e.risk_score,
                "source_path": e.source_path,
                "payload": e.payload,
                "tags": e.tags,
            }
            for e in events
        ],
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "description": a.description,
                "acknowledged": a.acknowledged,
            }
            for a in store.get_alerts(session_id=session_id)
        ],
    }
    return json.dumps(data, indent=2, default=str)


def export_csv(store: EventStore, session_id: str) -> str:
    """Export session events as CSV.

    Args:
        store: EventStore to query.
        session_id: Session to export.

    Returns:
        CSV string of events.
    """
    events = store.query_events(session_id=session_id, limit=100000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "event_type", "severity", "risk_score", "source_path", "payload", "tags"])
    for e in events:
        writer.writerow([
            e.id, e.timestamp, e.event_type, e.severity,
            e.risk_score, e.source_path, json.dumps(e.payload),
            ",".join(e.tags),
        ])
    return output.getvalue()


def export_html(store: EventStore, session_id: str) -> str:
    """Export session as a standalone HTML report.

    Args:
        store: EventStore to query.
        session_id: Session to export.

    Returns:
        HTML string of the report.
    """
    session = store.get_session(session_id)
    if not session:
        return "<html><body><h1>Session not found</h1></body></html>"

    timeline = build_timeline(store, session_id)
    alerts = store.get_alerts(session_id=session_id)

    severity_colors = {
        "info": "#3b82f6",
        "warning": "#f59e0b",
        "danger": "#ef4444",
        "critical": "#dc2626",
    }

    rows = ""
    for entry in timeline.entries:
        e = entry.event
        color = severity_colors.get(e.severity, "#6b7280")
        rows += f"""
        <tr>
            <td>{e.timestamp[11:19] if len(e.timestamp) > 19 else e.timestamp}</td>
            <td><span style="color:{color};font-weight:bold">{e.severity.upper()}</span></td>
            <td>{e.risk_score}</td>
            <td>{entry.label}</td>
            <td>{e.source_path or '-'}</td>
        </tr>"""

    alert_rows = ""
    for a in alerts:
        alert_rows += f"<tr><td>{a.alert_type}</td><td>{a.description}</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AgentBlackBox Report — {session.id}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; background: #0a0a0a; color: #e5e5e5; padding: 2rem; }}
  h1 {{ color: #f97316; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #333; padding: 0.5rem; text-align: left; }}
  th {{ background: #1a1a1a; color: #f97316; }}
  tr:hover {{ background: #1a1a1a; }}
  .stat {{ display: inline-block; background: #1a1a1a; padding: 0.5rem 1rem; margin: 0.25rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>🔴 AgentBlackBox Report</h1>
<p><strong>Session:</strong> {session.id} | <strong>Name:</strong> {session.name or 'unnamed'}</p>
<p><strong>Workspace:</strong> {session.workspace_path}</p>
<p><strong>Started:</strong> {session.started_at} | <strong>Ended:</strong> {session.ended_at or 'still recording'}</p>
<p><strong>Status:</strong> {session.status} | <strong>Risk Score:</strong> {session.risk_score}</p>

<div>
  <span class="stat">📊 Total Events: {session.total_events}</span>
  <span class="stat">⚠️ Alerts: {len(alerts)}</span>
</div>

<h2>📋 Timeline</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Risk</th><th>Event</th><th>File</th></tr>
{rows}
</table>

{"<h2>🚨 Alerts</h2><table><tr><th>Type</th><th>Description</th></tr>" + alert_rows + "</table>" if alerts else ""}

<p style="color:#666;margin-top:2rem">Generated by AgentBlackBox v0.1.0</p>
</body>
</html>"""
```

## STEP 4: Create src/agentblackbox/cli/main.py (Full CLI)

Replace the placeholder with the complete CLI:

```python
"""CLI entry point for AgentBlackBox (`abb` command)."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agentblackbox import __version__
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Session

app = typer.Typer(
    name="abb",
    help="AgentBlackBox — The flight recorder for AI agents. 🔴",
    no_args_is_help=True,
)
console = Console()


def _get_store(workspace: Optional[Path] = None) -> EventStore:
    """Get or create an EventStore for the workspace."""
    ws = workspace or Path.cwd()
    config = BlackBoxConfig(workspace_path=ws)
    return EventStore(config.db_path)


@app.command()
def version() -> None:
    """Show AgentBlackBox version."""
    console.print(f"[bold orange1]AgentBlackBox[/] v{__version__}")


@app.command()
def start(
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Session name"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent hint (cursor, claude-code, etc.)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
) -> None:
    """Start a new recording session."""
    ws = workspace or Path.cwd()
    config = BlackBoxConfig(workspace_path=ws)
    store = EventStore(config.db_path)

    session = Session(
        workspace_path=str(ws),
        name=name,
        agent_hint=agent,
    )
    store.create_session(session)

    console.print(f"[bold green]🔴 Recording started[/]")
    console.print(f"  Session: [cyan]{session.id}[/]")
    console.print(f"  Workspace: {ws}")
    if name:
        console.print(f"  Name: {name}")
    console.print(f"\n  Run [bold]abb stop[/] to end recording.")


@app.command()
def stop(
    session_id: Optional[str] = typer.Argument(None, help="Session ID to stop (latest if omitted)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Stop a recording session."""
    store = _get_store(workspace)

    if session_id:
        store.stop_session(session_id)
        console.print(f"[bold yellow]⏹️ Session {session_id} stopped.[/]")
    else:
        sessions = store.list_sessions(limit=1)
        if sessions and sessions[0].status == "recording":
            store.stop_session(sessions[0].id)
            console.print(f"[bold yellow]⏹️ Session {sessions[0].id} stopped.[/]")
        else:
            console.print("[red]No active recording session found.[/]")


@app.command()
def sessions(
    limit: int = typer.Option(10, "--limit", "-l"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """List recording sessions."""
    store = _get_store(workspace)
    all_sessions = store.list_sessions(limit=limit)

    if not all_sessions:
        console.print("[dim]No sessions found.[/]")
        return

    table = Table(title="🔴 Recording Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Started")

    for s in all_sessions:
        status_style = "green" if s.status == "recording" else "dim"
        risk_style = "red bold" if s.risk_score >= 5 else "yellow" if s.risk_score >= 3 else "dim"
        table.add_row(
            s.id,
            s.name or "-",
            f"[{status_style}]{s.status}[/]",
            str(s.total_events),
            f"[{risk_style}]{s.risk_score}[/]",
            s.started_at[:19] if s.started_at else "-",
        )

    console.print(table)


@app.command()
def search(
    query: str = typer.Argument(..., help="Text to search for"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Search events across sessions."""
    store = _get_store(workspace)
    results = store.search_events(query, session_id=session_id)

    if not results:
        console.print(f"[dim]No events matching '{query}'[/]")
        return

    table = Table(title=f"🔍 Search: '{query}' ({len(results)} results)")
    table.add_column("Time", style="dim")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("File")
    table.add_column("Risk", justify="right")

    severity_colors = {"info": "blue", "warning": "yellow", "danger": "red", "critical": "red bold"}

    for e in results[:50]:
        sev_color = severity_colors.get(e.severity, "white")
        table.add_row(
            e.timestamp[11:19] if len(e.timestamp) > 19 else e.timestamp,
            e.event_type,
            f"[{sev_color}]{e.severity}[/]",
            (e.source_path or "-")[-40:],
            str(e.risk_score),
        )

    console.print(table)


@app.command()
def blame(
    file_path: str = typer.Argument(..., help="File path to blame"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Show which events modified a file."""
    from agentblackbox.replay.blame import blame_file

    store = _get_store(workspace)
    entries = blame_file(store, file_path, session_id=session_id)

    if not entries:
        console.print(f"[dim]No events found for '{file_path}'[/]")
        return

    table = Table(title=f"📋 Blame: {file_path}")
    table.add_column("Time", style="dim")
    table.add_column("Action")
    table.add_column("Session")
    table.add_column("Risk", justify="right")

    for entry in entries:
        table.add_row(
            entry.event.timestamp[11:19],
            entry.action,
            entry.session_id[:16],
            str(entry.event.risk_score),
        )

    console.print(table)


@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session ID to export"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: json, csv, html"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Export a session report."""
    from agentblackbox.storage.export import export_json, export_csv, export_html

    store = _get_store(workspace)

    exporters = {
        "json": export_json,
        "csv": export_csv,
        "html": export_html,
    }

    if format not in exporters:
        console.print(f"[red]Unknown format: {format}. Use json, csv, or html.[/]")
        raise typer.Exit(1)

    content = exporters[format](store, session_id)

    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Report saved to {output}[/]")
    else:
        # Default output path
        ext = format
        out_path = Path(f"blackbox_report_{session_id[:12]}.{ext}")
        out_path.write_text(content, encoding="utf-8")
        console.print(f"[green]Report saved to {out_path}[/]")


@app.command()
def alerts(
    session_id: Optional[str] = typer.Option(None, "--session", "-s"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Show alerts for a session."""
    store = _get_store(workspace)
    all_alerts = store.get_alerts(session_id=session_id, unacked_only=True)

    if not all_alerts:
        console.print("[green]✅ No unacknowledged alerts.[/]")
        return

    table = Table(title="🚨 Alerts")
    table.add_column("ID", style="dim")
    table.add_column("Type", style="red")
    table.add_column("Description")
    table.add_column("Session")

    for a in all_alerts:
        table.add_row(
            str(a.id),
            a.alert_type,
            a.description,
            a.session_id[:16],
        )

    console.print(table)
```

## STEP 5: Create tests/test_replay/test_timeline.py

```python
"""Tests for timeline builder."""

import pytest
from agentblackbox.replay.timeline import build_timeline, _event_label, _parse_iso_ms
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity


class TestParseIsoMs:
    """Test ISO timestamp parsing."""

    def test_parse_utc(self) -> None:
        ms = _parse_iso_ms("2026-11-12T15:00:00+00:00")
        assert ms > 0

    def test_parse_empty(self) -> None:
        assert _parse_iso_ms("") == 0

    def test_parse_invalid(self) -> None:
        assert _parse_iso_ms("not-a-date") == 0


class TestEventLabel:
    """Test human-readable event labels."""

    def test_file_create_label(self) -> None:
        e = Event(session_id="s", event_type=EventType.FILE_CREATE, source_path="src/main.py")
        label = _event_label(e)
        assert "Created" in label
        assert "main.py" in label

    def test_cmd_execute_label(self) -> None:
        e = Event(session_id="s", event_type=EventType.CMD_EXECUTE, payload={"command": "npm install"})
        label = _event_label(e)
        assert "npm install" in label

    def test_secret_label(self) -> None:
        e = Event(session_id="s", event_type=EventType.SECRET_DETECTED,
                  payload={"secret_type": "aws_access_key"}, source_path=".env")
        label = _event_label(e)
        assert "SECRET" in label


class TestBuildTimeline:
    """Test timeline construction from stored events."""

    def test_empty_timeline(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        timeline = build_timeline(store, sample_session.id)
        assert len(timeline.entries) == 0

    def test_timeline_order(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        for i in range(5):
            store.insert_event(Event(
                session_id=sample_session.id,
                event_type=EventType.FILE_MODIFY,
                source_path=f"file{i}.py",
            ))
        timeline = build_timeline(store, sample_session.id)
        assert len(timeline.entries) == 5
        assert timeline.stats.get("total") == 5

    def test_timeline_stats(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_DELETE))
        timeline = build_timeline(store, sample_session.id)
        assert timeline.stats.get("file_create") == 2
        assert timeline.stats.get("file_delete") == 1

    def test_timeline_filter_by_type(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.CMD_EXECUTE, payload={"command": "ls"}))
        timeline = build_timeline(store, sample_session.id, event_type=EventType.FILE_CREATE)
        assert len(timeline.entries) == 1
        assert timeline.entries[0].event.event_type == EventType.FILE_CREATE
```

## STEP 6: Create tests/test_replay/test_blame.py (new file)

```python
"""Tests for blame analysis."""

import pytest
from agentblackbox.replay.blame import blame_file, last_modifier
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session


class TestBlame:
    """Test file blame functionality."""

    def test_blame_single_event(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_CREATE,
            source_path="src/auth.py",
        ))
        entries = blame_file(store, "src/auth.py")
        assert len(entries) == 1
        assert entries[0].action == "created"

    def test_blame_multiple_events(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path="src/auth.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="src/auth.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="src/auth.py"))
        entries = blame_file(store, "src/auth.py")
        assert len(entries) == 3
        # Most recent first
        assert entries[0].action == "modified"

    def test_blame_no_events(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        entries = blame_file(store, "nonexistent.py")
        assert len(entries) == 0

    def test_last_modifier(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path="x.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="x.py"))
        result = last_modifier(store, "x.py")
        assert result is not None
        assert result.action == "modified"

    def test_last_modifier_none(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        assert last_modifier(store, "nope.py") is None
```

## STEP 7: Run Phase 3 tests

```bash
cd AgentBlackBox
python -m pytest tests/ -v --tb=short
```

### Expected: 52 total tests passing

## ✅ PHASE 3 COMPLETE CHECKLIST
- [ ] replay/timeline.py — build_timeline + labels + stats
- [ ] replay/blame.py — blame_file + last_modifier
- [ ] storage/export.py — JSON, CSV, HTML export
- [ ] cli/main.py — full CLI with start/stop/sessions/search/blame/report/alerts
- [ ] test_timeline.py — 8 tests
- [ ] test_blame.py — 5 tests
- [ ] ALL 52 tests PASS

## NEXT: Read `.build/phase4_api.md`

