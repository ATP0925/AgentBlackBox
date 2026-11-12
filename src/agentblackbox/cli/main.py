"""CLI entry point for AgentBlackBox (`abb` command)."""

import os
import secrets
from pathlib import Path
from typing import Optional

import typer
import uvicorn
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


@app.command()
def verify(
    session_id: str = typer.Argument(..., help="Session ID to verify hash-chain integrity"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Verify tamper-evident hash chain for a session."""
    store = _get_store(workspace)
    session = store.get_session(session_id)
    if not session:
        console.print(f"[red]Session '{session_id}' not found.[/]")
        raise typer.Exit(1)

    res = store.verify_chain(session_id)
    if res.valid:
        console.print(
            f"[bold green]✅ Chain INTACT[/] for [cyan]{session_id}[/] "
            f"({res.total_events} events verified)"
        )
    else:
        console.print(
            f"[bold red]❌ TAMPERING DETECTED[/] in [cyan]{session_id}[/] "
            f"at seq={res.broken_at_seq}: {res.reason}"
        )
        raise typer.Exit(1)


@app.command()
def serve(
    port: int = typer.Option(7700, "--port", "-p", help="Local port to bind"),
    no_auth: bool = typer.Option(False, "--no-auth", help="Disable bearer token auth"),
) -> None:
    """Start the local AgentBlackBox API server bound to 127.0.0.1."""
    if not no_auth and not os.environ.get("ABB_API_TOKEN"):
        token = secrets.token_urlsafe(24)
        os.environ["ABB_API_TOKEN"] = token
        console.print(f"[bold yellow]🔒 Generated local API token:[/] [cyan]{token}[/]")
        console.print("   Pass header: [dim]Authorization: Bearer <token>[/]")

    console.print(f"[bold green]🚀 Starting AgentBlackBox API[/] on http://127.0.0.1:{port}")
    uvicorn.run("agentblackbox.api.main:app", host="127.0.0.1", port=port)
