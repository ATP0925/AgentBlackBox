"""CLI entry point for AgentBlackBox (`abb` command)."""

import json
import os
import secrets
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, List, Optional

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from agentblackbox import __version__
from agentblackbox.collectors.ide_hooks import UniversalIDECollector
from agentblackbox.context.diff_parser import parse_unified_diff
from agentblackbox.core.config import ReviewConfig
from agentblackbox.core.engine import ReviewEngine
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.daemon.core import (
    get_daemon_state,
    is_pid_alive,
    start_background_daemon,
    stop_background_daemon,
)
from agentblackbox.integrations.git_client import GitClient
from agentblackbox.models.finding import Severity
from agentblackbox.reporting.terminal import render_terminal_report
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session
from agentblackbox.watchers.agent_hooks import install_claude_hook
from agentblackbox.watchers.terminal import run_recorded_command

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="abb",
    help="AgentBlackBox -- AI-powered code analysis, automated code review, and flight recorder.",
    no_args_is_help=True,
)
console = Console()


@dataclass(frozen=True)
class CLIContext:
    workspace: Path
    abb_dir: Path
    db_path: Path
    pid_path: Path
    state_path: Path
    log_path: Path

    @classmethod
    def resolve(cls, workspace: Path | None = None) -> "CLIContext":
        root = (workspace or Path.cwd()).resolve()
        abb_dir = root / ".agentblackbox"
        abb_dir.mkdir(parents=True, exist_ok=True)
        if (abb_dir / "events.db").exists():
            db_path = abb_dir / "events.db"
        elif (abb_dir / "blackbox.db").exists():
            db_path = abb_dir / "blackbox.db"
        else:
            db_path = abb_dir / "blackbox.db"
        return cls(
            workspace=root,
            abb_dir=abb_dir,
            db_path=db_path,
            pid_path=abb_dir / "daemon.pid",
            state_path=abb_dir / "daemon.json",
            log_path=abb_dir / "daemon.log",
        )

    def open_store(self) -> EventStore:
        return EventStore(self.db_path)

    def active_daemon_pid(self) -> int | None:
        if not self.pid_path.exists():
            return None
        try:
            pid = int(self.pid_path.read_text(encoding="utf-8").strip())
        except ValueError:
            return None
        if is_pid_alive(pid):
            return pid
        # Clean up stale PID file automatically
        self.pid_path.unlink(missing_ok=True)
        return None


def cli_abort(message: str, code: int = 1) -> None:
    # Print formatted error and exit with a non-zero status code for CI/scripts.
    console.print(f"[bold red]Error:[/bold red] {message}")
    raise typer.Exit(code=code)


def _get_store(workspace: Optional[Path] = None) -> EventStore:
    """Get or create an EventStore for the workspace."""
    ctx = CLIContext.resolve(workspace)
    return ctx.open_store()


@app.command()
def version() -> None:
    """Show AgentBlackBox version."""
    console.print(f"[bold orange1]AgentBlackBox[/] v{__version__}")


@app.command()
def start(
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Session name"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent hint (cursor, claude-code, etc.)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
    no_daemon: bool = typer.Option(False, "--no-daemon", help="Create session record only without background watcher"),
) -> None:
    """Start a live background recording session."""
    ws = workspace or Path.cwd()
    config = BlackBoxConfig(workspace_path=ws)

    if no_daemon:
        store = EventStore(config.db_path)
        session = Session(workspace_path=str(ws), name=name, agent_hint=agent)
        store.create_session(session)
        console.print(f"[bold green]🔴 Session created (no-daemon)[/]: [cyan]{session.id}[/]")
        return

    try:
        state = start_background_daemon(config, name=name, agent_hint=agent)
    except RuntimeError as exc:
        cli_abort(str(exc))

    console.print("[bold green]🔴 Live recording started[/]")
    console.print(f"  Session:   [cyan]{state.session_id}[/]")
    console.print(f"  PID:       {state.pid}")
    console.print(f"  Workspace: {ws}")
    if name:
        console.print(f"  Name:      {name}")
    console.print("\n  Run [bold]abb stop[/] to end recording.")


@app.command()
def stop(
    session_id: Optional[str] = typer.Argument(None, help="Session ID to stop (latest/active if omitted)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Stop the live recording daemon and session."""
    ws = workspace or Path.cwd()
    config = BlackBoxConfig(workspace_path=ws)

    active_state = get_daemon_state(config)
    if active_state and (not session_id or active_state.session_id == session_id):
        stopped_state = stop_background_daemon(config)
        if stopped_state:
            console.print(
                f"[bold yellow]⏹️ Daemon (PID {stopped_state.pid}) & session "
                f"{stopped_state.session_id} stopped.[/]"
            )
            return

    store = _get_store(ws)
    if session_id:
        store.stop_session(session_id)
        console.print(f"[bold yellow]⏹️ Session {session_id} stopped.[/]")
    else:
        sessions = store.list_sessions(limit=1)
        if sessions and sessions[0].status == "recording":
            store.stop_session(sessions[0].id)
            console.print(f"[bold yellow]⏹️ Session {sessions[0].id} stopped.[/]")
        else:
            cli_abort("No active recording session found.")


@app.command()
def status(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Show whether a background recording daemon is active."""
    ws = workspace or Path.cwd()
    config = BlackBoxConfig(workspace_path=ws)
    state = get_daemon_state(config)
    if not state:
        console.print("[dim]No active AgentBlackBox daemon running in this workspace.[/]")
        return

    store = EventStore(config.db_path)
    session = store.get_session(state.session_id)
    events_count = session.total_events if session else 0
    console.print("[bold green]🟢 Daemon ACTIVE[/]")
    console.print(f"  Session:   [cyan]{state.session_id}[/]")
    console.print(f"  PID:       {state.pid}")
    console.print(f"  Events:    {events_count}")
    console.print(f"  Workspace: {state.workspace_path}")


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    command: List[str] = typer.Argument(..., help="Command and arguments to execute and record"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent identifier"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID (uses active if omitted)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Execute a command while recording stdin/stdout, exit code, and attribution."""
    ws = workspace or Path.cwd()
    config = BlackBoxConfig(workspace_path=ws)
    store = EventStore(config.db_path)

    target_sid = session_id
    auto_created = False
    if not target_sid:
        state = get_daemon_state(config)
        if state:
            target_sid = state.session_id
        else:
            existing = store.list_sessions(limit=1)
            if existing and existing[0].status == "recording":
                target_sid = existing[0].id
            else:
                sess = Session(workspace_path=str(ws), name="abb-run", agent_hint=agent)
                store.create_session(sess)
                target_sid = sess.id
                auto_created = True

    if len(command) == 1:
        cmd_str = command[0]
    elif sys.platform == "win32":
        cmd_str = subprocess.list2cmdline(command)
    else:
        cmd_str = shlex.join(command)
    result = run_recorded_command(
        store=store,
        session_id=target_sid,
        command=cmd_str,
        workspace=ws,
        agent_id=agent,
    )
    if auto_created:
        store.stop_session(target_sid)

    if result.stdout:
        console.print(result.stdout, end="")
    if result.stderr:
        console.print(f"[red]{result.stderr}[/]", end="")
    if result.exit_code != 0:
        cli_abort(f"Command exited with code {result.exit_code}", code=result.exit_code)


@app.command("hook-install")
def hook_install(
    agent: str = typer.Option("claude-code", "--agent", "-a", help="Target agent (claude-code)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Install agent attribution hooks (e.g., Claude Code PreToolUse hook)."""
    ws = workspace or Path.cwd()
    if agent.lower() != "claude-code":
        cli_abort(f"Unsupported agent '{agent}'. Currently supported: claude-code")
    path = install_claude_hook(ws)
    console.print(f"[bold green]✅ Installed Claude Code hook[/] at [cyan]{path}[/]")


@app.command("hook-ingest")
def hook_ingest(
    log_file: Optional[Path] = typer.Argument(None, help="Path to JSON/JSONL IDE log file"),
    source: str = typer.Option("auto", "--source", "-s", help="Source agent (auto|claude_code|cursor|cline|antigravity)"),
    session_id: Optional[str] = typer.Option(None, "--session", help="Session ID to record events into"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Ingest and normalize tool events from Cursor, Cline, Claude Code, or Antigravity IDE."""
    ws = workspace or Path.cwd()
    store = _get_store(ws)

    target_sid = session_id
    if not target_sid:
        active = store.get_active_session()
        if active:
            target_sid = active.id
        else:
            sess = Session(workspace_path=str(ws), name="ide-hooks", agent_hint=source)
            store.create_session(sess)
            target_sid = sess.id

    raw_events: list[dict[str, Any]] = []
    if log_file and log_file.exists():
        raw_events = UniversalIDECollector.ingest_ide_log_file(log_file, source_hint=source)
    else:
        # Read from stdin if available
        if not sys.stdin.isatty():
            content = sys.stdin.read().strip()
            if content:
                try:
                    if content.startswith("["):
                        items = json.loads(content)
                        for item in items:
                            if isinstance(item, dict):
                                raw_events.append(asdict(UniversalIDECollector.parse_hook_payload(item, source_hint=source)))
                    elif content.startswith("{"):
                        item = json.loads(content)
                        raw_events.append(asdict(UniversalIDECollector.parse_hook_payload(item, source_hint=source)))
                    else:
                        for line in content.splitlines():
                            line = line.strip()
                            if line:
                                item = json.loads(line)
                                raw_events.append(asdict(UniversalIDECollector.parse_hook_payload(item, source_hint=source)))
                except Exception as e:
                    console.print(f"[red]Failed to parse stdin: {e}[/]")
                    raise typer.Exit(1)

    if not raw_events:
        console.print("[yellow]No events parsed to ingest.[/]")
        return

    ingested = 0
    for rev in raw_events:
        ev_type = (
            EventType.CMD_EXECUTE if rev.get("event_type") == "terminal_cmd"
            else (EventType.FILE_MODIFY if rev.get("event_type") in ("file_edit", "mcp_call")
                  else EventType.API_REQUEST)
        )
        ev = Event(
            session_id=target_sid,
            event_type=ev_type,
            source_path=rev.get("target_resource"),
            agent_id=rev.get("agent_source"),
            payload={
                "tool_name": rev.get("tool_name"),
                "arguments": rev.get("raw_arguments"),
            },
            tags=[f"agent:{rev.get('agent_source')}", f"tool:{rev.get('tool_name')}"],
        )
        store.insert_event(ev)
        ingested += 1

    console.print(f"[bold green]✅ Ingested {ingested} normalized events[/] into session [cyan]{target_sid}[/]")


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
    table.add_column("ID", style="cyan", no_wrap=True)
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


@app.command("export-checkpoint")
def export_checkpoint(
    session_id: str = typer.Argument(..., help="Session ID to checkpoint"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File to write checkpoint JSON to"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Export head-tip checkpoint JSON to an external file or stdout."""
    store = _get_store(workspace)
    session = store.get_session(session_id)
    if not session:
        console.print(f"[red]Session '{session_id}' not found.[/]")
        raise typer.Exit(1)
    cp_path = store.checkpoint_chain_tip(session_id, checkpoint_path=output)
    content = cp_path.read_text(encoding="utf-8")
    if output:
        console.print(f"[green]Checkpoint exported to [cyan]{cp_path}[/][/]")
    else:
        console.print(content)


@app.command()
def verify(
    session_id: str = typer.Argument(..., help="Session ID to verify hash-chain integrity"),
    checkpoint: Optional[Path] = typer.Option(None, "--checkpoint", "-c", help="Path to checkpoint file for truncation check"),
    require_keyed: bool = typer.Option(False, "--require-keyed", help="Require session to be signed with HMAC key"),
    require_checkpoint: bool = typer.Option(False, "--require-checkpoint", help="Require checkpoint file to exist and verify"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Verify tamper-evident hash chain for a session."""
    store = _get_store(workspace)
    session = store.get_session(session_id)
    if not session:
        console.print(f"[red]Session '{session_id}' not found.[/]")
        raise typer.Exit(1)

    res = store.verify_chain(
        session_id,
        checkpoint_path=checkpoint,
        require_keyed=require_keyed,
        require_checkpoint=require_checkpoint,
    )
    if res.valid:
        note_str = f" [dim]({res.notes})[/]" if res.notes else ""
        console.print(
            f"[bold green]✅ Chain INTACT[/] for [cyan]{session_id}[/] "
            f"({res.total_events} events verified){note_str}"
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


@app.command()
def review(
    target: Optional[str] = typer.Argument(
        None,
        help="Git ref, commit range (e.g. HEAD~1..HEAD), branch, or omit for working tree changes",
    ),
    base: Optional[str] = typer.Option(
        None,
        "--base",
        "-b",
        help="Base branch/ref to compare against (e.g. main)",
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, markdown, json, sarif",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write report output directly to file path",
    ),
    min_severity: str = typer.Option(
        "low",
        "--min-severity",
        "-s",
        help="Minimum severity threshold: critical, high, medium, low, info",
    ),
    ai: Optional[str] = typer.Option(
        None,
        "--ai",
        help="Enable AI reasoning layer: gemini, openai, anthropic, or offline",
    ),
    ai_model: Optional[str] = typer.Option(
        None,
        "--ai-model",
        help="AI model name override",
    ),
    max_tokens: int = typer.Option(
        8000,
        "--max-tokens",
        help="Maximum context token budget for AI reasoning",
    ),
    exit_zero: bool = typer.Option(
        False,
        "--exit-zero",
        help="Always exit with 0 even if Critical or High severity findings are found",
    ),
    workspace: Optional[Path] = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Repository workspace root path",
    ),
) -> None:
    """Review code changes (PR diff, commit range, or unstaged working tree) using AI & static analysis."""
    repo_root = workspace or Path.cwd()
    git_client = GitClient(repo_root)

    if not git_client.is_git_repository():
        console.print(f"[bold red]Error:[/] '{repo_root}' is not a valid git repository.")
        raise typer.Exit(1)

    # Determine diff
    if target:
        if base:
            raw_diff = git_client.get_branch_diff(base=base, head=target)
        elif ".." in target:
            parts = target.split("..", 1)
            raw_diff = git_client.get_branch_diff(base=parts[0], head=parts[1])
        else:
            raw_diff = git_client.get_commit_diff(target)
    else:
        # Working tree changes
        raw_diff = git_client.get_working_tree_diff(staged=False, untracked=True)
        if not raw_diff.strip():
            raw_diff = git_client.get_working_tree_diff(staged=True)

    git_diff = parse_unified_diff(raw_diff)

    sev = Severity.from_str(min_severity)
    config = ReviewConfig(
        min_severity=sev,
        enable_ai=bool(ai),
        ai_provider=ai,
        ai_model=ai_model,
        max_context_tokens=max_tokens,
    )
    engine = ReviewEngine(config=config, git_client=git_client)
    report = engine.review_diff(git_diff, repo_root=repo_root)

    # Handle output
    fmt = format.lower()
    if fmt == "terminal":
        render_terminal_report(report, console=console)
        if output:
            output.write_text(report.to_markdown(), encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
    elif fmt == "markdown":
        md = report.to_markdown()
        if output:
            output.write_text(md, encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
        else:
            print(md)
    elif fmt == "json":
        data = json.dumps(report.to_dict(), indent=2)
        if output:
            output.write_text(data, encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
        else:
            print(data)
    elif fmt == "sarif":
        sarif_data = json.dumps(report.to_sarif(), indent=2)
        if output:
            output.write_text(sarif_data, encoding="utf-8")
            console.print(f"[dim]SARIF report saved to {output}[/]")
        else:
            print(sarif_data)
    else:
        console.print(f"[bold red]Unknown format:[/] {format}. Use terminal, markdown, json, or sarif.")
        raise typer.Exit(1)

    if not exit_zero and report.has_critical_or_high:
        raise typer.Exit(1)


@app.command()
def analyze(
    path: Optional[Path] = typer.Argument(
        None,
        help="Path to repository directory or single source file to analyze",
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, markdown, json, sarif",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write report output directly to file path",
    ),
    min_severity: str = typer.Option(
        "low",
        "--min-severity",
        "-s",
        help="Minimum severity threshold: critical, high, medium, low, info",
    ),
    ai: Optional[str] = typer.Option(
        None,
        "--ai",
        help="Enable AI reasoning layer: gemini, openai, anthropic, or offline",
    ),
    ai_model: Optional[str] = typer.Option(
        None,
        "--ai-model",
        help="AI model name override",
    ),
    max_tokens: int = typer.Option(
        8000,
        "--max-tokens",
        help="Maximum context token budget for AI reasoning",
    ),
    exit_zero: bool = typer.Option(
        False,
        "--exit-zero",
        help="Always exit with 0 even if Critical or High severity findings are found",
    ),
) -> None:
    """Analyze a repository or individual source file for security, bugs, performance, and code quality."""
    target_path = path or Path.cwd()
    target_path = target_path.resolve()

    if not target_path.exists():
        console.print(f"[bold red]Error:[/] Path '{target_path}' does not exist.")
        raise typer.Exit(1)

    sev = Severity.from_str(min_severity)
    config = ReviewConfig(
        min_severity=sev,
        enable_ai=bool(ai),
        ai_provider=ai,
        ai_model=ai_model,
        max_context_tokens=max_tokens,
    )
    engine = ReviewEngine(config=config)

    if target_path.is_file():
        report = engine.analyze_file(target_path)
    else:
        report = engine.analyze_repository(target_path)

    fmt = format.lower()
    if fmt == "terminal":
        render_terminal_report(report, console=console)
        if output:
            output.write_text(report.to_markdown(), encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
    elif fmt == "markdown":
        md = report.to_markdown()
        if output:
            output.write_text(md, encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
        else:
            print(md)
    elif fmt == "json":
        data = json.dumps(report.to_dict(), indent=2)
        if output:
            output.write_text(data, encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
        else:
            print(data)
    elif fmt == "sarif":
        sarif_data = json.dumps(report.to_sarif(), indent=2)
        if output:
            output.write_text(sarif_data, encoding="utf-8")
            console.print(f"[dim]SARIF report saved to {output}[/]")
        else:
            print(sarif_data)
    else:
        console.print(f"[bold red]Unknown format:[/] {format}. Use terminal, markdown, json, or sarif.")
        raise typer.Exit(1)

    if not exit_zero and report.has_critical_or_high:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
