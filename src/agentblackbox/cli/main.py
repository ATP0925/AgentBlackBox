"""CLI entry point for AgentBlackBox (`abb` command)."""

import json
import os
import secrets
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
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
from agentblackbox.analysis.alerting import maybe_create_alert
from agentblackbox.analysis.pattern_matcher import classify_event
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.integrations.git_client import GitClient
from agentblackbox.models.finding import Severity
from agentblackbox.reporting.terminal import render_terminal_report
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session
from agentblackbox.watchers.agent_hooks import install_claude_hook, install_agent_hook
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
    help="AgentBlackBox (abb) -- Cryptographic AI flight recorder, real-time architectural drift guard, and automated code review engine for autonomous agents.",
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
    agent: str = typer.Option("claude", "--agent", "-a", help="Target agent: claude, codex, cursor, gemini, or all"),
    is_global: bool = typer.Option(False, "--global/--project", help="Install hook globally in user home or locally in project workspace"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Install agent attribution and safety hooks across Claude Code, Codex, Cursor, Gemini, and Git."""
    ws = workspace or Path.cwd()
    try:
        installed = install_agent_hook(ws, agent=agent, is_global=is_global)
        for ag, path in installed.items():
            console.print(f"[bold green]✅ Installed {ag} hook[/] at [cyan]{path}[/]")
    except ValueError as exc:
        cli_abort(str(exc))


@app.command("hook-verify")
def hook_verify(
    is_global: bool = typer.Option(False, "--global/--project", help="Verify global user hooks instead of workspace project hooks"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Verify that installed agent hooks still exist and have not been removed or disabled."""
    from agentblackbox.watchers.agent_hooks import verify_agent_hooks

    ws = (workspace or Path.cwd()).resolve()
    results = verify_agent_hooks(ws, is_global=is_global)

    table = Table(title=f"Agent Hook Verification ({'Global' if is_global else 'Project Scope'})")
    table.add_column("Agent", style="cyan")
    table.add_column("Config File", style="white")
    table.add_column("Status", style="bold")

    for agent_name, info in results.items():
        status_str = f"[bold green]{info['status']}[/]" if info["status"] == "OK" else f"[bold red]{info['status']}[/]"
        table.add_row(agent_name, str(info["path"]), status_str)

    console.print(table)


@app.command("hook-ingest")
def hook_ingest(
    log_file: Optional[Path] = typer.Argument(None, help="Path to JSON/JSONL IDE log file"),
    source: str = typer.Option("auto", "--source", "-s", help="Source agent (auto|claude_code|codex|cursor|cline|antigravity)"),
    session_id: Optional[str] = typer.Option(None, "--session", help="Session ID to record events into"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Ingest and normalize tool events from Cursor, Cline, Claude Code, or Antigravity IDE."""
    ws = workspace or Path.cwd()
    store = _get_store(ws)

    target_sid = session_id
    if not target_sid:
        sessions = store.list_sessions(limit=1)
        if sessions and sessions[0].status == "recording":
            target_sid = sessions[0].id
        else:
            sess = Session(workspace_path=str(ws), name="agent-hooks", agent_hint=source)
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
        raw_type = rev.get("event_type")
        tool_name = str(rev.get("tool_name") or "")
        if raw_type in ("terminal_cmd", EventType.CMD_EXECUTE):
            ev_type = EventType.CMD_EXECUTE
        elif raw_type in ("mcp_call", EventType.PROCESS_SPAWN) or "mcp" in tool_name.lower():
            ev_type = EventType.PROCESS_SPAWN
        elif raw_type in ("file_edit", EventType.FILE_MODIFY):
            ev_type = EventType.FILE_MODIFY
        else:
            ev_type = EventType.PROCESS_SPAWN

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
        classify_event(ev)
        score_event(ev)
        stored = store.insert_event(ev)
        maybe_create_alert(store, stored)
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
    format: str = typer.Option("html", "--format", "-f", help="Output format: json, csv, html, sarif"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Export a session report in JSON, CSV, HTML, or SARIF v2.1.0."""
    from agentblackbox.storage.export import export_json, export_csv, export_html, export_sarif

    store = _get_store(workspace)

    exporters = {
        "json": export_json,
        "csv": export_csv,
        "html": export_html,
        "sarif": lambda s, sid: json.dumps(export_sarif(s, sid), indent=2),
    }

    if format not in exporters:
        console.print(f"[red]Unknown format: {format}. Use json, csv, html, or sarif.[/]")
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
def audit(
    session_id: Optional[str] = typer.Argument(
        None,
        help="Session ID to audit (defaults to latest active session if omitted)",
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
        help="Write audit report directly to file path",
    ),
    workspace: Optional[Path] = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Workspace root containing .agentblackbox store",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit with non-zero code if hash-chain tampering or critical findings exist",
    ),
) -> None:
    """Audit agent flight records, verify cryptographic Merkle chain, and generate compliance audit proof."""
    from agentblackbox.storage.export import export_sarif

    store = _get_store(workspace)
    target_sid = session_id
    if not target_sid:
        sessions_list = store.list_sessions(limit=1)
        if not sessions_list:
            console.print("[yellow]No recorded sessions found to audit.[/]")
            return
        target_sid = sessions_list[0].id

    session = store.get_session(target_sid)
    if not session:
        console.print(f"[red]Session '{target_sid}' not found.[/]")
        raise typer.Exit(1)

    chain_res = store.verify_chain(target_sid)
    events = store.query_events(session_id=target_sid, limit=50000)
    alerts = store.get_alerts(session_id=target_sid, unacked_only=False)

    secret_findings = []
    compliance_findings = []
    drift_violations = []
    high_risk_cmds = []

    for ev in events:
        p = ev.payload if isinstance(ev.payload, dict) else {}
        if ev.event_type == "secret_detected" or p.get("secret_matches"):
            matches = p.get("secret_matches", [])
            for m in matches:
                secret_findings.append({
                    "event_id": ev.id,
                    "seq": ev.seq,
                    "file": ev.source_path,
                    "match": m if isinstance(m, str) else m.get("pattern_name", "secret"),
                })
        if "compliance_findings" in p and isinstance(p["compliance_findings"], list):
            compliance_findings.extend(p["compliance_findings"])
        if "drift_violations" in p and isinstance(p["drift_violations"], list):
            drift_violations.extend(p["drift_violations"])
        if ev.risk_score >= 7.0 and ev.event_type in ("cmd_execute", "git_force_push", "git_reset"):
            high_risk_cmds.append({
                "seq": ev.seq,
                "command": p.get("command", ""),
                "risk": ev.risk_score,
            })

    tip_hash = events[-1].event_hash if events else "genesis"
    attestation = hashlib.sha256(
        f"{target_sid}:{chain_res.valid}:{chain_res.total_events}:{tip_hash}".encode("utf-8")
    ).hexdigest()

    audit_summary = {
        "session_id": target_sid,
        "session_name": session.name,
        "status": "PASS" if chain_res.valid else "FAIL",
        "tamper_evident": True,
        "chain_intact": chain_res.valid,
        "broken_at_seq": chain_res.broken_at_seq,
        "failure_reason": chain_res.reason,
        "total_events_verified": chain_res.total_events,
        "merkle_tip_hash": tip_hash,
        "cryptographic_attestation": attestation,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "secrets_detected": len(secret_findings),
            "compliance_findings": len(compliance_findings),
            "drift_violations": len(drift_violations),
            "high_risk_commands": len(high_risk_cmds),
            "alerts_recorded": len(alerts),
        },
        "findings": {
            "secrets": secret_findings,
            "compliance": compliance_findings,
            "drift": drift_violations,
            "high_risk_commands": high_risk_cmds,
        },
    }

    fmt = format.lower()
    if fmt == "terminal":
        status_style = "bold green" if chain_res.valid else "bold red"
        status_text = "VERIFIED INTACT (0 Tampering)" if chain_res.valid else f"TAMPERED (Seq #{chain_res.broken_at_seq})"

        t = Table(title="🔒 Agent Flight Recording Cryptographic Audit Proof", show_header=False)
        t.add_column("Property", style="bold cyan")
        t.add_column("Value", style="white")
        t.add_row("Session ID", target_sid)
        t.add_row("Session Name", session.name)
        t.add_row("Cryptographic Integrity", f"[{status_style}]{status_text}[/]")
        t.add_row("Merkle Root Tip", f"[dim]{tip_hash}[/]")
        t.add_row("Audit Seal (SHA-256)", f"[yellow]{attestation[:24]}...[/]")
        t.add_row("Events Audited", str(chain_res.total_events))
        t.add_row("Secrets Detected", f"[red]{len(secret_findings)}[/]" if secret_findings else "[green]0[/]")
        t.add_row("Compliance Drift", f"[yellow]{len(drift_violations)}[/]" if drift_violations else "[green]0[/]")
        t.add_row("High-Risk Commands", f"[red]{len(high_risk_cmds)}[/]" if high_risk_cmds else "[green]0[/]")
        t.add_row("Recorded Alerts", f"[yellow]{len(alerts)}[/]" if alerts else "[green]0[/]")
        console.print(t)

        if not chain_res.valid:
            console.print(f"[bold red]❌ Chain Failure Reason:[/] {chain_res.reason}")

        if output:
            output.write_text(json.dumps(audit_summary, indent=2), encoding="utf-8")
            console.print(f"[dim]Audit summary saved to {output}[/]")

    elif fmt == "markdown":
        md_lines = [
            f"# 🔒 Cryptographic Audit Proof — Session `{target_sid}`",
            "",
            f"**Audit Status**: `{'PASS - INTACT' if chain_res.valid else 'FAIL - TAMPERED'}`  ",
            f"**Merkle Chain Root Tip**: `{tip_hash}`  ",
            f"**Cryptographic Seal (SHA-256)**: `{attestation}`  ",
            f"**Verified Event Count**: `{chain_res.total_events}`  ",
            f"**Timestamp (UTC)**: `{audit_summary['timestamp_utc']}`  ",
            "",
            "## 🛡️ Security & Drift Metrics",
            f"- **Secrets Detected**: {len(secret_findings)}",
            f"- **Compliance Drift Violations**: {len(drift_violations)}",
            f"- **High-Risk Agent Actions**: {len(high_risk_cmds)}",
            f"- **Alerts Recorded**: {len(alerts)}",
            "",
        ]
        if secret_findings:
            md_lines.append("### ⚠️ Secret Detections")
            for sf in secret_findings:
                md_lines.append(f"- Seq #{sf['seq']} in `{sf['file']}`: `{sf['match']}`")
            md_lines.append("")
        if drift_violations:
            md_lines.append("### ⚠️ Drift Violations")
            for dv in drift_violations:
                md_lines.append(f"- {dv.get('rule_code')}: {dv.get('description')}")
            md_lines.append("")

        md_content = "\n".join(md_lines)
        if output:
            output.write_text(md_content, encoding="utf-8")
            console.print(f"[green]Markdown audit proof written to {output}[/]")
        else:
            print(md_content)

    elif fmt == "json":
        data = json.dumps(audit_summary, indent=2)
        if output:
            output.write_text(data, encoding="utf-8")
            console.print(f"[green]JSON audit proof written to {output}[/]")
        else:
            print(data)

    elif fmt == "sarif":
        sarif_doc = export_sarif(store, session_id=target_sid, output_path=output)
        sarif_str = json.dumps(sarif_doc, indent=2)
        if not output:
            print(sarif_str)
        else:
            console.print(f"[green]SARIF v2.1.0 audit proof written to {output}[/]")

    else:
        console.print(f"[red]Unknown format: {format}. Use terminal, markdown, json, or sarif.[/]")
        raise typer.Exit(1)

    if strict and (not chain_res.valid or len(secret_findings) > 0):
        raise typer.Exit(1)


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


@app.command("verify-receipt")
def verify_receipt(
    receipt_id: str = typer.Argument(..., help="Cryptographic review receipt ID (e.g. abb-rcpt-...)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Workspace containing .agentblackbox store"),
) -> None:
    """Verify cryptographic signed review receipt against local tamper-evident flight ledger."""
    import os
    from agentblackbox.github_app.receipts import ReviewReceiptManager

    env_db = os.environ.get("ABB_DB_PATH")
    if env_db and Path(env_db).exists():
        db_path = Path(env_db)
    elif workspace and workspace.is_file():
        db_path = workspace
    elif workspace and (workspace / "events.db").exists():
        db_path = workspace / "events.db"
    elif workspace and (workspace / "test_events.db").exists():
        db_path = workspace / "test_events.db"
    else:
        ctx = CLIContext.resolve(workspace)
        db_path = ctx.db_path

    manager = ReviewReceiptManager(db_path=db_path)
    is_valid, receipt, message = manager.verify_receipt(receipt_id)
    if is_valid and receipt:
        console.print(f"[bold green]✅ Cryptographic Receipt Verified[/]: [cyan]{receipt_id}[/]")
        console.print(f"  Repository:    [bold]{receipt.owner}/{receipt.repo}[/] PR #{receipt.pull_number}")
        console.print(f"  Commit SHA:    [yellow]{receipt.head_sha}[/]")
        console.print(f"  Diff SHA-256:  [dim]{receipt.diff_hash}[/]")
        console.print(f"  Merkle Tip:    [green]{receipt.chain_tip_hash}[/]")
        console.print(f"  Findings:      {receipt.total_findings} ({receipt.critical_count} Critical, {receipt.high_count} High)")
        console.print(f"  Model Engine:  {receipt.model_id}")
        console.print(f"  Verification:  [bold]{message}[/]")
    else:
        console.print(f"[bold red]❌ Receipt Verification Failed[/]: {message}")
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
        help="Enable AI reasoning layer: gemini, openai, codex, anthropic, or offline",
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

    sev = Severity.from_str(min_severity)
    config = ReviewConfig(
        min_severity=sev,
        enable_ai=bool(ai),
        ai_provider=ai,
        ai_model=ai_model,
        max_context_tokens=max_tokens,
    )
    engine = ReviewEngine(config=config, git_client=git_client)

    if not git_client.is_git_repository():
        console.print(f"[dim]Note: '{repo_root}' is not a git repository. Performing repository static analysis...[/]")
        report = engine.analyze_repository(repo_root)
    else:
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
        help="Enable AI reasoning layer: gemini, openai, codex, anthropic, or offline",
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


@app.command("ci-gate")
def ci_gate(
    max_risk: float = typer.Option(
        7.0,
        "--max-risk",
        help="Maximum allowable cumulative or single-event risk score before blocking.",
    ),
    fail_on_drift: bool = typer.Option(
        True,
        "--fail-on-drift/--no-fail-on-drift",
        help="Fail if any architectural drift violations are detected.",
    ),
    fail_on_compliance: bool = typer.Option(
        True,
        "--fail-on-compliance/--no-fail-on-compliance",
        help="Fail if any compliance violations (SOC2, OWASP, GDPR) are detected.",
    ),
    sarif_out: Optional[Path] = typer.Option(
        None,
        "--sarif-out",
        help="Write SARIF v2.1.0 report for GitHub Advanced Security / Code Scanning.",
    ),
    session: Optional[str] = typer.Option(
        None,
        "--session",
        "-s",
        help="Target session ID to evaluate (defaults to most recent session).",
    ),
    workspace: Optional[Path] = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Repository workspace root directory.",
    ),
) -> None:
    """Evaluate cryptographic integrity, agent risk, compliance, and drift in CI/CD pre-push gate."""
    from agentblackbox.storage.export import export_sarif

    ws = (workspace or Path.cwd()).resolve()
    db_path = ws / ".agentblackbox" / "events.db"

    console.print("[bold cyan]══════════════════════════════════════════════════════════[/]")
    console.print("[bold cyan]   AgentBlackBox CI/CD Cryptographic & Policy Gate        [/]")
    console.print("[bold cyan]══════════════════════════════════════════════════════════[/]")

    if not db_path.exists():
        console.print(f"[dim]Note: No event database found at {db_path}. Initializing clean state...[/]")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        store = EventStore(db_path)
        sess = store.create_session(Session(id="ci_clean_run", name="CI Clean Baseline", workspace_path=str(ws)))
        target_session_id = sess.id
    else:
        store = EventStore(db_path)
        if session:
            sess = store.get_session(session)
            target_session_id = sess.id if sess else session
        else:
            sessions = store.list_sessions(limit=1)
            target_session_id = sessions[0].id if sessions else "default_session"

    blocked_reasons: List[str] = []

    # 1. Verify Cryptographic Hash Chain
    verify_res = store.verify_chain(target_session_id, verify_blobs=False)
    chain_intact = verify_res.valid
    if not chain_intact:
        blocked_reasons.append(
            f"Tamper detected in session '{target_session_id}' at seq={verify_res.broken_at_seq}: {verify_res.reason}"
        )

    # 2. Query events & evaluate policies
    events = store.query_events(session_id=target_session_id, limit=50000)
    max_observed_risk = max([e.risk_score for e in events] or [0.0])

    if max_observed_risk >= max_risk:
        blocked_reasons.append(
            f"Highest event risk score ({max_observed_risk:.1f}) exceeds maximum threshold ({max_risk:.1f})"
        )

    compliance_findings_count = sum(
        len(ev.payload.get("compliance_findings", []))
        for ev in events
        if isinstance(ev.payload, dict) and isinstance(ev.payload.get("compliance_findings"), list)
    )
    drift_violations_count = sum(
        len(ev.payload.get("drift_violations", []))
        for ev in events
        if isinstance(ev.payload, dict) and isinstance(ev.payload.get("drift_violations"), list)
    )

    if fail_on_compliance and compliance_findings_count > 0:
        blocked_reasons.append(
            f"{compliance_findings_count} compliance finding(s) detected (SOC2, OWASP, GDPR)"
        )

    if fail_on_drift and drift_violations_count > 0:
        blocked_reasons.append(
            f"{drift_violations_count} architectural drift violation(s) detected against contract"
        )

    # 3. Write SARIF report if requested
    if sarif_out:
        export_sarif(store, session_id=target_session_id, output_path=sarif_out)
        console.print(f"[dim]SARIF v2.1.0 report exported to: {sarif_out}[/]")

    # 4. Render Rich Table
    table = Table(title=f"CI Gate Audit Summary (Session: {target_session_id})")
    table.add_column("Policy / Check", style="cyan")
    table.add_column("Observed Value", style="white")
    table.add_column("Rule / Threshold", style="dim")
    table.add_column("Status", style="bold")

    table.add_row(
        "HMAC-SHA256 Hash Chain",
        "INTACT" if chain_intact else "TAMPERED",
        "Sequence continuity & SHA256",
        "[green]PASS[/]" if chain_intact else "[red]FAIL[/]",
    )
    table.add_row(
        "Maximum Event Risk Score",
        f"{max_observed_risk:.1f}",
        f"<= {max_risk:.1f}",
        "[green]PASS[/]" if max_observed_risk < max_risk else "[red]FAIL[/]",
    )
    table.add_row(
        "Context Compliance Findings",
        str(compliance_findings_count),
        "0 allowed" if fail_on_compliance else "Advisory",
        "[green]PASS[/]" if (not fail_on_compliance or compliance_findings_count == 0) else "[red]FAIL[/]",
    )
    table.add_row(
        "Architectural Drift Violations",
        str(drift_violations_count),
        "0 allowed" if fail_on_drift else "Advisory",
        "[green]PASS[/]" if (not fail_on_drift or drift_violations_count == 0) else "[red]FAIL[/]",
    )

    console.print(table)

    if blocked_reasons:
        console.print("\n[bold red]❌ CI GATE REJECTED:[/] PR or Push blocked due to the following violations:")
        for r in blocked_reasons:
            console.print(f"  [red]• {r}[/]")
        raise typer.Exit(1)

    console.print("\n[bold green]✅ CI GATE APPROVED:[/] All cryptographic, risk, compliance, and architectural checks passed.")


@app.command("ide-bridge")
def ide_bridge(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address"),
    port: int = typer.Option(8765, "--port", "-p", help="Local port to bind"),
    token: Optional[str] = typer.Option(None, "--token", help="Bearer API authentication token"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Workspace root path"),
) -> None:
    """Start the local FastAPI + WebSocket bridge server for Google Antigravity IDE / VS Code."""
    ws = (workspace or Path.cwd()).resolve()
    if token:
        os.environ["ABB_API_TOKEN"] = token
    elif not os.environ.get("ABB_API_TOKEN"):
        generated_token = secrets.token_urlsafe(24)
        os.environ["ABB_API_TOKEN"] = generated_token
        console.print(f"[bold yellow]🔒 Generated IDE Bridge API token:[/] [cyan]{generated_token}[/]")
    else:
        console.print("[dim]Using configured ABB_API_TOKEN from environment.[/]")

    console.print(f"[bold green]🚀 AgentBlackBox IDE Bridge active[/] on http://{host}:{port}")
    console.print(f"   [dim]Workspace:[/] {ws}")
    console.print(f"   [dim]WebSocket:[/] ws://{host}:{port}/ws/stream")
    uvicorn.run("agentblackbox.api.main:app", host=host, port=port, log_level="info")


@app.command("github-app")
def github_app_server(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind host address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
) -> None:
    """Launch the AgentBlackBox GitHub App Webhook & Code Review server."""
    console.print(f"[bold green]🐰 Starting AgentBlackBox GitHub App server[/] on http://{host}:{port}")
    console.print(f"   [dim]Webhook URL:[/] http://{host}:{port}/github/webhook")
    console.print(f"   [dim]Manifest Setup:[/] http://{host}:{port}/github/manifest")
    console.print(f"   [dim]Health Check:[/] http://{host}:{port}/github/healthz")
    uvicorn.run("agentblackbox.api.main:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
