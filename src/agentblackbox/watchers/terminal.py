"""Terminal command recorder with secret redaction and child attribution."""

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import structlog

from agentblackbox.analysis.pattern_matcher import classify_event
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Alert, Event, EventType, Severity

logger = structlog.get_logger()

_MAX_CAPTURED_CHARS = 16_000


@dataclass
class CommandRunResult:
    """Result returned after executing a tracked shell command.

    Attributes:
        command: Command string executed.
        exit_code: Process exit code.
        duration_ms: Execution wall-clock time in milliseconds.
        stdout: Captured stdout (truncated if huge).
        stderr: Captured stderr (truncated if huge).
        execute_event_id: Database ID of the ``cmd_execute`` event.
        output_event_id: Database ID of the ``cmd_output`` event.
        pid: Spawned process PID.
    """

    command: str
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    execute_event_id: Optional[int]
    output_event_id: Optional[int]
    pid: int


def run_recorded_command(
    store: EventStore,
    session_id: str,
    command: str,
    workspace: Path,
    agent_id: Optional[str] = None,
    timeout: Optional[int] = None,
) -> CommandRunResult:
    """Execute a shell command while recording start, output, and attribution.

    Propagates ``ABB_SESSION_ID``, ``ABB_PARENT_EVENT_ID``, and ``ABB_AGENT_ID``
    into the child process environment so nested hooks/git events link cleanly.
    Secrets in command text or stdout/stderr are redacted by ``EventStore``
    before disk storage.

    Args:
        store: EventStore instance.
        session_id: Active session ID.
        command: Shell command to run.
        workspace: Working directory for execution.
        agent_id: Agent identifier to attribute the command to.
        timeout: Optional timeout in seconds.

    Returns:
        CommandRunResult containing exit code, output, and recorded event IDs.
    """
    exec_event = Event(
        session_id=session_id,
        event_type=EventType.CMD_EXECUTE,
        source_path=str(workspace),
        agent_id=agent_id,
        payload={"command": command, "cwd": str(workspace)},
    )
    classify_event(exec_event)
    score_event(exec_event)
    store.insert_event(exec_event)

    if exec_event.risk_score >= 5.0 and exec_event.id is not None:
        store.create_alert(Alert(
            event_id=exec_event.id,
            session_id=session_id,
            alert_type="dangerous_command",
            description=f"High-risk command executed (risk {exec_event.risk_score})",
        ))

    from agentblackbox.daemon.core import build_sanitized_child_env
    child_env = build_sanitized_child_env()
    child_env["ABB_SESSION_ID"] = session_id
    if exec_event.id is not None:
        child_env["ABB_PARENT_EVENT_ID"] = str(exec_event.id)
    if agent_id:
        child_env["ABB_AGENT_ID"] = agent_id

    popen_kwargs: dict = {
        "shell": True,
        "cwd": str(workspace),
        "env": child_env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    t0 = time.monotonic()
    proc = subprocess.Popen(command, **popen_kwargs)
    pid = proc.pid
    try:
        stdout_raw, stderr_raw = proc.communicate(timeout=timeout)
        exit_code = proc.returncode if proc.returncode is not None else 0
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_raw, stderr_raw = proc.communicate()
        exit_code = -1

    duration_ms = int((time.monotonic() - t0) * 1000)
    stdout_capped = (stdout_raw or "")[:_MAX_CAPTURED_CHARS]
    stderr_capped = (stderr_raw or "")[:_MAX_CAPTURED_CHARS]

    out_event = Event(
        session_id=session_id,
        event_type=EventType.CMD_OUTPUT,
        source_path=str(workspace),
        agent_id=agent_id,
        pid=pid,
        parent_event_id=exec_event.id,
        payload={
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "output": stdout_capped,
            "stderr": stderr_capped,
        },
    )
    score_event(out_event)
    if exit_code != 0 and out_event.severity == Severity.INFO:
        out_event.severity = Severity.WARNING
        out_event.risk_score = max(out_event.risk_score, 3.0)
    store.insert_event(out_event)

    logger.info(
        "command_recorded",
        session_id=session_id,
        pid=pid,
        exit_code=exit_code,
        duration_ms=duration_ms,
    )
    return CommandRunResult(
        command=command,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout=stdout_capped,
        stderr=stderr_capped,
        execute_event_id=exec_event.id,
        output_event_id=out_event.id,
        pid=pid,
    )

