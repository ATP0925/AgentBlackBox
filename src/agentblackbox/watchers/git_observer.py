"""Git observer — hooks and lightweight state watcher for repository activity."""

import os
import subprocess
import sys
from pathlib import Path
from threading import Event as ThreadEvent, Thread
from typing import Callable, List, Optional, Tuple

import structlog

from agentblackbox.analysis.pattern_matcher import classify_event
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Severity
from agentblackbox.watchers.base import BaseWatcher

logger = structlog.get_logger()

_HOOK_START_MARKER = "# BEGIN AGENTBLACKBOX HOOK"
_HOOK_END_MARKER = "# END AGENTBLACKBOX HOOK"
_ZERO_OID = "0" * 40


def _build_hook_snippet(workspace: Path) -> str:
    """Build shell-safe reference-transaction hook block."""
    py_exe = Path(sys.executable).as_posix()
    ws_str = workspace.resolve().as_posix()
    return (
        f"{_HOOK_START_MARKER}\n"
        f'"{py_exe}" -m agentblackbox.watchers.git_observer --workspace "{ws_str}" --state "$1" || true\n'
        f"{_HOOK_END_MARKER}\n"
    )


def install_git_hooks(workspace: Path) -> bool:
    """Install AgentBlackBox ``reference-transaction`` hook into ``.git/hooks``.

    Preserves any existing non-AgentBlackBox hook content.

    Args:
        workspace: Repository root directory.

    Returns:
        True if hook was installed or already present, False if ``.git`` missing.
    """
    git_dir = workspace / ".git"
    if not git_dir.is_dir():
        return False

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "reference-transaction"
    snippet = _build_hook_snippet(workspace)

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        if _HOOK_START_MARKER in existing:
            return True
        if not existing.endswith("\n"):
            existing += "\n"
        hook_path.write_text(existing + "\n" + snippet, encoding="utf-8")
    else:
        hook_path.write_text("#!/bin/sh\n" + snippet, encoding="utf-8")

    try:
        os.chmod(hook_path, 0o755)
    except OSError:
        pass
    logger.info("git_hook_installed", path=str(hook_path))
    return True


def uninstall_git_hooks(workspace: Path) -> bool:
    """Remove AgentBlackBox hook block from ``.git/hooks/reference-transaction``.

    Args:
        workspace: Repository root directory.

    Returns:
        True if removed or not present.
    """
    hook_path = workspace / ".git" / "hooks" / "reference-transaction"
    if not hook_path.exists():
        return True

    lines = hook_path.read_text(encoding="utf-8").splitlines(keepends=True)
    kept: List[str] = []
    inside = False
    for line in lines:
        if _HOOK_START_MARKER in line:
            inside = True
            continue
        if _HOOK_END_MARKER in line:
            inside = False
            continue
        if not inside:
            kept.append(line)

    remaining = "".join(kept).strip()
    if not remaining or remaining == "#!/bin/sh":
        hook_path.unlink(missing_ok=True)
    else:
        hook_path.write_text(remaining + "\n", encoding="utf-8")
    return True


def _run_git(workspace: Path, args: List[str]) -> Optional[str]:
    """Run a read-only git command quietly with no popup window."""
    kwargs: dict = {
        "cwd": str(workspace),
        "capture_output": True,
        "text": True,
        "timeout": 5,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        proc = subprocess.run(["git", *args], **kwargs)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def record_reference_transaction(
    workspace: Path,
    state: str,
    stdin_lines: List[str],
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    parent_event_id: Optional[int] = None,
) -> List[Event]:
    """Parse git ``reference-transaction`` lines and persist attributed git events.

    Only records ``committed`` transactions to avoid noisy ``prepared`` duplicates.

    Args:
        workspace: Repository root path.
        state: Hook state argument (``prepared``, ``committed``, ``aborted``).
        stdin_lines: Ref update lines formatted ``<old_oid> <new_oid> <refname>``.
        session_id: Target session ID (defaults to env or active session).
        agent_id: Attributed agent identifier.
        parent_event_id: Optional parent command event ID.

    Returns:
        List of persisted Event objects.
    """
    if state != "committed":
        return []

    config = BlackBoxConfig(workspace_path=workspace)
    store = EventStore(config.db_path)

    target_session_id = session_id or os.environ.get("ABB_SESSION_ID")
    if not target_session_id:
        sessions = store.list_sessions(limit=1)
        if sessions and sessions[0].status == "recording":
            target_session_id = sessions[0].id
    if not target_session_id:
        return []

    resolved_agent = agent_id or os.environ.get("ABB_AGENT_ID")
    env_parent = os.environ.get("ABB_PARENT_EVENT_ID")
    resolved_parent = parent_event_id if parent_event_id is not None else (
        int(env_parent) if env_parent and env_parent.isdigit() else None
    )

    recorded: List[Event] = []
    commit_msg = _run_git(workspace, ["log", "-1", "--pretty=%s"]) or ""
    last_reflog = _run_git(workspace, ["log", "-g", "-1", "--pretty=%gs"]) or ""

    for raw_line in stdin_lines:
        parts = raw_line.strip().split()
        if len(parts) < 3:
            continue
        old_oid, new_oid, refname = parts[0], parts[1], parts[2]
        if old_oid == new_oid:
            continue

        if "reset:" in last_reflog.lower() or new_oid == _ZERO_OID:
            ev_type = EventType.GIT_RESET
        else:
            ev_type = EventType.GIT_COMMIT

        ev = Event(
            session_id=target_session_id,
            event_type=ev_type,
            source_path=refname,
            agent_id=resolved_agent,
            pid=os.getppid(),
            parent_event_id=resolved_parent,
            payload={
                "ref": refname,
                "old_oid": old_oid[:12],
                "new_oid": new_oid[:12],
                "message": commit_msg,
                "reflog_action": last_reflog,
            },
            tags=["git"],
        )
        classify_event(ev)
        score_event(ev)
        store.insert_event(ev)
        recorded.append(ev)

    return recorded


class GitObserver(BaseWatcher):
    """Lightweight polling observer tracking HEAD and working-tree git state.

    Args:
        session_id: Active session ID.
        on_event: Callback invoked with each new Event.
        workspace: Git repository root path.
        poll_interval: Seconds between state checks.
        agent_id: Optional default agent attribution.
    """

    def __init__(
        self,
        session_id: str,
        on_event: Callable[[Event], None],
        workspace: Path,
        poll_interval: float = 1.0,
        agent_id: Optional[str] = None,
    ) -> None:
        super().__init__(session_id, on_event)
        self.workspace = workspace
        self.poll_interval = poll_interval
        self.agent_id = agent_id
        self._stop_event = ThreadEvent()
        self._thread: Optional[Thread] = None
        self._last_head: Optional[str] = None

    def _poll_loop(self) -> None:
        """Poll git HEAD changes until stopped."""
        self._last_head = _run_git(self.workspace, ["rev-parse", "HEAD"])
        while not self._stop_event.wait(self.poll_interval):
            if not (self.workspace / ".git").exists():
                continue
            current_head = _run_git(self.workspace, ["rev-parse", "HEAD"])
            if current_head and current_head != self._last_head:
                msg = _run_git(self.workspace, ["log", "-1", "--pretty=%s"]) or ""
                reflog = _run_git(self.workspace, ["log", "-g", "-1", "--pretty=%gs"]) or ""
                ev_type = EventType.GIT_RESET if "reset:" in reflog.lower() else EventType.GIT_COMMIT
                ev = Event(
                    session_id=self.session_id,
                    event_type=ev_type,
                    source_path=".git/HEAD",
                    agent_id=self.agent_id,
                    payload={
                        "old_oid": (self._last_head or "")[:12],
                        "new_oid": current_head[:12],
                        "message": msg,
                        "reflog_action": reflog,
                    },
                    tags=["git"],
                )
                classify_event(ev)
                score_event(ev)
                self._last_head = current_head
                self.on_event(ev)

    def start(self) -> None:
        """Start background git observer thread if directory is a git repo."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        self._running = True
        logger.info("git_observer_started", workspace=str(self.workspace))

    def stop(self) -> None:
        """Stop git observer thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._running = False
        logger.info("git_observer_stopped")


def _main() -> None:
    """CLI entrypoint invoked by git reference-transaction hook."""
    import argparse

    parser = argparse.ArgumentParser(description="AgentBlackBox git hook runner")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()

    lines = sys.stdin.read().splitlines()
    record_reference_transaction(Path(args.workspace), args.state, lines)


if __name__ == "__main__":
    _main()

