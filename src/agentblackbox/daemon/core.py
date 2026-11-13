"""Live background daemon coordinating watchers, blob store, and SQLite ledger."""

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event as ThreadEvent, Lock
from typing import Any, Optional

import structlog

from agentblackbox.analysis.key_provider import KeyProvider, ENV_HMAC_KEY
from agentblackbox.analysis.pattern_matcher import classify_event
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Alert, Event, Session, _utcnow
from agentblackbox.watchers.filesystem import FileSystemWatcher
from agentblackbox.watchers.git_observer import (
    GitObserver,
    install_git_hooks,
    uninstall_git_hooks,
)

logger = structlog.get_logger()

_STILL_ACTIVE = 259


def build_sanitized_child_env() -> dict[str, str]:
    """Return environment dictionary for child agent processes with secrets stripped."""
    env = dict(os.environ)
    env.pop(ENV_HMAC_KEY, None)
    env.pop("ABB_API_TOKEN", None)
    return env


@dataclass
class DaemonState:
    """Persisted metadata describing a running background daemon.

    Attributes:
        session_id: Active recording session ID.
        pid: Operating system process ID of the daemon.
        workspace_path: Monitored workspace directory.
        agent_hint: Optional agent identifier.
        started_at: ISO 8601 startup timestamp.
        installed_git_hook: Whether this daemon installed the git hook.
        cmd: Optional startup command arguments.
    """

    session_id: str
    pid: int
    workspace_path: str = ""
    agent_hint: Optional[str] = None
    started_at: str = ""
    installed_git_hook: bool = False
    cmd: Optional[list] = None


def _state_file(config: BlackBoxConfig) -> Path:
    """Return path to daemon state JSON file."""
    return config.workspace_path / ".agentblackbox" / "daemon.json"


def _pid_file(config: BlackBoxConfig) -> Path:
    """Return path to daemon PID file."""
    return config.workspace_path / ".agentblackbox" / "daemon.pid"


def _stop_file(config: BlackBoxConfig) -> Path:
    """Return path to cross-platform stop sentinel file."""
    return config.workspace_path / ".agentblackbox" / "daemon.stop"


def _log_file(config: BlackBoxConfig) -> Path:
    """Return path to daemon log file."""
    return config.workspace_path / ".agentblackbox" / "daemon.log"


def is_pid_alive(pid: int, expected_start_token: str | None = None) -> bool:
    """Check if PID is alive and verify it belongs to an agentblackbox process."""
    if pid <= 0:
        return False

    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == _STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

    # Linux /proc cmdline guard against stale PID reuse
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    if proc_cmdline.exists():
        try:
            raw = proc_cmdline.read_bytes().decode("utf-8", errors="ignore")
            if "agentblackbox" not in raw and "abb" not in raw:
                return False
        except OSError:
            pass

    return True


def spawn_detached_daemon(
    cmd: list[str],
    log_path: Path,
    state_path: Path,
    pid_path: Path,
    session_id: str,
    env: dict[str, str] | None = None,
) -> int:
    """Spawn background daemon safely without premature context-manager FD issues."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(
        str(log_path),
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    try:
        popen_kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": log_fd,
            "stderr": log_fd,
            "close_fds": True,
            "env": env or os.environ.copy(),
        }
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **popen_kwargs)
    finally:
        # Parent closes its copy of the FD; child retains its inherited descriptor
        os.close(log_fd)

    pid_path.write_text(str(proc.pid), encoding="utf-8")
    state_payload = {
        "pid": proc.pid,
        "session_id": session_id,
        "started_at": time.time(),
        "cmd": cmd,
    }
    state_path.write_text(json.dumps(state_payload, indent=2), encoding="utf-8")
    return proc.pid


class GracefulDaemonController:
    """Coordinates atomic event processing and clean SIGTERM/SIGINT shutdown."""

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._event_lock = threading.RLock()

    @property
    def should_stop(self) -> bool:
        return self._stop_event.is_set()

    def request_stop(self, signum: int | None = None, frame: Any = None) -> None:
        self._stop_event.set()

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, self.request_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.request_stop)

    def execute_atomic_event(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Acquire lock so SIGTERM loop waits for in-flight DB writes to finish."""
        with self._event_lock:
            if self._stop_event.is_set():
                return None
            return fn(*args, **kwargs)


def get_daemon_state(config: BlackBoxConfig) -> Optional[DaemonState]:
    """Return live DaemonState if a daemon is actively running, else None.

    Automatically cleans up stale state files if the PID is dead.

    Args:
        config: BlackBox configuration.

    Returns:
        Active DaemonState or None.
    """
    sf = _state_file(config)
    if not sf.exists():
        return None
    try:
        raw = json.loads(sf.read_text(encoding="utf-8"))
        state = DaemonState(**raw)
    except (OSError, json.JSONDecodeError, TypeError):
        return None

    if not is_pid_alive(state.pid):
        sf.unlink(missing_ok=True)
        _stop_file(config).unlink(missing_ok=True)
        return None
    return state


class BlackBoxDaemon:
    """In-process or background daemon running FileSystemWatcher + GitObserver.

    Args:
        config: BlackBox configuration.
        session_id: Session ID to record events into.
        agent_id: Optional default agent attribution label.
        install_hooks: Whether to auto-install ``reference-transaction`` git hook.
    """

    def __init__(
        self,
        config: BlackBoxConfig,
        session_id: str,
        agent_id: Optional[str] = None,
        install_hooks: bool = True,
    ) -> None:
        self.config = config
        self.session_id = session_id
        self.agent_id = agent_id
        self.install_hooks = install_hooks
        self.store = EventStore(config.db_path)
        self.blob_store = BlobStore(config.blobs_dir)
        self._lock = Lock()
        self._stop_event = ThreadEvent()
        self.controller = GracefulDaemonController()
        self._installed_git_hook = False

        self.fs_watcher = FileSystemWatcher(
            session_id=session_id,
            on_event=self.handle_event,
            watch_path=config.workspace_path,
            ignore_patterns=config.ignore_patterns,
            debounce_seconds=max(0.05, config.debounce_ms / 1000.0),
            max_file_size=config.max_file_size_bytes,
            blob_store=self.blob_store,
            agent_id=agent_id,
        )
        self.git_observer = GitObserver(
            session_id=session_id,
            on_event=self.handle_event,
            workspace=config.workspace_path,
            poll_interval=0.5,
            agent_id=agent_id,
        )

    def handle_event(self, event: Event) -> Event:
        """Classify, score, redact/persist, and alert on a captured event.

        Args:
            event: Newly captured Event.

        Returns:
            Persisted Event with DB ID and hash-chain fields.
        """
        res = self.controller.execute_atomic_event(self._handle_event_locked, event)
        return res if res is not None else event

    def _handle_event_locked(self, event: Event) -> Event:
        prior_risk = float(event.risk_score)
        classify_event(event)
        score_event(event)
        if prior_risk > event.risk_score:
            event.risk_score = prior_risk

        with self._lock:
            stored = self.store.insert_event(event)
            if (stored.risk_score >= 5.0 or "secret" in stored.tags) and stored.id is not None:
                alert_type = "secret_leak" if "secret" in stored.tags else "high_risk_event"
                self.store.create_alert(Alert(
                    event_id=stored.id,
                    session_id=self.session_id,
                    alert_type=alert_type,
                    description=f"{stored.event_type} (risk {stored.risk_score}) on {stored.source_path or '-'}",
                ))
        return stored

    def start(self) -> DaemonState:
        """Start all watchers and write daemon state file."""
        self.controller.install_signal_handlers()
        _stop_file(self.config).unlink(missing_ok=True)
        self.fs_watcher.start()
        if (self.config.workspace_path / ".git").is_dir():
            self.git_observer.start()
            if self.install_hooks:
                hook_path = self.config.workspace_path / ".git" / "hooks" / "reference-transaction"
                had_hook = hook_path.exists() and "AGENTBLACKBOX" not in hook_path.read_text(encoding="utf-8")
                if not had_hook:
                    self._installed_git_hook = install_git_hooks(self.config.workspace_path)

        # Brief yield so Windows ReadDirectoryChangesW thread finishes attaching
        time.sleep(0.2)

        state = DaemonState(
            session_id=self.session_id,
            pid=os.getpid(),
            workspace_path=str(self.config.workspace_path),
            agent_hint=self.agent_id,
            started_at=_utcnow(),
            installed_git_hook=self._installed_git_hook,
        )
        sf = _state_file(self.config)
        sf.parent.mkdir(parents=True, exist_ok=True)
        sf.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
        _pid_file(self.config).write_text(str(os.getpid()), encoding="utf-8")
        logger.info("daemon_started", session_id=self.session_id, pid=state.pid)
        return state

    def stop(self) -> None:
        """Stop all watchers, finalize session, and remove sentinel files."""
        self.controller.request_stop()
        self._stop_event.set()
        if self.fs_watcher.is_running:
            self.fs_watcher.stop()
        if self.git_observer.is_running:
            self.git_observer.stop()
        if self._installed_git_hook:
            uninstall_git_hooks(self.config.workspace_path)

        session = self.store.get_session(self.session_id)
        if session and session.status == "recording":
            self.store.stop_session(self.session_id)
        self.store.close()

        _pid_file(self.config).unlink(missing_ok=True)
        _state_file(self.config).unlink(missing_ok=True)
        _stop_file(self.config).unlink(missing_ok=True)
        logger.info("daemon_stopped", session_id=self.session_id)

    def run_forever(self) -> None:
        """Block until stop sentinel file appears or OS signal is received."""
        self.start()
        stop_sentinel = _stop_file(self.config)
        try:
            while not self._stop_event.wait(0.2) and not self.controller.should_stop:
                if stop_sentinel.exists():
                    break
        finally:
            self.stop()


def start_background_daemon(
    config: BlackBoxConfig,
    name: Optional[str] = None,
    agent_hint: Optional[str] = None,
    timeout: float = 5.0,
) -> DaemonState:
    """Create a session and launch a detached background BlackBoxDaemon process.

    Args:
        config: Workspace configuration.
        name: Optional session name.
        agent_hint: Optional agent attribution identifier.
        timeout: Seconds to wait for watcher readiness.

    Returns:
        Active DaemonState once watchers are ready.

    Raises:
        RuntimeError: If a daemon is already running or fails to become ready.
    """
    existing = get_daemon_state(config)
    if existing:
        raise RuntimeError(
            f"Recording daemon already active (session {existing.session_id}, pid {existing.pid})."
        )

    store = EventStore(config.db_path)
    session = Session(
        workspace_path=str(config.workspace_path),
        name=name,
        agent_hint=agent_hint,
    )
    store.create_session(session)
    store.close()

    log_path = _log_file(config)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "agentblackbox.daemon.core",
        "--workspace",
        str(config.workspace_path),
        "--session",
        session.id,
        "--debounce-ms",
        str(config.debounce_ms),
    ]
    if agent_hint:
        cmd.extend(["--agent", agent_hint])

    pid_path = _pid_file(config)
    state_path = _state_file(config)
    proc_pid = spawn_detached_daemon(
        cmd=cmd,
        log_path=log_path,
        state_path=state_path,
        pid_path=pid_path,
        session_id=session.id,
        env=os.environ.copy(),
    )

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = get_daemon_state(config)
        if state and state.session_id == session.id and state.workspace_path:
            return state
        if not is_pid_alive(proc_pid):
            break
        time.sleep(0.1)

    fail_store = EventStore(config.db_path)
    fail_store.stop_session(session.id)
    fail_store.close()
    raise RuntimeError(f"Daemon failed to start within {timeout}s. Check {log_path}.")


def stop_background_daemon(config: BlackBoxConfig, timeout: float = 5.0) -> Optional[DaemonState]:
    """Signal a running background daemon to stop cleanly and wait for exit.

    Args:
        config: Workspace configuration.
        timeout: Maximum seconds to wait for clean shutdown.

    Returns:
        Stopped DaemonState if one was running, None otherwise.
    """
    state = get_daemon_state(config)
    if not state:
        return None

    sf = _stop_file(config)
    sf.parent.mkdir(parents=True, exist_ok=True)
    sf.write_text("stop", encoding="utf-8")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not is_pid_alive(state.pid) and not _state_file(config).exists():
            _pid_file(config).unlink(missing_ok=True)
            return state
        time.sleep(0.1)

    # Fallback termination if daemon did not exit within timeout
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(state.pid), "/F"],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            os.kill(state.pid, signal.SIGTERM)
    except OSError:
        pass

    stop_store = EventStore(config.db_path)
    stop_store.stop_session(state.session_id)
    stop_store.close()
    _pid_file(config).unlink(missing_ok=True)
    _state_file(config).unlink(missing_ok=True)
    _stop_file(config).unlink(missing_ok=True)
    return state


def _main() -> None:
    """CLI entrypoint for detached background daemon process."""
    parser = argparse.ArgumentParser(description="AgentBlackBox background daemon")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--agent", default=None)
    parser.add_argument("--debounce-ms", type=int, default=500)
    args = parser.parse_args()

    config = BlackBoxConfig(
        workspace_path=Path(args.workspace),
        debounce_ms=args.debounce_ms,
    )
    daemon = BlackBoxDaemon(config=config, session_id=args.session, agent_id=args.agent)

    def _handle_signal(_signum: int, _frame: object) -> None:
        daemon._stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    daemon.run_forever()


if __name__ == "__main__":
    _main()

