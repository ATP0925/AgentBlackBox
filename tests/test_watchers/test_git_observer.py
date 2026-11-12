"""Tests for GitObserver and reference-transaction git hooks."""

import subprocess
import time
from pathlib import Path
from typing import List

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session
from agentblackbox.watchers.git_observer import (
    GitObserver,
    install_git_hooks,
    record_reference_transaction,
    uninstall_git_hooks,
)


def _init_temp_git_repo(repo_dir: Path) -> None:
    """Initialize a minimal local git repository with an initial commit."""
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True)
    (repo_dir / "README.md").write_text("# init\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), check=True, capture_output=True)


class TestGitHooks:
    """Test safe installation, removal, and parsing of reference-transaction hooks."""

    def test_install_preserves_existing_hook_and_uninstalls_cleanly(self, tmp_path: Path) -> None:
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        hook = tmp_path / ".git" / "hooks" / "reference-transaction"
        hook.write_text("#!/bin/sh\necho user-hook\n", encoding="utf-8")

        assert install_git_hooks(tmp_path) is True
        content = hook.read_text(encoding="utf-8")
        assert "echo user-hook" in content
        assert "AGENTBLACKBOX" in content

        assert uninstall_git_hooks(tmp_path) is True
        after = hook.read_text(encoding="utf-8")
        assert "echo user-hook" in after
        assert "AGENTBLACKBOX" not in after

    def test_record_reference_transaction_committed_vs_prepared(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        _init_temp_git_repo(tmp_path)
        config = BlackBoxConfig(workspace_path=tmp_path)
        store = EventStore(config.db_path)
        sess = Session(workspace_path=str(tmp_path))
        store.create_session(sess)

        monkeypatch.setenv("ABB_AGENT_ID", "claude-code")
        monkeypatch.setenv("ABB_PARENT_EVENT_ID", "99")

        # prepared state must be ignored
        prep = record_reference_transaction(
            tmp_path, "prepared", ["111111 222222 refs/heads/main"], session_id=sess.id
        )
        assert prep == []

        # committed commit
        events = record_reference_transaction(
            tmp_path, "committed", ["111111 222222 refs/heads/main"], session_id=sess.id
        )
        assert len(events) == 1
        assert events[0].event_type == EventType.GIT_COMMIT
        assert events[0].agent_id == "claude-code"
        assert events[0].parent_event_id == 99

        # branch deletion (zero oid) classified as GIT_RESET
        deletes = record_reference_transaction(
            tmp_path,
            "committed",
            [f"222222 {'0'*40} refs/heads/feature"],
            session_id=sess.id,
        )
        assert len(deletes) == 1
        assert deletes[0].event_type == EventType.GIT_RESET


class TestGitObserver:
    """Test polling GitObserver against a real git commit."""

    def test_detects_new_commit(self, tmp_path: Path) -> None:
        _init_temp_git_repo(tmp_path)
        events: List[Event] = []
        observer = GitObserver(
            session_id="sess-git",
            on_event=lambda e: events.append(e),
            workspace=tmp_path,
            poll_interval=0.1,
            agent_id="cursor",
        )
        observer.start()
        try:
            time.sleep(0.25)
            (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
            subprocess.run(["git", "add", "app.py"], cwd=str(tmp_path), check=True)
            subprocess.run(["git", "commit", "-m", "add app"], cwd=str(tmp_path), check=True, capture_output=True)

            deadline = time.monotonic() + 2.5
            while time.monotonic() < deadline and not events:
                time.sleep(0.05)
        finally:
            observer.stop()

        assert len(events) >= 1
        assert events[0].event_type == EventType.GIT_COMMIT
        assert events[0].agent_id == "cursor"

