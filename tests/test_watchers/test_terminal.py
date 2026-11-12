"""Tests for terminal command recording, attribution propagation, and redaction."""

import sqlite3
import sys
from pathlib import Path

from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import EventType, Session, Severity
from agentblackbox.watchers.terminal import run_recorded_command


class TestTerminalRecorder:
    """Test run_recorded_command execution and ledger recording."""

    def test_records_command_output_pid_and_parent_link(
        self, store: EventStore, sample_session: Session, tmp_workspace: Path
    ) -> None:
        store.create_session(sample_session)
        py = f'"{sys.executable}"'
        res = run_recorded_command(
            store=store,
            session_id=sample_session.id,
            command=f'{py} -c "import os; print(os.environ.get(\'ABB_AGENT_ID\'), os.environ.get(\'ABB_PARENT_EVENT_ID\'))"',
            workspace=tmp_workspace,
            agent_id="claude-code",
        )
        assert res.exit_code == 0
        assert "claude-code" in res.stdout
        assert str(res.execute_event_id) in res.stdout

        events = store.query_events(session_id=sample_session.id)
        assert len(events) == 2
        assert events[0].event_type == EventType.CMD_EXECUTE
        assert events[1].event_type == EventType.CMD_OUTPUT
        assert events[1].parent_event_id == events[0].id
        assert events[1].pid == res.pid
        assert store.verify_chain(sample_session.id).valid is True

    def test_redacts_secrets_from_command_and_stdout(
        self, store: EventStore, sample_session: Session, tmp_workspace: Path
    ) -> None:
        store.create_session(sample_session)
        secret = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
        py = f'"{sys.executable}"'
        res = run_recorded_command(
            store=store,
            session_id=sample_session.id,
            command=f'{py} -c "print(\'{secret}\')"',
            workspace=tmp_workspace,
            agent_id="codex",
        )
        assert res.exit_code == 0
        with sqlite3.connect(str(store.db_path)) as conn:
            rows = conn.execute(
                "SELECT payload FROM events WHERE session_id = ?",
                (sample_session.id,),
            ).fetchall()
            for (raw_payload,) in rows:
                assert secret not in raw_payload

        events = store.query_events(session_id=sample_session.id)
        assert all(e.severity == Severity.CRITICAL for e in events)
        assert store.verify_chain(sample_session.id).valid is True

    def test_nonzero_exit_creates_warning(
        self, store: EventStore, sample_session: Session, tmp_workspace: Path
    ) -> None:
        store.create_session(sample_session)
        py = f'"{sys.executable}"'
        res = run_recorded_command(
            store=store,
            session_id=sample_session.id,
            command=f'{py} -c "import sys; sys.exit(2)"',
            workspace=tmp_workspace,
        )
        assert res.exit_code == 2
        events = store.query_events(session_id=sample_session.id, event_type=EventType.CMD_OUTPUT)
        assert len(events) == 1
        assert events[0].severity == Severity.WARNING

