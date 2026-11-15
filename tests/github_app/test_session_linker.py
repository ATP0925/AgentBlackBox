"""Tests for Agent-Session Linkage and PreToolUse Flight Ledger Auditing."""

from __future__ import annotations

from pathlib import Path
import pytest

from agentblackbox.github_app.session_linker import AgentSessionLinker
from agentblackbox.models.finding import Severity as FindingSeverity
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity as StorageSeverity


@pytest.fixture
def temp_linker(tmp_path: Path) -> AgentSessionLinker:
    db_file = tmp_path / "test_events.db"
    store = EventStore(db_file)
    return AgentSessionLinker(store=store)


def test_extract_session_id_patterns() -> None:
    linker = AgentSessionLinker(store=None)

    # 1. From PR body
    body1 = "Fix login bugs\n\nAgentBlackBox-Session: sess-abc-123\nSigned by agent."
    assert linker.extract_session_id(pr_body=body1) == "sess-abc-123"

    # 2. From shorthand trailer
    body2 = "ABB-Session: cursor-flight-999"
    assert linker.extract_session_id(pr_body=body2) == "cursor-flight-999"

    # 3. From branch name
    assert linker.extract_session_id(branch_name="feature/abb-session-alpha-44") == "alpha-44"

    # 4. From commit messages
    commits = ["Initial commit", "refactor auth\n\nAgentBlackBox-Session: claude-code-77"]
    assert linker.extract_session_id(commit_messages=commits) == "claude-code-77"

    # 5. None when absent
    assert linker.extract_session_id(pr_body="Just a normal PR", branch_name="patch-1") is None


def test_audit_valid_linked_session(temp_linker: AgentSessionLinker) -> None:
    session_id = "test-agent-session-1"
    store = temp_linker.store

    # Create session
    session = Session(
        id=session_id,
        name="Claude Code Refactor Session",
        workspace_path="/workspace/test",
        agent_hint="claude-code",
    )
    store.create_session(session)

    # Add events: bash executions, file modifications, blocked actions
    e1 = Event(
        session_id=session_id,
        event_type=EventType.CMD_EXECUTE,
        severity=StorageSeverity.INFO,
        source_path="bash",
        payload={"command": "pytest tests/ -v"},
    )
    e2 = Event(
        session_id=session_id,
        event_type=EventType.FILE_MODIFY,
        severity=StorageSeverity.INFO,
        source_path="tests/test_auth.py",
        payload={"diff": "..."},
    )
    e3 = Event(
        session_id=session_id,
        event_type=EventType.FILE_DELETE,
        severity=StorageSeverity.WARNING,
        source_path="tests/test_legacy.py",
        payload={"action": "deleted"},
    )
    e4 = Event(
        session_id=session_id,
        event_type=EventType.CMD_EXECUTE,
        severity=StorageSeverity.CRITICAL,
        risk_score=8.5,
        source_path="bash",
        payload={"command": "cat .env", "blocked": True},
    )

    store.record_event(e1)
    store.record_event(e2)
    store.record_event(e3)
    store.record_event(e4)

    summary = temp_linker.audit_session(session_id)
    assert summary.is_valid is True
    assert summary.tamper_detected is False
    assert summary.total_events == 4
    assert summary.commands_executed == 2
    assert summary.files_modified == 1
    assert summary.files_deleted == 1
    assert "tests/test_auth.py" in summary.tests_touched
    assert "tests/test_legacy.py" in summary.tests_touched
    assert summary.blocked_actions == 1
    assert summary.high_risk_actions == 1


def test_audit_tampered_linked_session(temp_linker: AgentSessionLinker) -> None:
    session_id = "test-tampered-session"
    store = temp_linker.store

    session = Session(id=session_id, workspace_path="/tmp")
    store.create_session(session)

    e1 = Event(session_id=session_id, event_type=EventType.CMD_EXECUTE, payload={"cmd": "ls"})
    e2 = Event(session_id=session_id, event_type=EventType.CMD_EXECUTE, payload={"cmd": "pwd"})
    store.record_event(e1)
    store.record_event(e2)

    # Break hash chain in SQLite
    import sqlite3
    conn = sqlite3.connect(str(store.db_path))
    cur = conn.cursor()
    cur.execute("UPDATE events SET prev_hash = 'bad-tampered-hash' WHERE seq = 2 AND session_id = ?", (session_id,))
    conn.commit()
    conn.close()

    summary = temp_linker.audit_session(session_id)
    assert summary.is_valid is False
    assert summary.tamper_detected is True
    assert len(summary.findings) == 1
    assert summary.findings[0].rule_id == "SEC-TAMPERED-AGENT-SESSION"
    assert summary.findings[0].severity == FindingSeverity.CRITICAL


def test_audit_missing_session(temp_linker: AgentSessionLinker) -> None:
    summary = temp_linker.audit_session("non-existent-session-id")
    assert summary.is_valid is False
    assert summary.tamper_detected is False
    assert len(summary.findings) == 1
    assert summary.findings[0].rule_id == "SEC-SESSION-NOT-FOUND"
