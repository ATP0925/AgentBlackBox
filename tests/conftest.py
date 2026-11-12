"""Shared test fixtures for AgentBlackBox."""

import pytest
from pathlib import Path
import tempfile

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Session, Event, EventType, Severity


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Provide a temporary workspace directory."""
    ws = tmp_path / "test_workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Provide a temporary database path."""
    return tmp_path / "test.db"


@pytest.fixture
def config(tmp_workspace: Path, tmp_db: Path) -> BlackBoxConfig:
    """Provide a test configuration."""
    return BlackBoxConfig(
        workspace_path=tmp_workspace,
        db_path=tmp_db,
    )


@pytest.fixture
def store(tmp_db: Path) -> EventStore:
    """Provide a fresh EventStore with empty database."""
    return EventStore(tmp_db)


@pytest.fixture
def sample_session(tmp_workspace: Path) -> Session:
    """Provide a sample session for testing."""
    return Session(
        workspace_path=str(tmp_workspace),
        name="test-session",
        agent_hint="pytest",
    )


@pytest.fixture
def sample_event(sample_session: Session) -> Event:
    """Provide a sample event for testing."""
    return Event(
        session_id=sample_session.id,
        event_type=EventType.FILE_CREATE,
        source_path="src/main.py",
        payload={"content": "print('hello')"},
        tags=["python"],
    )

