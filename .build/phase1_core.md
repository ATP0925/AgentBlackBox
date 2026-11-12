# PHASE 1: Core Foundation
# ========================
# After completing this phase: models, storage, session management, and config will work.
# Tests to pass: 14
# Estimated time: 1-2 hours
#
# READ AGENTS.md FIRST. Follow every rule there.

## STEP 1: Create pyproject.toml

Create `pyproject.toml` at project root with EXACTLY this content:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "agentblackbox"
version = "0.1.0"
description = "The flight recorder for autonomous AI agents"
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
authors = [
    { name = "Pratik Atpadkar" },
]
keywords = ["ai", "agents", "security", "forensics", "devtools"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.11",
    "Topic :: Software Development :: Testing",
    "Topic :: Security",
]
dependencies = [
    "watchdog>=4.0.0",
    "typer>=0.12.0",
    "rich>=13.0.0",
    "fastapi>=0.111.0",
    "uvicorn>=0.30.0",
    "websockets>=12.0",
    "gitpython>=3.1.0",
    "pydantic>=2.7.0",
    "structlog>=24.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "httpx>=0.27.0",
]

[project.scripts]
abb = "agentblackbox.cli.main:app"

[tool.hatch.build.targets.wheel]
packages = ["src/agentblackbox"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

## STEP 2: Create src/agentblackbox/__init__.py

```python
"""AgentBlackBox — The flight recorder for autonomous AI agents."""

__version__ = "0.1.0"
```

## STEP 3: Create src/agentblackbox/__main__.py

```python
"""Allow running as `python -m agentblackbox`."""

from agentblackbox.cli.main import app

if __name__ == "__main__":
    app()
```

## STEP 4: Create src/agentblackbox/daemon/__init__.py

```python
"""Daemon package — core recording engine."""
```

## STEP 5: Create src/agentblackbox/daemon/config.py

This is the SINGLE source of truth for all configuration.
Copy EXACTLY — do not add fields, do not rename anything:

```python
"""Configuration management for AgentBlackBox."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import json
import os


# Default ignore patterns — files/dirs we never watch
DEFAULT_IGNORE_PATTERNS: List[str] = [
    "__pycache__",
    "*.pyc",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    "*.egg-info",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "dist",
    "build",
    "*.swp",
    "*.swo",
    "*~",
]


@dataclass
class BlackBoxConfig:
    """Central configuration for AgentBlackBox.

    Attributes:
        workspace_path: Root directory to monitor.
        db_path: Path to SQLite database file.
        ignore_patterns: File/dir patterns to skip.
        max_file_size_bytes: Skip files larger than this (default 1MB).
        debounce_ms: Milliseconds to debounce rapid file changes.
        dashboard_port: Port for the web dashboard.
        log_level: Logging level.
    """

    workspace_path: Path = field(default_factory=Path.cwd)
    db_path: Optional[Path] = None
    ignore_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATTERNS))
    max_file_size_bytes: int = 1_048_576  # 1 MB
    debounce_ms: int = 500
    dashboard_port: int = 7700
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        """Set derived defaults after init."""
        if self.db_path is None:
            self.db_path = self.workspace_path / ".agentblackbox" / "blackbox.db"

    @classmethod
    def from_file(cls, path: Path) -> "BlackBoxConfig":
        """Load config from a JSON file.

        Args:
            path: Path to config JSON file.

        Returns:
            Populated BlackBoxConfig instance.
        """
        with open(path, "r") as f:
            data = json.load(f)
        if "workspace_path" in data:
            data["workspace_path"] = Path(data["workspace_path"])
        if "db_path" in data:
            data["db_path"] = Path(data["db_path"])
        return cls(**data)

    def to_dict(self) -> dict:
        """Serialize config to a dictionary.

        Returns:
            Dictionary representation of config.
        """
        return {
            "workspace_path": str(self.workspace_path),
            "db_path": str(self.db_path),
            "ignore_patterns": self.ignore_patterns,
            "max_file_size_bytes": self.max_file_size_bytes,
            "debounce_ms": self.debounce_ms,
            "dashboard_port": self.dashboard_port,
            "log_level": self.log_level,
        }
```

## STEP 6: Create src/agentblackbox/storage/__init__.py

```python
"""Storage package — SQLite event persistence."""
```

## STEP 7: Create src/agentblackbox/storage/models.py

These are the EXACT data models. Do NOT change field names or types:

```python
"""Data models for AgentBlackBox events and sessions."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
import hashlib
import json
import uuid


def _utcnow() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    """Generate a new session ID."""
    return f"sess-{uuid.uuid4().hex[:12]}"


def _hash_payload(payload: dict) -> str:
    """SHA256 hash of payload for integrity verification.

    Args:
        payload: Dictionary to hash.

    Returns:
        Hex digest string.
    """
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------- Event Types ----------
# Use ONLY these constants. Never use raw strings.

class EventType:
    """Enumeration of all valid event types."""
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    CMD_EXECUTE = "cmd_execute"
    CMD_OUTPUT = "cmd_output"
    GIT_ADD = "git_add"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    GIT_FORCE_PUSH = "git_force_push"
    GIT_RESET = "git_reset"
    PROCESS_SPAWN = "process_spawn"
    PROCESS_EXIT = "process_exit"
    SECRET_DETECTED = "secret_detected"

    ALL = [
        FILE_CREATE, FILE_MODIFY, FILE_DELETE, FILE_RENAME,
        CMD_EXECUTE, CMD_OUTPUT,
        GIT_ADD, GIT_COMMIT, GIT_PUSH, GIT_FORCE_PUSH, GIT_RESET,
        PROCESS_SPAWN, PROCESS_EXIT,
        SECRET_DETECTED,
    ]


class Severity:
    """Enumeration of severity levels."""
    INFO = "info"
    WARNING = "warning"
    DANGER = "danger"
    CRITICAL = "critical"


# ---------- Data Classes ----------

@dataclass
class Event:
    """A single recorded event in a session.

    Attributes:
        session_id: ID of the parent session.
        event_type: Type from EventType constants.
        timestamp: ISO 8601 UTC timestamp.
        severity: Severity level.
        risk_score: Numeric risk 0.0-10.0.
        source_path: File path if applicable.
        payload: Event-specific data dictionary.
        tags: List of string tags for categorization.
        id: Auto-assigned database row ID.
        payload_hash: SHA256 of payload for integrity.
    """

    session_id: str
    event_type: str
    timestamp: str = field(default_factory=_utcnow)
    severity: str = Severity.INFO
    risk_score: float = 0.0
    source_path: Optional[str] = None
    payload: dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    id: Optional[int] = None
    payload_hash: str = ""

    def __post_init__(self) -> None:
        """Compute payload hash after init."""
        if not self.payload_hash and self.payload:
            self.payload_hash = _hash_payload(self.payload)


@dataclass
class Session:
    """A recording session — one per `abb start` invocation.

    Attributes:
        id: Unique session identifier.
        name: Human-readable name.
        workspace_path: Directory being monitored.
        agent_hint: Which AI agent is running (optional).
        started_at: ISO 8601 start time.
        ended_at: ISO 8601 end time (None if recording).
        status: Current state: recording | stopped.
        total_events: Count of events in this session.
        risk_score: Aggregate risk score.
    """

    workspace_path: str
    id: str = field(default_factory=_new_id)
    name: Optional[str] = None
    agent_hint: Optional[str] = None
    started_at: str = field(default_factory=_utcnow)
    ended_at: Optional[str] = None
    status: str = "recording"
    total_events: int = 0
    risk_score: float = 0.0

    def stop(self) -> None:
        """Mark session as stopped."""
        self.ended_at = _utcnow()
        self.status = "stopped"


@dataclass
class Alert:
    """A flagged high-risk event.

    Attributes:
        event_id: ID of the triggering event.
        session_id: Parent session.
        alert_type: Category of alert.
        description: Human-readable explanation.
        acknowledged: Whether user has seen this.
        created_at: When the alert was raised.
        id: Auto-assigned database row ID.
    """

    event_id: int
    session_id: str
    alert_type: str
    description: str
    acknowledged: bool = False
    created_at: str = field(default_factory=_utcnow)
    id: Optional[int] = None
```

## STEP 8: Create src/agentblackbox/storage/event_store.py

This is the MOST critical file. Copy the exact schema:

```python
"""SQLite-based event store with WAL mode for concurrent access."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional

import structlog

from agentblackbox.storage.models import Alert, Event, Session

logger = structlog.get_logger()

# SQL schema — do NOT modify column names or types
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    name            TEXT,
    workspace_path  TEXT NOT NULL,
    agent_hint      TEXT,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    status          TEXT DEFAULT 'recording',
    total_events    INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(id),
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT DEFAULT 'info',
    risk_score      REAL DEFAULT 0.0,
    source_path     TEXT,
    payload         TEXT,
    payload_hash    TEXT,
    tags            TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_path);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER REFERENCES events(id),
    session_id      TEXT REFERENCES sessions(id),
    alert_type      TEXT NOT NULL,
    description     TEXT,
    acknowledged    INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL
);
"""


class EventStore:
    """SQLite-backed storage for events, sessions, and alerts.

    Args:
        db_path: Path to SQLite database file. Parent dirs are auto-created.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema and enable WAL mode."""
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections.

        Yields:
            SQLite connection with row factory.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---------- Session Operations ----------

    def create_session(self, session: Session) -> Session:
        """Insert a new session record.

        Args:
            session: Session to store.

        Returns:
            The same session (with id set).
        """
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO sessions (id, name, workspace_path, agent_hint,
                   started_at, ended_at, status, total_events, risk_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session.id, session.name, session.workspace_path,
                    session.agent_hint, session.started_at, session.ended_at,
                    session.status, session.total_events, session.risk_score,
                ),
            )
        logger.info("session_created", session_id=session.id)
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieve a session by ID.

        Args:
            session_id: The session identifier.

        Returns:
            Session if found, None otherwise.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        return Session(
            id=row["id"], name=row["name"],
            workspace_path=row["workspace_path"],
            agent_hint=row["agent_hint"],
            started_at=row["started_at"], ended_at=row["ended_at"],
            status=row["status"], total_events=row["total_events"],
            risk_score=row["risk_score"],
        )

    def list_sessions(self, limit: int = 50) -> List[Session]:
        """List sessions ordered by most recent first.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of Session objects.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            Session(
                id=r["id"], name=r["name"],
                workspace_path=r["workspace_path"],
                agent_hint=r["agent_hint"],
                started_at=r["started_at"], ended_at=r["ended_at"],
                status=r["status"], total_events=r["total_events"],
                risk_score=r["risk_score"],
            )
            for r in rows
        ]

    def stop_session(self, session_id: str) -> None:
        """Mark a session as stopped with current timestamp.

        Args:
            session_id: The session to stop.
        """
        from agentblackbox.storage.models import _utcnow
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET status = 'stopped', ended_at = ? WHERE id = ?",
                (_utcnow(), session_id),
            )
        logger.info("session_stopped", session_id=session_id)

    # ---------- Event Operations ----------

    def insert_event(self, event: Event) -> Event:
        """Insert a single event and update session counters.

        Args:
            event: Event to store.

        Returns:
            Event with id populated.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO events (session_id, timestamp, event_type,
                   severity, risk_score, source_path, payload, payload_hash, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.session_id, event.timestamp, event.event_type,
                    event.severity, event.risk_score, event.source_path,
                    json.dumps(event.payload), event.payload_hash,
                    json.dumps(event.tags),
                ),
            )
            event.id = cursor.lastrowid
            # Update session counters
            conn.execute(
                """UPDATE sessions SET total_events = total_events + 1,
                   risk_score = MAX(risk_score, ?) WHERE id = ?""",
                (event.risk_score, event.session_id),
            )
        return event

    def insert_events_batch(self, events: List[Event]) -> None:
        """Insert multiple events in a single transaction.

        Args:
            events: List of events to store.
        """
        if not events:
            return
        with self._connect() as conn:
            for event in events:
                conn.execute(
                    """INSERT INTO events (session_id, timestamp, event_type,
                       severity, risk_score, source_path, payload, payload_hash, tags)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.session_id, event.timestamp, event.event_type,
                        event.severity, event.risk_score, event.source_path,
                        json.dumps(event.payload), event.payload_hash,
                        json.dumps(event.tags),
                    ),
                )
            # Bulk update session
            session_id = events[0].session_id
            max_risk = max(e.risk_score for e in events)
            conn.execute(
                """UPDATE sessions SET total_events = total_events + ?,
                   risk_score = MAX(risk_score, ?) WHERE id = ?""",
                (len(events), max_risk, session_id),
            )

    def query_events(
        self,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_path: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Event]:
        """Query events with optional filters.

        Args:
            session_id: Filter by session.
            event_type: Filter by event type.
            severity: Filter by severity.
            source_path: Filter by file path (exact match).
            limit: Max results.
            offset: Pagination offset.

        Returns:
            List of matching Event objects.
        """
        conditions = []
        params: list = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if source_path:
            conditions.append("source_path = ?")
            params.append(source_path)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_event(r) for r in rows]

    def search_events(self, query_text: str, session_id: Optional[str] = None) -> List[Event]:
        """Full-text search across event payloads and source paths.

        Args:
            query_text: Text to search for.
            session_id: Optional session filter.

        Returns:
            Matching events.
        """
        conditions = ["(payload LIKE ? OR source_path LIKE ? OR tags LIKE ?)"]
        like_param = f"%{query_text}%"
        params: list = [like_param, like_param, like_param]

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = f"WHERE {' AND '.join(conditions)}"
        query = f"SELECT * FROM events {where} ORDER BY timestamp ASC LIMIT 200"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_event(r) for r in rows]

    def get_events_for_file(self, file_path: str) -> List[Event]:
        """Get all events that touched a specific file.

        Args:
            file_path: The file path to look up.

        Returns:
            Events sorted chronologically.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE source_path = ? ORDER BY timestamp ASC",
                (file_path,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def _row_to_event(self, row: sqlite3.Row) -> Event:
        """Convert a database row to an Event object."""
        return Event(
            id=row["id"],
            session_id=row["session_id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            severity=row["severity"],
            risk_score=row["risk_score"],
            source_path=row["source_path"],
            payload=json.loads(row["payload"]) if row["payload"] else {},
            payload_hash=row["payload_hash"] or "",
            tags=json.loads(row["tags"]) if row["tags"] else [],
        )

    # ---------- Alert Operations ----------

    def create_alert(self, alert: Alert) -> Alert:
        """Insert an alert record.

        Args:
            alert: Alert to store.

        Returns:
            Alert with id populated.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO alerts (event_id, session_id, alert_type,
                   description, acknowledged, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    alert.event_id, alert.session_id, alert.alert_type,
                    alert.description, int(alert.acknowledged), alert.created_at,
                ),
            )
            alert.id = cursor.lastrowid
        return alert

    def get_alerts(self, session_id: Optional[str] = None, unacked_only: bool = False) -> List[Alert]:
        """Get alerts with optional filters.

        Args:
            session_id: Filter by session.
            unacked_only: Only unacknowledged alerts.

        Returns:
            List of alerts.
        """
        conditions = []
        params: list = []
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if unacked_only:
            conditions.append("acknowledged = 0")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY created_at DESC", params
            ).fetchall()
        return [
            Alert(
                id=r["id"], event_id=r["event_id"], session_id=r["session_id"],
                alert_type=r["alert_type"], description=r["description"],
                acknowledged=bool(r["acknowledged"]), created_at=r["created_at"],
            )
            for r in rows
        ]
```

## STEP 9: Create src/agentblackbox/daemon/session.py

```python
"""Session lifecycle manager."""

from pathlib import Path
from typing import Optional

import structlog

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Session

logger = structlog.get_logger()


class SessionManager:
    """Manages recording sessions — create, get current, stop.

    Args:
        config: BlackBox configuration.
        store: Event store instance.
    """

    def __init__(self, config: BlackBoxConfig, store: EventStore) -> None:
        self.config = config
        self.store = store
        self._current_session: Optional[Session] = None

    def start(self, name: Optional[str] = None, agent_hint: Optional[str] = None) -> Session:
        """Start a new recording session.

        Args:
            name: Optional human-readable name.
            agent_hint: Optional agent identifier (e.g., "cursor", "claude-code").

        Returns:
            The newly created Session.

        Raises:
            RuntimeError: If a session is already recording.
        """
        if self._current_session and self._current_session.status == "recording":
            raise RuntimeError(
                f"Session {self._current_session.id} is already recording. "
                "Stop it first with `abb stop`."
            )

        session = Session(
            workspace_path=str(self.config.workspace_path),
            name=name,
            agent_hint=agent_hint,
        )
        self.store.create_session(session)
        self._current_session = session
        logger.info("session_started", session_id=session.id, workspace=session.workspace_path)
        return session

    def stop(self) -> Optional[Session]:
        """Stop the current recording session.

        Returns:
            The stopped Session, or None if no session was active.
        """
        if not self._current_session:
            logger.warning("no_active_session")
            return None
        self.store.stop_session(self._current_session.id)
        self._current_session.stop()
        logger.info("session_stopped", session_id=self._current_session.id)
        stopped = self._current_session
        self._current_session = None
        return stopped

    @property
    def current(self) -> Optional[Session]:
        """Get the currently active session."""
        return self._current_session

    @property
    def is_recording(self) -> bool:
        """Check if a session is actively recording."""
        return (
            self._current_session is not None
            and self._current_session.status == "recording"
        )
```

## STEP 10: Create tests/conftest.py

```python
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
```

## STEP 11: Create tests/test_storage/test_event_store.py

```python
"""Tests for EventStore — SQLite persistence layer."""

import pytest
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import (
    Event, Session, Alert, EventType, Severity
)


class TestSessionCRUD:
    """Test session create/read/list/stop operations."""

    def test_create_and_get_session(self, store: EventStore, sample_session: Session) -> None:
        """Session can be created and retrieved by ID."""
        store.create_session(sample_session)
        retrieved = store.get_session(sample_session.id)
        assert retrieved is not None
        assert retrieved.id == sample_session.id
        assert retrieved.status == "recording"
        assert retrieved.workspace_path == sample_session.workspace_path

    def test_list_sessions(self, store: EventStore, sample_session: Session) -> None:
        """Sessions are listed in reverse chronological order."""
        store.create_session(sample_session)
        sessions = store.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].id == sample_session.id

    def test_stop_session(self, store: EventStore, sample_session: Session) -> None:
        """Stopping a session sets status and ended_at."""
        store.create_session(sample_session)
        store.stop_session(sample_session.id)
        retrieved = store.get_session(sample_session.id)
        assert retrieved is not None
        assert retrieved.status == "stopped"
        assert retrieved.ended_at is not None

    def test_get_nonexistent_session(self, store: EventStore) -> None:
        """Getting a non-existent session returns None."""
        result = store.get_session("sess-doesnotexist")
        assert result is None


class TestEventCRUD:
    """Test event insert/query/search operations."""

    def test_insert_and_query_event(self, store: EventStore, sample_session: Session, sample_event: Event) -> None:
        """Event can be inserted and queried."""
        store.create_session(sample_session)
        inserted = store.insert_event(sample_event)
        assert inserted.id is not None
        events = store.query_events(session_id=sample_session.id)
        assert len(events) == 1
        assert events[0].event_type == EventType.FILE_CREATE

    def test_insert_updates_session_counter(self, store: EventStore, sample_session: Session, sample_event: Event) -> None:
        """Inserting an event increments session's total_events."""
        store.create_session(sample_session)
        store.insert_event(sample_event)
        session = store.get_session(sample_session.id)
        assert session is not None
        assert session.total_events == 1

    def test_query_by_event_type(self, store: EventStore, sample_session: Session) -> None:
        """Events can be filtered by type."""
        store.create_session(sample_session)
        e1 = Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path="a.py")
        e2 = Event(session_id=sample_session.id, event_type=EventType.FILE_DELETE, source_path="b.py")
        store.insert_event(e1)
        store.insert_event(e2)
        creates = store.query_events(session_id=sample_session.id, event_type=EventType.FILE_CREATE)
        assert len(creates) == 1
        assert creates[0].source_path == "a.py"

    def test_search_events_by_payload(self, store: EventStore, sample_session: Session) -> None:
        """Events can be searched by payload content."""
        store.create_session(sample_session)
        event = Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"command": "rm -rf /tmp/test"},
        )
        store.insert_event(event)
        results = store.search_events("rm -rf")
        assert len(results) == 1
        assert results[0].payload["command"] == "rm -rf /tmp/test"

    def test_get_events_for_file(self, store: EventStore, sample_session: Session) -> None:
        """All events for a specific file can be retrieved."""
        store.create_session(sample_session)
        for i in range(3):
            store.insert_event(Event(
                session_id=sample_session.id,
                event_type=EventType.FILE_MODIFY,
                source_path="src/auth.py",
                payload={"change": i},
            ))
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_CREATE,
            source_path="src/other.py",
        ))
        auth_events = store.get_events_for_file("src/auth.py")
        assert len(auth_events) == 3

    def test_batch_insert(self, store: EventStore, sample_session: Session) -> None:
        """Multiple events can be inserted in a batch."""
        store.create_session(sample_session)
        events = [
            Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path=f"file{i}.py")
            for i in range(5)
        ]
        store.insert_events_batch(events)
        all_events = store.query_events(session_id=sample_session.id)
        assert len(all_events) == 5
        session = store.get_session(sample_session.id)
        assert session is not None
        assert session.total_events == 5


class TestAlerts:
    """Test alert operations."""

    def test_create_and_get_alert(self, store: EventStore, sample_session: Session, sample_event: Event) -> None:
        """Alert can be created and retrieved."""
        store.create_session(sample_session)
        stored_event = store.insert_event(sample_event)
        alert = Alert(
            event_id=stored_event.id,
            session_id=sample_session.id,
            alert_type="secret_leak",
            description="API key detected in src/main.py",
        )
        created = store.create_alert(alert)
        assert created.id is not None
        alerts = store.get_alerts(session_id=sample_session.id)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "secret_leak"

    def test_filter_unacked_alerts(self, store: EventStore, sample_session: Session, sample_event: Event) -> None:
        """Can filter to only unacknowledged alerts."""
        store.create_session(sample_session)
        stored_event = store.insert_event(sample_event)
        a1 = Alert(event_id=stored_event.id, session_id=sample_session.id,
                   alert_type="secret_leak", description="leak 1", acknowledged=False)
        a2 = Alert(event_id=stored_event.id, session_id=sample_session.id,
                   alert_type="destructive_cmd", description="rm -rf", acknowledged=True)
        store.create_alert(a1)
        store.create_alert(a2)
        unacked = store.get_alerts(session_id=sample_session.id, unacked_only=True)
        assert len(unacked) == 1
        assert unacked[0].alert_type == "secret_leak"
```

## STEP 12: Create remaining __init__.py files

Create empty `__init__.py` in ALL missing packages:
- `src/agentblackbox/watchers/__init__.py`
- `src/agentblackbox/analysis/__init__.py`
- `src/agentblackbox/replay/__init__.py`
- `src/agentblackbox/api/__init__.py`
- `src/agentblackbox/api/routes/__init__.py`
- `src/agentblackbox/cli/__init__.py`
- `tests/__init__.py` (empty)
- `tests/test_storage/__init__.py` (empty)
- `tests/test_watchers/__init__.py` (empty)
- `tests/test_analysis/__init__.py` (empty)
- `tests/test_replay/__init__.py` (empty)

Each file content: just an empty string or a one-line docstring.

## STEP 13: Create placeholder cli/main.py

```python
"""CLI entry point — placeholder for Phase 3."""

import typer

app = typer.Typer(
    name="abb",
    help="AgentBlackBox — The flight recorder for AI agents.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Show version."""
    from agentblackbox import __version__
    typer.echo(f"AgentBlackBox v{__version__}")
```

## STEP 14: Run tests

```bash
cd AgentBlackBox
pip install -e ".[dev]"
python -m pytest tests/test_storage/ -v --tb=short
```

### Expected output:
```
tests/test_storage/test_event_store.py::TestSessionCRUD::test_create_and_get_session PASSED
tests/test_storage/test_event_store.py::TestSessionCRUD::test_list_sessions PASSED
tests/test_storage/test_event_store.py::TestSessionCRUD::test_stop_session PASSED
tests/test_storage/test_event_store.py::TestSessionCRUD::test_get_nonexistent_session PASSED
tests/test_storage/test_event_store.py::TestEventCRUD::test_insert_and_query_event PASSED
tests/test_storage/test_event_store.py::TestEventCRUD::test_insert_updates_session_counter PASSED
tests/test_storage/test_event_store.py::TestEventCRUD::test_query_by_event_type PASSED
tests/test_storage/test_event_store.py::TestEventCRUD::test_search_events_by_payload PASSED
tests/test_storage/test_event_store.py::TestEventCRUD::test_get_events_for_file PASSED
tests/test_storage/test_event_store.py::TestEventCRUD::test_batch_insert PASSED
tests/test_storage/test_event_store.py::TestAlerts::test_create_and_get_alert PASSED
tests/test_storage/test_event_store.py::TestAlerts::test_filter_unacked_alerts PASSED

12 passed
```

## ✅ PHASE 1 COMPLETE CHECKLIST
- [ ] pyproject.toml exists and is valid
- [ ] All __init__.py files created
- [ ] config.py has BlackBoxConfig dataclass
- [ ] models.py has Event, Session, Alert, EventType, Severity
- [ ] event_store.py has EventStore with full CRUD
- [ ] session.py has SessionManager
- [ ] conftest.py has all shared fixtures
- [ ] test_event_store.py has 12 tests
- [ ] ALL 12 tests PASS
- [ ] No lint errors

## NEXT: Read `.build/phase2_watchers.md`

