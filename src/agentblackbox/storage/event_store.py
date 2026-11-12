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

