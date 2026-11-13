"""SQLite-based event store with WAL mode, secret redaction, and hash chaining."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

import structlog

from agentblackbox.analysis.redactor import redact_payload
from agentblackbox.storage.models import (
    Alert,
    ChainVerificationResult,
    Event,
    FileSnapshot,
    Session,
    Severity,
    _compute_event_hash,
    _compute_event_hash_v1,
    _hash_payload,
)

logger = structlog.get_logger()

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
    seq             INTEGER DEFAULT 0,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT DEFAULT 'info',
    risk_score      REAL DEFAULT 0.0,
    source_path     TEXT,
    payload         TEXT,
    payload_hash    TEXT,
    prev_hash       TEXT DEFAULT '',
    event_hash      TEXT DEFAULT '',
    hash_version    INTEGER DEFAULT 2,
    agent_id        TEXT,
    pid             INTEGER,
    parent_event_id INTEGER,
    blob_hash       TEXT,
    tags            TEXT
);

CREATE TABLE IF NOT EXISTS file_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(id),
    event_id        INTEGER REFERENCES events(id),
    file_path       TEXT NOT NULL,
    blob_hash       TEXT NOT NULL,
    size_bytes      INTEGER DEFAULT 0,
    timestamp       TEXT NOT NULL
);

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

_INDEX_SCHEMA = """
DROP INDEX IF EXISTS idx_events_session_seq;
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_session_seq_unique ON events(session_id, seq) WHERE seq > 0;
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_path);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_session ON file_snapshots(session_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_file ON file_snapshots(file_path);
"""

_EVENT_MIGRATION_COLUMNS: List[Tuple[str, str]] = [
    ("seq", "INTEGER DEFAULT 0"),
    ("prev_hash", "TEXT DEFAULT ''"),
    ("event_hash", "TEXT DEFAULT ''"),
    ("hash_version", "INTEGER DEFAULT 1"),
    ("agent_id", "TEXT"),
    ("pid", "INTEGER"),
    ("parent_event_id", "INTEGER"),
    ("blob_hash", "TEXT"),
]


class EventStore:
    """SQLite-backed storage for events, sessions, snapshots, and alerts.

    Enforces secret redaction before disk persistence and maintains a per-session
    tamper-evident SHA-256 hash chain.

    Args:
        db_path: Path to SQLite database file. Parent dirs are auto-created.
    """

    def __init__(self, db_path: Path, blobs_dir: Optional[Path] = None) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.blobs_dir = blobs_dir or (self.db_path.parent / "blobs")
        from agentblackbox.storage.blob_store import BlobStore
        self.blob_store = BlobStore(self.blobs_dir)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema, additive columns, and WAL mode."""
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(_SCHEMA)
            self._ensure_event_columns(conn)
            conn.executescript(_INDEX_SCHEMA)

    def _ensure_event_columns(self, conn: sqlite3.Connection) -> None:
        """Add v0.2 columns to pre-existing v0.1 event tables if absent."""
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(events)").fetchall()
        }
        for col_name, col_def in _EVENT_MIGRATION_COLUMNS:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_def}")

    @contextmanager
    def _connect(self, write: bool = False) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections.

        Args:
            write: If True, executes ``BEGIN IMMEDIATE`` to acquire an exclusive
                write lock up front, eliminating concurrency races between parallel
                watchers/processes.

        Yields:
            SQLite connection with row factory.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout = 5000")
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
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

    # ---------- Event Preparation & Chain Helpers ----------

    def _prepare_event(self, event: Event, seq: int, prev_hash: str) -> Event:
        """Redact secrets from payload, assign chain metadata, and hash."""
        clean_payload, matches = redact_payload(event.payload)
        event.payload = clean_payload
        event.payload_hash = _hash_payload(event.payload) if event.payload else ""

        if matches:
            if "secret_redacted" not in event.tags:
                event.tags = list(event.tags) + ["secret_redacted"]
            if "secret" not in event.tags:
                event.tags = list(event.tags) + ["secret"]
            event.risk_score = max(float(event.risk_score), 8.0)
            event.severity = Severity.CRITICAL

        if getattr(event, "hash_version", 2) == 1:
            raise ValueError(
                "Legacy hash_version=1 is not permitted for new event inserts. "
                "All new events must use canonical hash_version=2."
            )
        event.hash_version = 2
        event.seq = seq
        event.prev_hash = prev_hash
        event.event_hash = _compute_event_hash(event)
        return event

    def _get_chain_tip(self, conn: sqlite3.Connection, session_id: str) -> Tuple[int, str]:
        """Return (last_seq, last_event_hash) for a session inside a transaction."""
        row = conn.execute(
            "SELECT seq, event_hash FROM events WHERE session_id = ? ORDER BY seq DESC, id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        if row is None:
            return 0, "GENESIS"
        return int(row["seq"] or 0), row["event_hash"] or "GENESIS"

    # ---------- Event Operations ----------

    def insert_event(self, event: Event) -> Event:
        """Insert a single event with secret redaction and hash-chain linkage.

        Acquires an exclusive write lock (BEGIN IMMEDIATE) up front.
        Retries with backoff if SQLite encounters high concurrent contention.

        Args:
            event: Event to store.

        Returns:
            Event with id, seq, prev_hash, and event_hash populated.
        """
        import random
        import time

        last_err: Optional[Exception] = None
        for attempt in range(5):
            try:
                with self._connect(write=True) as conn:
                    last_seq, prev_hash = self._get_chain_tip(conn, event.session_id)
                    self._prepare_event(event, seq=last_seq + 1, prev_hash=prev_hash)

                    cursor = conn.execute(
                        """INSERT INTO events (session_id, seq, timestamp, event_type,
                           severity, risk_score, source_path, payload, payload_hash,
                           prev_hash, event_hash, hash_version, agent_id, pid, parent_event_id,
                           blob_hash, tags)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            event.session_id, event.seq, event.timestamp, event.event_type,
                            event.severity, event.risk_score, event.source_path,
                            json.dumps(event.payload), event.payload_hash,
                            event.prev_hash, event.event_hash, event.hash_version,
                            event.agent_id, event.pid, event.parent_event_id,
                            event.blob_hash, json.dumps(event.tags),
                        ),
                    )
                    event.id = cursor.lastrowid

                    if event.blob_hash and event.source_path:
                        conn.execute(
                            """INSERT INTO file_snapshots (session_id, event_id, file_path,
                               blob_hash, size_bytes, timestamp)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (
                                event.session_id, event.id, event.source_path,
                                event.blob_hash, int(event.payload.get("file_size", 0)),
                                event.timestamp,
                            ),
                        )

                    conn.execute(
                        """UPDATE sessions SET total_events = total_events + 1,
                           risk_score = MAX(risk_score, ?) WHERE id = ?""",
                        (event.risk_score, event.session_id),
                    )
                return event
            except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
                last_err = e
                time.sleep(0.02 * (2 ** attempt) + random.uniform(0.005, 0.02))

        if last_err:
            raise last_err
        return event

    def insert_events_batch(self, events: List[Event]) -> None:
        """Insert multiple events in a single transaction with intact hash chains.

        Args:
            events: List of events to store.
        """
        if not events:
            return
        with self._connect(write=True) as conn:
            tips: Dict[str, Tuple[int, str]] = {}
            counts: Dict[str, int] = {}
            max_risks: Dict[str, float] = {}

            for event in events:
                if event.session_id not in tips:
                    tips[event.session_id] = self._get_chain_tip(conn, event.session_id)
                last_seq, prev_hash = tips[event.session_id]
                self._prepare_event(event, seq=last_seq + 1, prev_hash=prev_hash)
                tips[event.session_id] = (event.seq, event.event_hash)

                cursor = conn.execute(
                    """INSERT INTO events (session_id, seq, timestamp, event_type,
                       severity, risk_score, source_path, payload, payload_hash,
                       prev_hash, event_hash, hash_version, agent_id, pid, parent_event_id,
                       blob_hash, tags)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.session_id, event.seq, event.timestamp, event.event_type,
                        event.severity, event.risk_score, event.source_path,
                        json.dumps(event.payload), event.payload_hash,
                        event.prev_hash, event.event_hash, event.hash_version,
                        event.agent_id, event.pid, event.parent_event_id,
                        event.blob_hash, json.dumps(event.tags),
                    ),
                )
                event.id = cursor.lastrowid

                if event.blob_hash and event.source_path:
                    conn.execute(
                        """INSERT INTO file_snapshots (session_id, event_id, file_path,
                           blob_hash, size_bytes, timestamp)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            event.session_id, event.id, event.source_path,
                            event.blob_hash, int(event.payload.get("file_size", 0)),
                            event.timestamp,
                        ),
                    )

                counts[event.session_id] = counts.get(event.session_id, 0) + 1
                max_risks[event.session_id] = max(
                    max_risks.get(event.session_id, 0.0), event.risk_score
                )

            for sid, cnt in counts.items():
                conn.execute(
                    """UPDATE sessions SET total_events = total_events + ?,
                       risk_score = MAX(risk_score, ?) WHERE id = ?""",
                    (cnt, max_risks[sid], sid),
                )

    def verify_chain(
        self,
        session_id: str,
        verify_blobs: bool = True,
        hmac_key: Optional[bytes] = None,
    ) -> ChainVerificationResult:
        """Verify sequence continuity, payload integrity, and hash-chain linkage.

        Args:
            session_id: Session ID to verify.
            verify_blobs: If True, re-hashes on-disk content blobs and fails if missing or tampered.
            hmac_key: Optional HMAC key for HMAC-SHA256 chain verification.

        Returns:
            ChainVerificationResult indicating validity and failure reason if tampered.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE session_id = ? ORDER BY seq ASC, id ASC",
                (session_id,),
            ).fetchall()

        if not rows:
            return ChainVerificationResult(session_id=session_id, valid=True, total_events=0)

        expected_prev = "GENESIS"
        for idx, row in enumerate(rows, start=1):
            event = self._row_to_event(row)
            if event.seq != idx:
                return ChainVerificationResult(
                    session_id=session_id,
                    valid=False,
                    total_events=len(rows),
                    broken_at_seq=event.seq,
                    reason=f"Sequence gap or mismatch: expected {idx}, got {event.seq}",
                )
            if event.prev_hash != expected_prev:
                return ChainVerificationResult(
                    session_id=session_id,
                    valid=False,
                    total_events=len(rows),
                    broken_at_seq=event.seq,
                    reason=f"prev_hash mismatch at seq {event.seq}",
                )
            expected_payload_hash = _hash_payload(event.payload) if event.payload else ""
            if event.payload_hash != expected_payload_hash:
                return ChainVerificationResult(
                    session_id=session_id,
                    valid=False,
                    total_events=len(rows),
                    broken_at_seq=event.seq,
                    reason=f"payload_hash mismatch at seq {event.seq}",
                )
            if getattr(event, "hash_version", 2) == 1:
                expected_event_hash = _compute_event_hash_v1(event)
            else:
                expected_event_hash = _compute_event_hash(event, hmac_key=hmac_key)

            if event.event_hash != expected_event_hash:
                return ChainVerificationResult(
                    session_id=session_id,
                    valid=False,
                    total_events=len(rows),
                    broken_at_seq=event.seq,
                    reason=f"event_hash mismatch at seq {event.seq} (hash_version {getattr(event, 'hash_version', 2)})",
                )
            if verify_blobs and event.blob_hash:
                valid_blob, blob_err = self.blob_store.verify_blob(event.blob_hash)
                if not valid_blob:
                    return ChainVerificationResult(
                        session_id=session_id,
                        valid=False,
                        total_events=len(rows),
                        broken_at_seq=event.seq,
                        reason=f"Blob integrity failure at seq {event.seq}: {blob_err}",
                    )

            expected_prev = event.event_hash

        return ChainVerificationResult(
            session_id=session_id,
            valid=True,
            total_events=len(rows),
        )

    def get_file_snapshots(
        self, file_path: str, session_id: Optional[str] = None
    ) -> List[FileSnapshot]:
        """Retrieve snapshot metadata records for a file path.

        Args:
            file_path: Source path to query.
            session_id: Optional session filter.

        Returns:
            List of FileSnapshot records ordered chronologically.
        """
        conditions = ["file_path = ?"]
        params: list = [file_path]
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        where = " AND ".join(conditions)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM file_snapshots WHERE {where} ORDER BY timestamp ASC, id ASC",
                params,
            ).fetchall()
        return [
            FileSnapshot(
                id=r["id"],
                session_id=r["session_id"],
                event_id=r["event_id"],
                file_path=r["file_path"],
                blob_hash=r["blob_hash"],
                size_bytes=r["size_bytes"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

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
        query = f"SELECT * FROM events {where} ORDER BY timestamp ASC, seq ASC LIMIT ? OFFSET ?"
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
                "SELECT * FROM events WHERE source_path = ? ORDER BY timestamp ASC, seq ASC",
                (file_path,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def _row_to_event(self, row: sqlite3.Row) -> Event:
        """Convert a database row to an Event object."""
        keys = row.keys()
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
            seq=row["seq"] if "seq" in keys and row["seq"] is not None else 0,
            prev_hash=row["prev_hash"] if "prev_hash" in keys and row["prev_hash"] else "",
            event_hash=row["event_hash"] if "event_hash" in keys and row["event_hash"] else "",
            hash_version=row["hash_version"] if "hash_version" in keys and row["hash_version"] is not None else 1,
            agent_id=row["agent_id"] if "agent_id" in keys else None,
            pid=row["pid"] if "pid" in keys else None,
            parent_event_id=row["parent_event_id"] if "parent_event_id" in keys else None,
            blob_hash=row["blob_hash"] if "blob_hash" in keys else None,
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
