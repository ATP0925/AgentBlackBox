"""Tests for tamper-evident hash chain, attribution columns, redaction, and migration."""

import sqlite3
from pathlib import Path

from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity


class TestHashChainAndAttribution:
    """Test monotonic seq, prev_hash/event_hash linkage, tamper detection, and attribution."""

    def test_chain_builds_and_verifies(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        e1 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"command": "pytest"},
            agent_id="claude-code",
            pid=4242,
        ))
        e2 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_MODIFY,
            source_path="src/app.py",
            payload={"file_size": 120},
            agent_id="claude-code",
            pid=4242,
            parent_event_id=e1.id,
        ))

        assert e1.seq == 1
        assert e1.prev_hash == "GENESIS"
        assert len(e1.event_hash) == 64
        assert e2.seq == 2
        assert e2.prev_hash == e1.event_hash
        assert e2.parent_event_id == e1.id

        queried = store.query_events(session_id=sample_session.id)
        assert queried[1].agent_id == "claude-code"
        assert queried[1].pid == 4242
        assert queried[1].parent_event_id == e1.id

        res = store.verify_chain(sample_session.id)
        assert res.valid is True
        assert res.total_events == 2

    def test_batch_insert_chain_valid(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        batch = [
            Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path=f"f{i}.py")
            for i in range(4)
        ]
        store.insert_events_batch(batch)
        res = store.verify_chain(sample_session.id)
        assert res.valid is True
        assert res.total_events == 4

    def test_redacts_before_store_and_preserves_valid_chain(
        self, store: EventStore, sample_session: Session
    ) -> None:
        store.create_session(sample_session)
        raw_secret = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
        inserted = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"command": f"curl -H 'Authorization: Bearer {raw_secret}'"},
        ))
        assert raw_secret not in inserted.payload["command"]
        assert "secret_redacted" in inserted.tags
        assert inserted.severity == Severity.CRITICAL
        assert inserted.risk_score >= 8.0

        # Also verify raw SQLite row contains NO plaintext secret
        with sqlite3.connect(str(store.db_path)) as conn:
            row = conn.execute("SELECT payload FROM events WHERE id = ?", (inserted.id,)).fetchone()
            assert raw_secret not in row[0]

        res = store.verify_chain(sample_session.id)
        assert res.valid is True

    def test_detects_payload_tampering(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        e1 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"command": "rm -rf /tmp/bad"},
        ))
        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute(
                'UPDATE events SET payload = \'{"command": "echo harmless"}\' WHERE id = ?',
                (e1.id,),
            )
            conn.commit()

        res = store.verify_chain(sample_session.id)
        assert res.valid is False
        assert res.broken_at_seq == 1
        assert "payload_hash" in (res.reason or "")

    def test_detects_metadata_tampering_and_deleted_row(
        self, store: EventStore, sample_session: Session
    ) -> None:
        store.create_session(sample_session)
        e1 = store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path="a.py"))
        e2 = store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="a.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_DELETE, source_path="a.py"))

        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute("UPDATE events SET source_path = 'innocent.py' WHERE id = ?", (e2.id,))
            conn.commit()
        res_meta = store.verify_chain(sample_session.id)
        assert res_meta.valid is False
        assert res_meta.broken_at_seq == 2

        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute("DELETE FROM events WHERE id = ?", (e1.id,))
            conn.commit()
        res_del = store.verify_chain(sample_session.id)
        assert res_del.valid is False

    def test_migrates_v01_schema_cleanly(self, tmp_path: Path) -> None:
        db_path = tmp_path / "legacy_v01.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.executescript("""
                CREATE TABLE sessions (
                    id TEXT PRIMARY KEY, name TEXT, workspace_path TEXT NOT NULL,
                    agent_hint TEXT, started_at TEXT NOT NULL, ended_at TEXT,
                    status TEXT DEFAULT 'recording', total_events INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id),
                    timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'info', risk_score REAL DEFAULT 0.0,
                    source_path TEXT, payload TEXT, payload_hash TEXT, tags TEXT
                );
            """)
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        store.create_session(sess)
        ev = store.insert_event(Event(
            session_id=sess.id,
            event_type=EventType.FILE_CREATE,
            source_path="migrated.py",
            agent_id="cursor",
        ))
        assert ev.seq == 1
        assert store.verify_chain(sess.id).valid is True
