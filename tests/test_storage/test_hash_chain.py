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

    def test_detects_attribution_or_metadata_tampering(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """Modifying agent_id, source_path, severity, or tags must invalidate the chain."""
        store.create_session(sample_session)
        e1 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_CREATE,
            source_path="auth.py",
            agent_id="claude-code",
            tags=["auth", "critical"],
        ))
        assert store.verify_chain(sample_session.id).valid is True

        # Attempt to spoof agent_id in SQLite directly
        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute("UPDATE events SET agent_id = 'developer' WHERE id = ?", (e1.id,))
            conn.commit()

        res = store.verify_chain(sample_session.id)
        assert res.valid is False
        assert res.broken_at_seq == 1
        assert "event_hash mismatch" in (res.reason or "")

    def test_concurrent_inserts_locked_without_race(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """Concurrent threads inserting into the same session must produce a continuous, valid chain."""
        import concurrent.futures

        store.create_session(sample_session)

        def _worker(thread_id: int) -> None:
            for i in range(10):
                store.insert_event(Event(
                    session_id=sample_session.id,
                    event_type=EventType.CMD_EXECUTE,
                    payload={"thread": thread_id, "step": i},
                ))

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_worker, tid) for tid in range(4)]
            for f in futures:
                f.result()

        res = store.verify_chain(sample_session.id)
        assert res.valid is True
        assert res.total_events == 40

    def test_detects_tags_and_source_path_tampering(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """Modifying tags or source_path in SQLite must invalidate the chain."""
        store.create_session(sample_session)
        e1 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_CREATE,
            source_path="auth.py",
            tags=["sensitive_file", "secret_redacted"],
        ))
        assert store.verify_chain(sample_session.id).valid is True

        # Malicious agent tries to remove the secret_redacted tag from SQLite
        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute("UPDATE events SET tags = '[\"harmless\"]' WHERE id = ?", (e1.id,))
            conn.commit()

        res = store.verify_chain(sample_session.id)
        assert res.valid is False
        assert res.broken_at_seq == 1
        assert "event_hash mismatch" in (res.reason or "")

    def test_legacy_v1_events_still_verify(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """Legacy sessions with v1 hashes must still pass chain verification."""
        import json
        from agentblackbox.storage.models import _compute_event_hash_v1, _hash_payload
        store.create_session(sample_session)
        payload = {"cmd": "ls"}
        e1 = Event(
            session_id=sample_session.id,
            seq=1,
            timestamp="2026-11-12T10:00:00Z",
            event_type=EventType.CMD_EXECUTE,
            payload=payload,
            payload_hash=_hash_payload(payload),
            prev_hash="GENESIS",
            agent_id="claude-code",
            pid=1234,
        )
        e1.event_hash = _compute_event_hash_v1(e1)
        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute(
                """INSERT INTO events (session_id, seq, timestamp, event_type,
                   severity, risk_score, source_path, payload, payload_hash,
                   prev_hash, event_hash, agent_id, pid, parent_event_id,
                   blob_hash, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    e1.session_id, e1.seq, e1.timestamp, e1.event_type,
                    e1.severity, e1.risk_score, e1.source_path,
                    json.dumps(e1.payload), e1.payload_hash,
                    e1.prev_hash, e1.event_hash,
                    e1.agent_id, e1.pid, e1.parent_event_id,
                    e1.blob_hash, json.dumps(e1.tags),
                ),
            )
            conn.commit()

        res = store.verify_chain(sample_session.id)
        assert res.valid is True
        assert res.total_events == 1

    def test_multiprocess_concurrent_inserts_valid_chain(
        self, tmp_path: Path
    ) -> None:
        """Multiple independent OS processes inserting concurrently must produce a clean linear chain."""
        import subprocess
        import sys

        db_path = tmp_path / "multiprocess_test.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path), name="multiprocess-session")
        store.create_session(sess)

        worker_code = (
            "import sys\n"
            "from pathlib import Path\n"
            "from agentblackbox.storage.event_store import EventStore\n"
            "from agentblackbox.storage.models import Event, EventType\n"
            "db_path = Path(sys.argv[1])\n"
            "session_id = sys.argv[2]\n"
            "proc_id = sys.argv[3]\n"
            "count = int(sys.argv[4])\n"
            "store = EventStore(db_path)\n"
            "for i in range(count):\n"
            "    store.insert_event(Event(\n"
            "        session_id=session_id,\n"
            "        event_type=EventType.CMD_EXECUTE,\n"
            "        payload={'proc_id': proc_id, 'step': i},\n"
            "        agent_id=f'worker-{proc_id}',\n"
            "    ))\n"
            "sys.exit(0)\n"
        )

        num_procs = 4
        events_per_proc = 10
        procs = []
        for p_idx in range(num_procs):
            cmd = [
                sys.executable,
                "-c",
                worker_code,
                str(db_path),
                sess.id,
                str(p_idx),
                str(events_per_proc),
            ]
            procs.append(subprocess.Popen(cmd))

        for p in procs:
            exit_code = p.wait(timeout=20)
            assert exit_code == 0

        res = store.verify_chain(sess.id)
        assert res.valid is True
        assert res.total_events == num_procs * events_per_proc




