"""Tests for tamper-evident hash chain, attribution columns, redaction, and migration."""

import json
import sqlite3
import pytest
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
        sample_session.v1_max_seq = 1
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
                   prev_hash, event_hash, hash_version, agent_id, pid, parent_event_id,
                   blob_hash, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    e1.session_id, e1.seq, e1.timestamp, e1.event_type,
                    e1.severity, e1.risk_score, e1.source_path,
                    json.dumps(e1.payload), e1.payload_hash,
                    e1.prev_hash, e1.event_hash, 1,
                    e1.agent_id, e1.pid, e1.parent_event_id,
                    e1.blob_hash, json.dumps(e1.tags),
                ),
            )
            conn.commit()

        res = store.verify_chain(sample_session.id)
        assert res.valid is True
        assert res.total_events == 1

        loaded = store.query_events(session_id=sample_session.id)
        assert loaded[0].hash_version == 1

        # Now insert a new event and ensure it gets hash_version = 2
        new_ev = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_CREATE,
            source_path="new.py",
        ))
        assert new_ev.hash_version == 2
        res2 = store.verify_chain(sample_session.id)
        assert res2.valid is True
        assert res2.total_events == 2

    def test_rejects_legacy_v1_for_new_inserts(self, store: EventStore, sample_session: Session) -> None:
        """New event inserts must reject hash_version=1."""
        store.create_session(sample_session)
        with pytest.raises(ValueError, match="Legacy hash_version=1 is not permitted"):
            store.insert_event(Event(
                session_id=sample_session.id,
                event_type=EventType.FILE_CREATE,
                source_path="foo.py",
                hash_version=1,
            ))

    def test_hmac_keyed_hash_chain_prevents_offline_forgery(self, tmp_path: Path) -> None:
        """When ABB_HMAC_KEY is active, event hashes are cryptographic HMAC signatures."""
        import os
        db_path = tmp_path / "hmac_test.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        store.create_session(sess)

        key = b"super-secret-audit-hmac-key-123456"
        os.environ["ABB_HMAC_KEY"] = key.decode("utf-8")
        try:
            ev = store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                source_path="cmd.sh",
            ))
            # Verification with matching key passes
            res = store.verify_chain(sess.id, hmac_key=key)
            assert res.valid is True

            # Verification with wrong key fails because hash is keyed HMAC
            wrong_res = store.verify_chain(sess.id, hmac_key=b"wrong-key-000000000000")
            assert wrong_res.valid is False
            assert "mismatch" in (wrong_res.reason or "").lower()
        finally:
            os.environ.pop("ABB_HMAC_KEY", None)

    def test_verify_chain_detects_sqlite_direct_downgrade_to_v1(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """Attacker modifying SQLite directly to set hash_version=1 must be caught by watermark cutoff."""
        from agentblackbox.storage.models import _compute_event_hash_v1
        store.create_session(sample_session)
        e1 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "pwd"},
        ))
        e2 = store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "ls"},
        ))
        assert store.verify_chain(sample_session.id).valid is True

        # Attacker with direct SQLite access tries to tamper with e2 by setting hash_version=1
        e2.hash_version = 1
        fake_v1_hash = _compute_event_hash_v1(e2)
        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute(
                "UPDATE events SET hash_version = 1, event_hash = ? WHERE seq = 2",
                (fake_v1_hash,),
            )
            conn.commit()

        res = store.verify_chain(sample_session.id)
        assert res.valid is False
        assert "Downgrade attack detected" in (res.reason or "")
        assert "seq 2" in (res.reason or "")

    def test_keyed_session_rejects_unkeyed_verification(self, tmp_path: Path) -> None:
        """A session recorded with HMAC key must reject unkeyed verification."""
        import os
        db_path = tmp_path / "keyed_sess.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        key = b"audit-hmac-key-999"
        os.environ["ABB_HMAC_KEY"] = key.decode("utf-8")
        try:
            store.create_session(sess)
            store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"cmd": "whoami"},
            ))
        finally:
            os.environ.pop("ABB_HMAC_KEY", None)

        # Environment no longer has key; calling verify_chain without key must fail
        res = store.verify_chain(sess.id)
        assert res.valid is False
        assert "HMAC verification failure" in (res.reason or "")

        # Supplying correct key verifies cleanly
        valid_res = store.verify_chain(sess.id, hmac_key=key)
        assert valid_res.valid is True

    def test_attacker_clears_is_keyed_and_recomputes_plain_chain_fails_when_key_configured(
        self, tmp_path: Path
    ) -> None:
        """Attacker clearing sessions.is_keyed=0 and writing plain SHA256 hashes must fail when key is configured."""
        import os
        from agentblackbox.storage.models import _compute_event_hash
        db_path = tmp_path / "tamper_keyed.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        key = b"strong-audit-key-12345"
        os.environ["ABB_HMAC_KEY"] = key.decode("utf-8")
        try:
            store.create_session(sess)
            e1 = store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"cmd": "git status"},
            ))
            assert store.verify_chain(sess.id, hmac_key=key).valid is True

            # Attacker opens SQLite directly, sets is_keyed = 0, and recomputes plain SHA-256 event_hash
            plain_hash = _compute_event_hash(e1, hmac_key=None)  # unkeyed
            with sqlite3.connect(str(db_path)) as conn:
                conn.execute(
                    "UPDATE sessions SET is_keyed = 0 WHERE id = ?", (sess.id,)
                )
                conn.execute(
                    "UPDATE events SET event_hash = ? WHERE id = ?", (plain_hash, e1.id)
                )
                conn.commit()

            # Verifier runs with configured key: MUST FAIL!
            res = store.verify_chain(sess.id, hmac_key=key)
            assert res.valid is False
            assert "mismatch" in (res.reason or "").lower() or "tampering" in (res.reason or "").lower()
        finally:
            os.environ.pop("ABB_HMAC_KEY", None)

    def test_attacker_raises_v1_max_seq_detected_when_key_configured(
        self, tmp_path: Path
    ) -> None:
        """Attacker modifying sessions.v1_max_seq directly in SQLite must fail meta_mac verification."""
        import os
        from agentblackbox.storage.models import _compute_event_hash_v1
        db_path = tmp_path / "tamper_v1_max.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        key = b"strong-audit-key-12345"
        os.environ["ABB_HMAC_KEY"] = key.decode("utf-8")
        try:
            store.create_session(sess)
            e1 = store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"cmd": "pwd"},
            ))
            assert store.verify_chain(sess.id, hmac_key=key).valid is True

            # Attacker sets v1_max_seq = 10 and changes e1 to hash_version=1 with v1 hash
            fake_v1_hash = _compute_event_hash_v1(e1)
            with sqlite3.connect(str(db_path)) as conn:
                conn.execute(
                    "UPDATE sessions SET v1_max_seq = 10 WHERE id = ?", (sess.id,)
                )
                conn.execute(
                    "UPDATE events SET hash_version = 1, event_hash = ? WHERE id = ?",
                    (fake_v1_hash, e1.id),
                )
                conn.commit()

            # Verification must fail because session metadata was tampered or meta_mac mismatch
            res = store.verify_chain(sess.id, hmac_key=key)
            assert res.valid is False
            assert "tampering" in (res.reason or "").lower() or "mismatch" in (res.reason or "").lower()
        finally:
            os.environ.pop("ABB_HMAC_KEY", None)

    def test_upgrade_legacy_db_v1_rows_verify_after_migration(self, tmp_path: Path) -> None:
        """A legacy v0.2.0a1-style database must cleanly backfill v1_max_seq and verify both old and new events."""
        import json
        from agentblackbox.storage.models import _compute_event_hash_v1, _hash_payload

        db_path = tmp_path / "legacy_v01.db"
        # 1. Create a legacy table without v1_max_seq, is_keyed, meta_mac
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                """CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    workspace_path TEXT NOT NULL,
                    agent_hint TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    status TEXT DEFAULT 'recording',
                    total_events INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0
                )"""
            )
            conn.execute(
                """CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id),
                    seq INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    risk_score REAL DEFAULT 0.0,
                    source_path TEXT,
                    payload TEXT,
                    payload_hash TEXT,
                    prev_hash TEXT DEFAULT '',
                    event_hash TEXT DEFAULT '',
                    agent_id TEXT,
                    pid INTEGER,
                    parent_event_id INTEGER,
                    blob_hash TEXT,
                    tags TEXT
                )"""
            )
            sess_id = "sess-legacy-123"
            conn.execute(
                "INSERT INTO sessions (id, workspace_path, started_at) VALUES (?, ?, ?)",
                (sess_id, str(tmp_path), "2026-11-10T10:00:00Z"),
            )
            # Insert 2 legacy v1 events
            p1 = {"cmd": "init"}
            e1 = Event(
                session_id=sess_id, seq=1, timestamp="2026-11-10T10:00:01Z",
                event_type=EventType.CMD_EXECUTE, payload=p1, payload_hash=_hash_payload(p1),
                prev_hash="GENESIS",
            )
            h1 = _compute_event_hash_v1(e1)
            conn.execute(
                """INSERT INTO events (session_id, seq, timestamp, event_type, payload, payload_hash, prev_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (sess_id, 1, e1.timestamp, e1.event_type, json.dumps(p1), e1.payload_hash, "GENESIS", h1),
            )

            p2 = {"cmd": "build"}
            e2 = Event(
                session_id=sess_id, seq=2, timestamp="2026-11-10T10:00:02Z",
                event_type=EventType.CMD_EXECUTE, payload=p2, payload_hash=_hash_payload(p2),
                prev_hash=h1,
            )
            h2 = _compute_event_hash_v1(e2)
            conn.execute(
                """INSERT INTO events (session_id, seq, timestamp, event_type, payload, payload_hash, prev_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (sess_id, 2, e2.timestamp, e2.event_type, json.dumps(p2), e2.payload_hash, h1, h2),
            )
            conn.commit()

        # 2. Now open with new EventStore code - migration must run automatically
        store = EventStore(db_path)
        sess = store.get_session(sess_id)
        assert sess is not None
        assert sess.v1_max_seq == 2  # Migration backfilled cutoff!

        # 3. Old v1 events must pass verification
        res = store.verify_chain(sess_id)
        assert res.valid is True
        assert res.total_events == 2

        # 4. Appending a new event should create a canonical v2 event and verify cleanly
        new_ev = store.insert_event(Event(
            session_id=sess_id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "deploy"},
        ))
        assert new_ev.hash_version == 2
        res2 = store.verify_chain(sess_id)
        assert res2.valid is True
        assert res2.total_events == 3

    def test_checkpoint_detects_tail_truncation(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """External checkpoint tip detects middle and tail deletions."""
        store.create_session(sample_session)
        for i in range(5):
            store.insert_event(Event(
                session_id=sample_session.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"step": i},
            ))

        assert store.verify_chain(sample_session.id).valid is True

        # Write external checkpoint tip
        cp_file = store.checkpoint_chain_tip(sample_session.id)
        assert cp_file.exists()

        # Attacker deletes the last 2 events directly in SQLite (tail truncation)
        with sqlite3.connect(str(store.db_path)) as conn:
            conn.execute("DELETE FROM events WHERE seq >= 4")
            conn.commit()

        # Without checkpoint, plain verify on prefix would pass!
        prefix_res = store.verify_chain(sample_session.id, checkpoint_path=Path("nonexistent.tip"))
        assert prefix_res.valid is True

        # With external checkpoint tip, tail truncation is immediately detected
        res = store.verify_chain(sample_session.id, checkpoint_path=cp_file)
        assert res.valid is False
        assert "Tail truncation detected" in (res.reason or "")
        assert "5 events" in (res.reason or "")

    def test_tampered_checkpoint_signature_fails_verification(
        self, tmp_path: Path
    ) -> None:
        """Checkpoint signature tampering must be caught during verification."""
        import os
        db_path = tmp_path / "sig_test.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        key = b"checkpoint-signing-key-12345"
        os.environ["ABB_HMAC_KEY"] = key.decode("utf-8")
        try:
            store.create_session(sess)
            store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"cmd": "ls"},
            ))
            cp_file = store.checkpoint_chain_tip(sess.id, hmac_key=key)
            assert cp_file.exists()

            # Clean verification with genuine checkpoint
            res = store.verify_chain(sess.id, hmac_key=key, checkpoint_path=cp_file)
            assert res.valid is True
            assert "signed" in (res.notes or "").lower()

            # Attacker alters the signature in the checkpoint file
            cp_data = json.loads(cp_file.read_text(encoding="utf-8"))
            cp_data["signature"] = "deadbeef" * 8
            cp_file.write_text(json.dumps(cp_data), encoding="utf-8")

            # Verification must fail on tampered checkpoint signature
            bad_res = store.verify_chain(sess.id, hmac_key=key, checkpoint_path=cp_file)
            assert bad_res.valid is False
            assert "checkpoint signature tampering" in (bad_res.reason or "").lower()
        finally:
            os.environ.pop("ABB_HMAC_KEY", None)

    def test_missing_checkpoint_reports_truncation_not_checked(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """When no checkpoint exists, verify_chain notes that truncation check was not performed."""
        store.create_session(sample_session)
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "whoami"},
        ))
        res = store.verify_chain(sample_session.id, checkpoint_path=Path("nonexistent/checkpoint.tip"))
        assert res.valid is True
        assert res.notes == "truncation check not performed, no checkpoint"

    def test_require_keyed_policy_enforcement(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """require_keyed=True must enforce HMAC key requirement."""
        store.create_session(sample_session)
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "date"},
        ))
        # Plain verify passes
        assert store.verify_chain(sample_session.id).valid is True

        # Policy require_keyed fails without key
        res = store.verify_chain(sample_session.id, require_keyed=True)
        assert res.valid is False
        assert "Verification policy failure" in (res.reason or "")

    def test_auto_checkpoint_on_stop_session(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """Calling stop_session must automatically generate a checkpoint tip file."""
        store.create_session(sample_session)
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "exit"},
        ))
        store.stop_session(sample_session.id)
        cp_file = store.db_path.parent / "checkpoints" / f"{sample_session.id}.tip"
        assert cp_file.exists()
        cp = json.loads(cp_file.read_text(encoding="utf-8"))
        assert cp["session_id"] == sample_session.id
        assert cp["last_seq"] == 1

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

    def test_key_configured_unkeyed_session_fails_by_default(
        self, tmp_path: Path
    ) -> None:
        """When an HMAC key is configured, verify_chain must enforce keyed hashes across all v2 rows by default."""
        db_path = tmp_path / "keyed_enforce.db"
        store = EventStore(db_path)
        sess = Session(workspace_path=str(tmp_path))
        store.create_session(sess)
        # Insert without key
        store.insert_event(Event(
            session_id=sess.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "pwd"},
        ))
        # Plain verify passes
        assert store.verify_chain(sess.id).valid is True

        # Now configure key in environment or argument
        key = b"verifier-secret-key-12345"
        res = store.verify_chain(sess.id, hmac_key=key)
        assert res.valid is False
        assert "HMAC verification key is configured" in (res.reason or "") or "event_hash mismatch" in (res.reason or "")

    def test_meta_mac_null_with_key_configured_fails(
        self, tmp_path: Path
    ) -> None:
        """When HMAC key is configured, a NULL/missing meta_mac in SQLite must fail verification immediately."""
        import os
        db_path = tmp_path / "meta_mac_null.db"
        key = b"session-meta-mac-secret-key"
        os.environ["ABB_HMAC_KEY"] = key.decode("utf-8")
        try:
            store = EventStore(db_path)
            sess = Session(workspace_path=str(tmp_path))
            store.create_session(sess)
            store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"cmd": "ls"},
            ))
            assert store.verify_chain(sess.id).valid is True

            # Attacker wipes meta_mac to NULL in SQLite
            with sqlite3.connect(str(db_path)) as conn:
                conn.execute("UPDATE sessions SET meta_mac = NULL WHERE id = ?", (sess.id,))
                conn.commit()

            res = store.verify_chain(sess.id)
            assert res.valid is False
            assert "missing meta_mac" in (res.reason or "").lower()
        finally:
            os.environ.pop("ABB_HMAC_KEY", None)

    def test_event_mac_not_valid_as_checkpoint_mac(
        self, tmp_path: Path
    ) -> None:
        """Subkeys must domain-separate event hashes from checkpoint signatures."""
        import hashlib
        import hmac
        from agentblackbox.storage.models import _derive_hmac_subkey
        master_key = b"master-key-32-bytes-long-secret"
        event_key = _derive_hmac_subkey(master_key, b"abb-event-mac-v1")
        cp_key = _derive_hmac_subkey(master_key, b"abb-checkpoint-mac-v1")
        meta_key = _derive_hmac_subkey(master_key, b"abb-session-meta-mac-v1")

        # Distinct keys
        assert event_key != cp_key
        assert cp_key != meta_key
        assert event_key != meta_key

        payload = b"canonical-test-payload-data"
        event_mac = hmac.new(event_key, payload, hashlib.sha256).hexdigest()
        cp_mac = hmac.new(cp_key, payload, hashlib.sha256).hexdigest()
        assert event_mac != cp_mac

    def test_checkpoint_written_every_n_events(
        self, tmp_path: Path
    ) -> None:
        """EventStore automatically writes checkpoint every checkpoint_interval events."""
        db_path = tmp_path / "periodic_cp.db"
        # Set small checkpoint interval = 5
        store = EventStore(db_path, checkpoint_interval=5)
        sess = Session(workspace_path=str(tmp_path))
        store.create_session(sess)
        cp_file = store.db_path.parent / "checkpoints" / f"{sess.id}.tip"

        for i in range(4):
            store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"step": i},
            ))
        # After 4 events, no checkpoint yet
        assert not cp_file.exists()

        # 5th event triggers checkpoint!
        store.insert_event(Event(
            session_id=sess.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"step": 4},
        ))
        assert cp_file.exists()
        data = json.loads(cp_file.read_text(encoding="utf-8"))
        assert data["last_seq"] == 5

    def test_require_checkpoint_fails_when_missing(
        self, store: EventStore, sample_session: Session
    ) -> None:
        """require_checkpoint=True must fail if checkpoint file does not exist."""
        store.create_session(sample_session)
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"cmd": "whoami"},
        ))
        res = store.verify_chain(
            sample_session.id,
            checkpoint_path=Path("nonexistent/checkpoint.tip"),
            require_checkpoint=True,
        )
        assert res.valid is False
        assert "checkpoint required" in (res.reason or "").lower()

    def test_truncation_after_kill_detected_up_to_last_checkpoint(
        self, tmp_path: Path
    ) -> None:
        """When an agent process is killed, periodic checkpoint preserves evidence of events prior to crash."""
        db_path = tmp_path / "kill_trunc.db"
        store = EventStore(db_path, checkpoint_interval=5)
        sess = Session(workspace_path=str(tmp_path))
        store.create_session(sess)

        for i in range(6):
            store.insert_event(Event(
                session_id=sess.id,
                event_type=EventType.CMD_EXECUTE,
                payload={"step": i},
            ))

        # Checkpoint recorded seq=5
        cp_file = store.db_path.parent / "checkpoints" / f"{sess.id}.tip"
        assert cp_file.exists()

        # Attacker truncates DB to seq=3 (as if process was killed earlier)
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM events WHERE seq > 3")
            conn.commit()

        # Verification with checkpoint catches that events up to 5 existed
        res = store.verify_chain(sess.id, checkpoint_path=cp_file)
        assert res.valid is False
        assert "Tail truncation detected" in (res.reason or "")
        assert "5 events" in (res.reason or "")




