"""Tests for content-addressed BlobStore and watcher integration."""

import time
from pathlib import Path
from typing import List

from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity
from agentblackbox.watchers.filesystem import FileSystemWatcher


class TestBlobStore:
    """Test deduplicated, redacted content-addressed blob storage."""

    def test_put_and_get_deduplicated(self, tmp_path: Path) -> None:
        blobs = BlobStore(tmp_path / "blobs")
        h1, sz1, m1 = blobs.put_bytes(b"print('hello')\n")
        h2, sz2, m2 = blobs.put_bytes(b"print('hello')\n")
        assert h1 == h2
        assert len(h1) == 64
        assert sz1 == sz2 == 15
        assert m1 == [] and m2 == []
        assert blobs.exists(h1)
        assert blobs.get_text(h1) == "print('hello')\n"

    def test_redacts_secrets_before_writing_disk(self, tmp_path: Path) -> None:
        blobs = BlobStore(tmp_path / "blobs")
        raw_secret = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
        blob_hash, _, matches = blobs.put_bytes(
            f'OPENAI_API_KEY="{raw_secret}"\n'.encode("utf-8"),
            redact=True,
        )
        assert len(matches) == 1
        on_disk = (tmp_path / "blobs" / blob_hash).read_text(encoding="utf-8")
        assert raw_secret not in on_disk
        assert "[REDACTED:openai_api_key]" in on_disk

    def test_rejects_invalid_hash_or_traversal(self, tmp_path: Path) -> None:
        blobs = BlobStore(tmp_path / "blobs")
        assert not blobs.exists("../blackbox.db")
        assert blobs.get_bytes("../../etc/passwd") is None
        assert blobs.get_text("not-a-sha256") is None


class TestWatcherBlobIntegration:
    """Verify FileSystemWatcher stores redacted blobs and snapshots."""

    def test_watcher_saves_redacted_blob_and_snapshot(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        ws.mkdir()
        store = EventStore(tmp_path / "blackbox.db")
        blobs = BlobStore(tmp_path / "blobs")
        session = Session(workspace_path=str(ws), agent_hint="claude-code")
        store.create_session(session)

        events: List[Event] = []
        watcher = FileSystemWatcher(
            session_id=session.id,
            on_event=lambda e: events.append(store.insert_event(e)),
            watch_path=ws,
            ignore_patterns=[".agentblackbox"],
            debounce_seconds=0.1,
            blob_store=blobs,
            agent_id="claude-code",
            use_polling=True,
        )
        raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
        watcher.start()
        try:
            time.sleep(0.3)
            (ws / "config.py").write_text(f'AWS_KEY = "{raw_key}"\n', encoding="utf-8")
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline and not any(
                e.event_type in (EventType.FILE_CREATE, EventType.FILE_MODIFY) and e.blob_hash for e in events
            ):
                time.sleep(0.05)
        finally:
            watcher.stop()

        created = [e for e in events if e.event_type in (EventType.FILE_CREATE, EventType.FILE_MODIFY) and e.blob_hash]
        assert len(created) >= 1
        ev = created[0]
        assert ev.agent_id == "claude-code"
        assert ev.severity == Severity.CRITICAL
        assert "secret_redacted" in ev.tags
        blob_text = blobs.get_text(ev.blob_hash)
        assert blob_text is not None
        assert raw_key not in blob_text
        assert "[REDACTED:aws_access_key]" in blob_text
        snaps = store.get_file_snapshots(ev.source_path or "", session_id=session.id)
        assert len(snaps) >= 1
        assert snaps[0].blob_hash == ev.blob_hash

    def test_verify_chain_fails_if_blob_missing(self, tmp_path: Path) -> None:
        db_path = tmp_path / "bb.db"
        blobs_dir = tmp_path / "blobs"
        store = EventStore(db_path, blobs_dir=blobs_dir)
        session = Session(workspace_path=str(tmp_path))
        store.create_session(session)

        fake_hash = "a" * 64
        store.insert_event(Event(
            session_id=session.id,
            event_type=EventType.FILE_CREATE,
            source_path="foo.py",
            blob_hash=fake_hash,
        ))

        res = store.verify_chain(session.id)
        assert res.valid is False
        assert "Blob file missing on disk" in (res.reason or "")

    def test_verify_chain_fails_if_blob_content_tampered(self, tmp_path: Path) -> None:
        db_path = tmp_path / "bb2.db"
        blobs_dir = tmp_path / "blobs2"
        store = EventStore(db_path, blobs_dir=blobs_dir)
        session = Session(workspace_path=str(tmp_path))
        store.create_session(session)

        blob_hash, _, _ = store.blob_store.put_bytes(b"original content")
        store.insert_event(Event(
            session_id=session.id,
            event_type=EventType.FILE_CREATE,
            source_path="foo.py",
            blob_hash=blob_hash,
        ))

        assert store.verify_chain(session.id).valid is True

        # Malicious actor tampers with the blob file directly on disk
        blob_file = blobs_dir / blob_hash
        blob_file.write_bytes(b"tampered content")

        res = store.verify_chain(session.id)
        assert res.valid is False
        assert "Blob content mismatch" in (res.reason or "")

