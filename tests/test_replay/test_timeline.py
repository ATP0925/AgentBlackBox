"""Tests for timeline builder."""

import pytest
from agentblackbox.replay.timeline import build_timeline, _event_label, _parse_iso_ms
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity


class TestParseIsoMs:
    """Test ISO timestamp parsing."""

    def test_parse_utc(self) -> None:
        ms = _parse_iso_ms("2026-11-12T15:00:00+00:00")
        assert ms > 0

    def test_parse_empty(self) -> None:
        assert _parse_iso_ms("") == 0

    def test_parse_invalid(self) -> None:
        assert _parse_iso_ms("not-a-date") == 0


class TestEventLabel:
    """Test human-readable event labels."""

    def test_file_create_label(self) -> None:
        e = Event(session_id="s", event_type=EventType.FILE_CREATE, source_path="src/main.py")
        label = _event_label(e)
        assert "Created" in label
        assert "main.py" in label

    def test_cmd_execute_label(self) -> None:
        e = Event(session_id="s", event_type=EventType.CMD_EXECUTE, payload={"command": "npm install"})
        label = _event_label(e)
        assert "npm install" in label

    def test_secret_label(self) -> None:
        e = Event(session_id="s", event_type=EventType.SECRET_DETECTED,
                  payload={"secret_type": "aws_access_key"}, source_path=".env")
        label = _event_label(e)
        assert "SECRET" in label


class TestBuildTimeline:
    """Test timeline construction from stored events."""

    def test_empty_timeline(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        timeline = build_timeline(store, sample_session.id)
        assert len(timeline.entries) == 0

    def test_timeline_order(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        for i in range(5):
            store.insert_event(Event(
                session_id=sample_session.id,
                event_type=EventType.FILE_MODIFY,
                source_path=f"file{i}.py",
            ))
        timeline = build_timeline(store, sample_session.id)
        assert len(timeline.entries) == 5
        assert timeline.stats.get("total") == 5

    def test_timeline_stats(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_DELETE))
        timeline = build_timeline(store, sample_session.id)
        assert timeline.stats.get("file_create") == 2
        assert timeline.stats.get("file_delete") == 1

    def test_timeline_filter_by_type(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.CMD_EXECUTE, payload={"command": "ls"}))
        timeline = build_timeline(store, sample_session.id, event_type=EventType.FILE_CREATE)
        assert len(timeline.entries) == 1
        assert timeline.entries[0].event.event_type == EventType.FILE_CREATE

