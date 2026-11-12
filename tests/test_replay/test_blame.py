"""Tests for blame analysis."""

import pytest
from agentblackbox.replay.blame import blame_file, last_modifier
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session


class TestBlame:
    """Test file blame functionality."""

    def test_blame_single_event(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(
            session_id=sample_session.id,
            event_type=EventType.FILE_CREATE,
            source_path="src/auth.py",
        ))
        entries = blame_file(store, "src/auth.py")
        assert len(entries) == 1
        assert entries[0].action == "created"

    def test_blame_multiple_events(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path="src/auth.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="src/auth.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="src/auth.py"))
        entries = blame_file(store, "src/auth.py")
        assert len(entries) == 3
        # Most recent first
        assert entries[0].action == "modified"

    def test_blame_no_events(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        entries = blame_file(store, "nonexistent.py")
        assert len(entries) == 0

    def test_last_modifier(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_CREATE, source_path="x.py"))
        store.insert_event(Event(session_id=sample_session.id, event_type=EventType.FILE_MODIFY, source_path="x.py"))
        result = last_modifier(store, "x.py")
        assert result is not None
        assert result.action == "modified"

    def test_last_modifier_none(self, store: EventStore, sample_session: Session) -> None:
        store.create_session(sample_session)
        assert last_modifier(store, "nope.py") is None

