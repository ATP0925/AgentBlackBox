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

