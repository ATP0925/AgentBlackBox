"""Tests for FastAPI routes."""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from agentblackbox.api.main import app
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Session, Event, EventType


@pytest.fixture
def api_store(tmp_path: Path, monkeypatch):
    """Set up a test store and patch the route's _get_store."""
    config = BlackBoxConfig(workspace_path=tmp_path)
    store = EventStore(config.db_path)
    
    # Patch all route modules to use our test store
    def mock_get_store():
        return store
    
    import agentblackbox.api.routes.sessions as sess_mod
    import agentblackbox.api.routes.events as evt_mod
    import agentblackbox.api.routes.timeline as tl_mod
    monkeypatch.setattr(sess_mod, "_get_store", mock_get_store)
    monkeypatch.setattr(evt_mod, "_get_store", mock_get_store)
    monkeypatch.setattr(tl_mod, "_get_store", mock_get_store)
    
    return store


@pytest.fixture
def client():
    return TestClient(app)


class TestSessionRoutes:
    
    def test_list_sessions_empty(self, client, api_store):
        response = client.get("/api/v1/sessions")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_session(self, client, api_store, tmp_path):
        response = client.post("/api/v1/sessions", json={
            "name": "test-session",
            "workspace_path": str(tmp_path),
        })
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-session"
        assert data["status"] == "recording"

    def test_get_session(self, client, api_store, tmp_path):
        # Create first
        create_resp = client.post("/api/v1/sessions", json={"workspace_path": str(tmp_path)})
        session_id = create_resp.json()["id"]
        # Get
        response = client.get(f"/api/v1/sessions/{session_id}")
        assert response.status_code == 200
        assert response.json()["id"] == session_id

    def test_get_nonexistent_session(self, client, api_store):
        response = client.get("/api/v1/sessions/fake-id")
        assert response.status_code == 404

    def test_stop_session(self, client, api_store, tmp_path):
        create_resp = client.post("/api/v1/sessions", json={"workspace_path": str(tmp_path)})
        session_id = create_resp.json()["id"]
        response = client.patch(f"/api/v1/sessions/{session_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "stopped"


class TestEventRoutes:

    def test_list_events_empty(self, client, api_store):
        response = client.get("/api/v1/events")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_events_with_data(self, client, api_store, tmp_path):
        # Create session and event directly in store
        session = Session(workspace_path=str(tmp_path))
        api_store.create_session(session)
        api_store.insert_event(Event(
            session_id=session.id,
            event_type=EventType.FILE_CREATE,
            source_path="test.py",
        ))
        response = client.get(f"/api/v1/events?session_id={session.id}")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["event_type"] == "file_create"

    def test_search_events(self, client, api_store, tmp_path):
        session = Session(workspace_path=str(tmp_path))
        api_store.create_session(session)
        api_store.insert_event(Event(
            session_id=session.id,
            event_type=EventType.CMD_EXECUTE,
            payload={"command": "rm -rf /danger"},
        ))
        response = client.get("/api/v1/search?q=rm+-rf")
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestTimelineRoutes:

    def test_get_timeline(self, client, api_store, tmp_path):
        session = Session(workspace_path=str(tmp_path))
        api_store.create_session(session)
        api_store.insert_event(Event(session_id=session.id, event_type=EventType.FILE_CREATE, source_path="a.py"))
        api_store.insert_event(Event(session_id=session.id, event_type=EventType.FILE_MODIFY, source_path="a.py"))
        response = client.get(f"/api/v1/timeline/{session.id}")
        assert response.status_code == 200
        data = response.json()
        assert len(data["entries"]) == 2
        assert data["stats"]["total"] == 2

    def test_timeline_nonexistent(self, client, api_store):
        response = client.get("/api/v1/timeline/fake-id")
        assert response.status_code == 404

    def test_export_json(self, client, api_store, tmp_path):
        session = Session(workspace_path=str(tmp_path))
        api_store.create_session(session)
        response = client.get(f"/api/v1/export/{session.id}?format=json")
        assert response.status_code == 200
        data = response.json()
        assert "session" in data
        assert data["session"]["id"] == session.id

