"""Tests for API bearer token authentication and hash-chain verification route."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentblackbox.api.main import app
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session


@pytest.fixture
def authed_store(tmp_path: Path, monkeypatch):
    """Set up an isolated EventStore and enforce ABB_API_TOKEN for tests."""
    config = BlackBoxConfig(workspace_path=tmp_path)
    store = EventStore(config.db_path)

    def mock_get_store():
        return store

    import agentblackbox.api.routes.sessions as sess_mod
    import agentblackbox.api.routes.events as evt_mod
    import agentblackbox.api.routes.timeline as tl_mod
    monkeypatch.setattr(sess_mod, "_get_store", mock_get_store)
    monkeypatch.setattr(evt_mod, "_get_store", mock_get_store)
    monkeypatch.setattr(tl_mod, "_get_store", mock_get_store)
    monkeypatch.setenv("ABB_API_TOKEN", "test-secret-token-123")
    return store


class TestApiAuthAndVerify:
    """Test bearer token protection on REST + WebSocket and verify endpoint."""

    def test_rejects_missing_or_wrong_token(self, authed_store) -> None:
        client = TestClient(app)
        assert client.get("/api/v1/sessions").status_code == 401
        assert client.get(
            "/api/v1/sessions",
            headers={"Authorization": "Bearer wrong-token"},
        ).status_code == 401

    def test_accepts_valid_token_and_verifies_chain(self, authed_store, tmp_path: Path) -> None:
        client = TestClient(app)
        headers = {"Authorization": "Bearer test-secret-token-123"}

        sess = Session(workspace_path=str(tmp_path), name="auth-test")
        authed_store.create_session(sess)
        ev = authed_store.insert_event(Event(
            session_id=sess.id,
            event_type=EventType.FILE_CREATE,
            source_path="main.py",
        ))

        resp = client.get(f"/api/v1/sessions/{sess.id}/verify", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["total_events"] == 1

        # Tamper in SQLite and re-verify
        with sqlite3.connect(str(authed_store.db_path)) as conn:
            conn.execute("UPDATE events SET source_path = 'hacked.py' WHERE id = ?", (ev.id,))
            conn.commit()

        resp2 = client.get(f"/api/v1/sessions/{sess.id}/verify", headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["valid"] is False

    def test_websocket_requires_token(self, authed_store) -> None:
        client = TestClient(app)
        with client.websocket_connect("/ws/live?token=test-secret-token-123") as ws:
            ws.send_text("ping")
            assert ws.receive_json() == {"type": "pong"}
