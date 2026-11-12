# PHASE 4: FastAPI + WebSocket + README
# =======================================
# Prerequisites: Phase 3 complete, 52 tests passing.
# After this phase: Full REST API, WebSocket live feed, README.
# New tests: 12 (total: 64)
#
# READ AGENTS.md FIRST.

## STEP 1: Create src/agentblackbox/api/main.py

```python
"""FastAPI application for the AgentBlackBox dashboard API."""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import json

from agentblackbox import __version__

app = FastAPI(
    title="AgentBlackBox API",
    description="The flight recorder for autonomous AI agents.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import routes
from agentblackbox.api.routes import sessions, events, timeline  # noqa: E402
app.include_router(sessions.router, prefix="/api/v1", tags=["sessions"])
app.include_router(events.router, prefix="/api/v1", tags=["events"])
app.include_router(timeline.router, prefix="/api/v1", tags=["timeline"])


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    """Health check and welcome page."""
    return f"""
    <html>
    <head><title>AgentBlackBox</title></head>
    <body style="background:#0a0a0a;color:#e5e5e5;font-family:monospace;padding:2rem">
    <h1 style="color:#f97316">🔴 AgentBlackBox v{__version__}</h1>
    <p>The flight recorder for autonomous AI agents.</p>
    <p>API docs: <a href="/docs" style="color:#3b82f6">/docs</a></p>
    </body>
    </html>
    """


# WebSocket manager for live event feeds
class ConnectionManager:
    """Manages WebSocket connections for live event streaming."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


ws_manager = ConnectionManager()


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Client can send ping/pong or filter requests
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
```

## STEP 2: Create src/agentblackbox/api/routes/sessions.py

```python
"""Session management API routes."""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Session

router = APIRouter()


def _get_store() -> EventStore:
    config = BlackBoxConfig()
    return EventStore(config.db_path)


class SessionResponse(BaseModel):
    id: str
    name: Optional[str]
    workspace_path: str
    agent_hint: Optional[str]
    started_at: str
    ended_at: Optional[str]
    status: str
    total_events: int
    risk_score: float


class CreateSessionRequest(BaseModel):
    name: Optional[str] = None
    agent_hint: Optional[str] = None
    workspace_path: Optional[str] = None


def _session_to_response(s: Session) -> SessionResponse:
    return SessionResponse(
        id=s.id, name=s.name, workspace_path=s.workspace_path,
        agent_hint=s.agent_hint, started_at=s.started_at,
        ended_at=s.ended_at, status=s.status,
        total_events=s.total_events, risk_score=s.risk_score,
    )


@router.get("/sessions")
async def list_sessions(limit: int = Query(default=20, le=100)) -> list[SessionResponse]:
    """List all recording sessions."""
    store = _get_store()
    sessions = store.list_sessions(limit=limit)
    return [_session_to_response(s) for s in sessions]


@router.get("/sessions/{session_id}")
async def get_session(session_id: str) -> SessionResponse:
    """Get a single session by ID."""
    store = _get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return _session_to_response(session)


@router.post("/sessions", status_code=201)
async def create_session(req: CreateSessionRequest) -> SessionResponse:
    """Start a new recording session."""
    store = _get_store()
    session = Session(
        workspace_path=req.workspace_path or str(Path.cwd()),
        name=req.name,
        agent_hint=req.agent_hint,
    )
    store.create_session(session)
    return _session_to_response(session)


@router.patch("/sessions/{session_id}")
async def stop_session(session_id: str) -> SessionResponse:
    """Stop a recording session."""
    store = _get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    store.stop_session(session_id)
    updated = store.get_session(session_id)
    return _session_to_response(updated)
```

## STEP 3: Create src/agentblackbox/api/routes/events.py

```python
"""Event query and search API routes."""

from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore

router = APIRouter()


def _get_store() -> EventStore:
    config = BlackBoxConfig()
    return EventStore(config.db_path)


class EventResponse(BaseModel):
    id: Optional[int]
    session_id: str
    timestamp: str
    event_type: str
    severity: str
    risk_score: float
    source_path: Optional[str]
    payload: dict
    tags: list[str]


@router.get("/events")
async def list_events(
    session_id: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    source_path: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
) -> list[EventResponse]:
    """Query events with optional filters."""
    store = _get_store()
    events = store.query_events(
        session_id=session_id, event_type=event_type,
        severity=severity, source_path=source_path,
        limit=limit, offset=offset,
    )
    return [
        EventResponse(
            id=e.id, session_id=e.session_id, timestamp=e.timestamp,
            event_type=e.event_type, severity=e.severity,
            risk_score=e.risk_score, source_path=e.source_path,
            payload=e.payload, tags=e.tags,
        )
        for e in events
    ]


@router.get("/search")
async def search_events(
    q: str = Query(..., min_length=1),
    session_id: Optional[str] = Query(default=None),
) -> list[EventResponse]:
    """Full-text search across events."""
    store = _get_store()
    events = store.search_events(q, session_id=session_id)
    return [
        EventResponse(
            id=e.id, session_id=e.session_id, timestamp=e.timestamp,
            event_type=e.event_type, severity=e.severity,
            risk_score=e.risk_score, source_path=e.source_path,
            payload=e.payload, tags=e.tags,
        )
        for e in events
    ]


@router.get("/blame")
async def blame_file_endpoint(
    file: str = Query(...),
    session_id: Optional[str] = Query(default=None),
) -> list[dict]:
    """Blame analysis for a file."""
    from agentblackbox.replay.blame import blame_file
    store = _get_store()
    entries = blame_file(store, file, session_id=session_id)
    return [
        {
            "file_path": e.file_path,
            "action": e.action,
            "session_id": e.session_id,
            "timestamp": e.event.timestamp,
            "risk_score": e.event.risk_score,
        }
        for e in entries
    ]
```

## STEP 4: Create src/agentblackbox/api/routes/timeline.py

```python
"""Timeline and replay API routes."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.replay.timeline import build_timeline
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.export import export_json, export_csv, export_html

router = APIRouter()


def _get_store() -> EventStore:
    config = BlackBoxConfig()
    return EventStore(config.db_path)


class TimelineEntryResponse(BaseModel):
    relative_ms: int
    label: str
    event_type: str
    severity: str
    risk_score: float
    source_path: Optional[str]
    timestamp: str


class TimelineResponse(BaseModel):
    session_id: str
    entries: list[TimelineEntryResponse]
    duration_ms: int
    stats: dict


@router.get("/timeline/{session_id}")
async def get_timeline(
    session_id: str,
    event_type: Optional[str] = Query(default=None),
    min_severity: Optional[str] = Query(default=None),
) -> TimelineResponse:
    """Get the full timeline for a session."""
    store = _get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    timeline = build_timeline(store, session_id, event_type=event_type, min_severity=min_severity)

    return TimelineResponse(
        session_id=timeline.session_id,
        entries=[
            TimelineEntryResponse(
                relative_ms=e.relative_ms,
                label=e.label,
                event_type=e.event.event_type,
                severity=e.event.severity,
                risk_score=e.event.risk_score,
                source_path=e.event.source_path,
                timestamp=e.event.timestamp,
            )
            for e in timeline.entries
        ],
        duration_ms=timeline.duration_ms,
        stats=timeline.stats,
    )


@router.get("/export/{session_id}")
async def export_session(
    session_id: str,
    format: str = Query(default="json"),
) -> dict:
    """Export session data in various formats."""
    store = _get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    if format == "json":
        import json
        return json.loads(export_json(store, session_id))
    elif format == "csv":
        return {"data": export_csv(store, session_id), "content_type": "text/csv"}
    elif format == "html":
        return {"data": export_html(store, session_id), "content_type": "text/html"}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format}")
```

## STEP 5: Create tests/test_api/test_routes.py

```python
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
```

Create test_api __init__.py:
```python
# tests/test_api/__init__.py
```

## STEP 6: Create README.md

```markdown
# 🔴 AgentBlackBox

**The flight recorder for autonomous AI agents.**

> Every autonomous system needs a black box.

---

## Problem

AI coding agents (Claude Code, Cursor, Codex, Cline) now have full terminal and filesystem access on developer machines. When something goes wrong — files deleted, secrets leaked, code broken — there's **zero forensic trail**. No way to see what the agent did, when, or why.

AgentBlackBox records everything an AI agent does and lets you replay, search, and investigate.

## Features

- 📁 **File Watcher** — Tracks every file create, modify, delete, rename
- 💻 **Terminal Logger** — Records shell commands and their output
- 🌿 **Git Observer** — Captures git add, commit, push, force-push, reset
- 🔐 **Secret Detector** — Auto-detects API keys, tokens, passwords (15+ patterns)
- ⚠️ **Risk Scoring** — Every event scored 0-10 with severity classification
- 🔍 **Search** — Full-text search across all events
- 📋 **Blame** — "Which event changed this file?"
- ⏮️ **Timeline Replay** — Reconstruct exactly what happened
- 🚨 **Alerts** — Auto-flag destructive commands and secret leaks
- 📊 **Dashboard** — Web UI with live event feed (localhost:7700)
- 📄 **Export** — JSON, CSV, HTML reports

## Install

```bash
pip install agentblackbox
```

## Quick Start

```bash
# Start recording
abb start --name "refactor-auth"

# ... run your AI agent ...

# Stop recording
abb stop

# See what happened
abb sessions
abb search "rm -rf"
abb blame src/auth.py
abb report sess-abc123def --format html
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `abb start` | Start recording |
| `abb stop` | Stop recording |
| `abb sessions` | List all sessions |
| `abb search <query>` | Search events |
| `abb blame <file>` | File change history |
| `abb alerts` | Show security alerts |
| `abb report <session_id>` | Export report |
| `abb version` | Show version |

## API

Start the dashboard:
```bash
uvicorn agentblackbox.api.main:app --port 7700
```

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/sessions` | List sessions |
| `POST /api/v1/sessions` | Start session |
| `GET /api/v1/events` | Query events |
| `GET /api/v1/search?q=...` | Search |
| `GET /api/v1/timeline/:id` | Session timeline |
| `GET /api/v1/blame?file=...` | File blame |
| `GET /api/v1/export/:id` | Export data |
| `WS /ws/live` | Live event stream |

## Part of the AI Agent Safety Suite

| Tool | Purpose |
|------|---------|
| [AgentShield](https://github.com/ATP0925/AgentShield) | **Prevents** disasters (pre-commit gate) |
| **AgentBlackBox** | **Investigates** what happened (flight recorder) |

> *AgentShield is the seatbelt. AgentBlackBox is the black box.*

## Tech Stack

- Python 3.11+
- FastAPI (API + WebSocket)
- SQLite (WAL mode)
- watchdog (filesystem monitoring)
- typer + rich (CLI)
- pytest (64+ tests)

## License

MIT

---

Built by [Pratik Atpadkar](https://linkedin.com/in/pratik-atpadkar)
```

## STEP 7: Run ALL tests

```bash
cd AgentBlackBox
python -m pytest tests/ -v --tb=short
```

### Expected: 64 total tests passing

```
tests/test_storage/test_event_store.py    — 12 passed
tests/test_watchers/test_filesystem.py    — 10 passed
tests/test_analysis/test_secret_detector.py — 10 passed
tests/test_analysis/test_risk_scorer.py   — 8 passed
tests/test_replay/test_timeline.py        — 8 passed
tests/test_replay/test_blame.py           — 5 passed
tests/test_api/test_routes.py             — 12 passed (needs httpx)
                                            ─────────
                                     TOTAL: 65 passed
```

## ✅ PHASE 4 COMPLETE CHECKLIST
- [ ] api/main.py — FastAPI app + WebSocket manager
- [ ] api/routes/sessions.py — Session CRUD endpoints
- [ ] api/routes/events.py — Event query + search + blame endpoints
- [ ] api/routes/timeline.py — Timeline + export endpoints
- [ ] test_routes.py — 12 API tests
- [ ] README.md — complete documentation
- [ ] ALL 64+ tests PASS
- [ ] `abb version` works
- [ ] `uvicorn agentblackbox.api.main:app` starts on port 7700

## 🏁 PROJECT COMPLETE

Run final verification:
```bash
# Tests
python -m pytest tests/ -v

# CLI
abb version
abb start --name "test"
abb sessions
abb stop

# API
uvicorn agentblackbox.api.main:app --port 7700
# Open http://localhost:7700/docs
```

