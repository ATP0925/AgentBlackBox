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

