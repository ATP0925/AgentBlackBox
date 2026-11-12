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

