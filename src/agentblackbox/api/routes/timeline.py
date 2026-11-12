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

