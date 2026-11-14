"""IDE Bridge API routes and real-time WebSocket event broadcaster."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from agentblackbox import __version__
from agentblackbox.analysis.compliance_tracker import ComplianceTracker
from agentblackbox.analysis.drift_detector import ArchitecturalDriftDetector
from agentblackbox.analysis.refactor_guard import LegacyRefactorGuard
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.analysis.secret_detector import SecretDetector
from agentblackbox.api.auth import require_api_token, verify_ws_token
from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity

router = APIRouter()


class EditAnalysisRequest(BaseModel):
    file_path: str = Field(..., description="Target file path relative to workspace or absolute")
    content: str = Field(..., description="Full source content modified by the AI agent")
    agent_name: str = Field("antigravity", description="Attributed AI agent name")
    prompt_summary: str = Field("", description="Optional summary of agent prompt")


class RollbackRequest(BaseModel):
    file_path: str = Field(..., description="Target file path to restore")
    snapshot_sha256: str = Field(..., description="Content-addressed SHA-256 hash in BlobStore")
    session_id: Optional[str] = Field(None, description="Active session ID")


class BridgeConnectionManager:
    """Manages active IDE extension WebSocket subscribers."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = BridgeConnectionManager()


def get_event_store(request: Request) -> EventStore:
    store = getattr(request.app.state, "event_store", None)
    if not store:
        db_dir = Path.cwd() / ".agentblackbox"
        db_dir.mkdir(parents=True, exist_ok=True)
        store = EventStore(db_dir / "events.db")
        request.app.state.event_store = store
    return store


def get_blob_store(request: Request) -> BlobStore:
    blob_store = getattr(request.app.state, "blob_store", None)
    if not blob_store:
        blobs_dir = Path.cwd() / ".agentblackbox" / "blobs"
        blobs_dir.mkdir(parents=True, exist_ok=True)
        blob_store = BlobStore(blobs_dir)
        request.app.state.blob_store = blob_store
    return blob_store


@router.get("/status")
async def get_bridge_status(request: Request) -> Dict[str, Any]:
    """Retrieve active session status, chain integrity, and cumulative risk score."""
    store = get_event_store(request)
    sessions = store.list_sessions(limit=1)
    if not sessions:
        sess = store.create_session(Session(id="default_session", name="IDE Active Session", workspace_path=str(Path.cwd())))
        sessions = [sess]

    active_session_id = sessions[0].id
    total_events = sessions[0].total_events
    cum_risk = sessions[0].risk_score

    chain_ok = True
    if sessions:
        res = store.verify_chain(active_session_id, verify_blobs=False)
        chain_ok = res.valid

    return {
        "status": "ready",
        "session_id": active_session_id,
        "chain_intact": chain_ok,
        "cumulative_risk": cum_risk,
        "event_count": total_events,
        "version": __version__,
    }


@router.post("/analyze-edit")
async def analyze_edit(
    req: EditAnalysisRequest,
    request: Request,
) -> Dict[str, Any]:
    """Run real-time compliance, drift, secret, and risk analysis on an AI-edited file."""
    store = get_event_store(request)
    blob_store = get_blob_store(request)

    # 1. Compliance Tracker
    compliance_tracker = ComplianceTracker()
    compliance_findings = compliance_tracker.check_content(req.content, file_path=req.file_path)

    # 2. Architectural Drift Detector
    drift_detector = ArchitecturalDriftDetector(blob_store=blob_store)
    drift_violations = drift_detector.check_file(req.file_path, content=req.content)

    # 3. Secret Detector
    secret_detector = SecretDetector()
    secret_matches = secret_detector.scan_text(req.content)

    # 4. Refactor Guard Pre-Edit Snapshot & Blast Radius
    refactor_guard = LegacyRefactorGuard(blob_store=blob_store, event_store=store)
    snapshot_sha256, meta = refactor_guard.create_pre_refactor_snapshot(req.file_path, content=req.content)

    # 5. Determine active session (create if none exists to satisfy foreign key)
    sessions = store.list_sessions(limit=1)
    if sessions:
        session_id = sessions[0].id
    else:
        sess = store.create_session(Session(id="default_session", name="IDE Active Session", workspace_path=str(Path.cwd())))
        session_id = sess.id

    # 6. Construct Event
    event = Event(
        session_id=session_id,
        event_type=EventType.FILE_MODIFY,
        source_path=req.file_path.replace("\\", "/"),
        blob_hash=snapshot_sha256,
        agent_id=req.agent_name,
        payload={
            "action": "ai_agent_edit",
            "agent_name": req.agent_name,
            "prompt_summary": req.prompt_summary,
            "snapshot_sha256": snapshot_sha256,
            "compliance_findings": [f.to_dict() for f in compliance_findings],
            "drift_violations": [v.to_dict() for v in drift_violations],
            "secret_matches": [m.to_dict() for m in secret_matches],
            "blast_radius": meta.get("blast_radius", {}),
        },
    )

    # Score event
    score_event(event)

    # Elevate risk if high-severity compliance or drift detected
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.DANGER) for f in compliance_findings):
        event.risk_score = max(event.risk_score, 8.0)
        event.severity = Severity.HIGH
    if any(v.severity in (Severity.HIGH, Severity.DANGER) for v in drift_violations):
        event.risk_score = max(event.risk_score, 7.5)
        event.severity = Severity.HIGH

    # Record into tamper-evident store
    recorded = store.record_event(event)

    response_payload = {
        "file_path": req.file_path,
        "snapshot_sha256": snapshot_sha256,
        "risk_score": recorded.risk_score,
        "severity": recorded.severity,
        "compliance_findings": [f.to_dict() for f in compliance_findings],
        "drift_violations": [v.to_dict() for v in drift_violations],
        "secret_matches": [m.to_dict() for m in secret_matches],
        "blast_radius": meta.get("blast_radius", {}),
        "chain_hash": recorded.event_hash,
    }

    # Broadcast event to IDE extension via WebSocket
    asyncio.create_task(manager.broadcast({
        "type": "agent_edit_analyzed",
        "data": response_payload,
    }))

    return response_payload


@router.post("/rollback")
async def rollback_edit(
    req: RollbackRequest,
    request: Request,
) -> Dict[str, Any]:
    """Rollback a file to a content-addressed snapshot from BlobStore."""
    store = get_event_store(request)
    blob_store = get_blob_store(request)

    refactor_guard = LegacyRefactorGuard(blob_store=blob_store, event_store=store)
    success = refactor_guard.rollback_to_snapshot(
        file_path=req.file_path,
        snapshot_sha256=req.snapshot_sha256,
        session_id=req.session_id,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Snapshot '{req.snapshot_sha256}' not found in BlobStore.",
        )

    response = {
        "success": True,
        "file_path": req.file_path,
        "snapshot_sha256": req.snapshot_sha256,
        "message": f"Successfully restored '{req.file_path}' to snapshot {req.snapshot_sha256[:12]}",
    }

    asyncio.create_task(manager.broadcast({
        "type": "file_rollback_executed",
        "data": response,
    }))

    return response
