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

