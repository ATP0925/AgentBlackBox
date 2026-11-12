"""FastAPI application for the AgentBlackBox dashboard API."""

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from agentblackbox import __version__
from agentblackbox.api.auth import require_api_token, verify_ws_token

app = FastAPI(
    title="AgentBlackBox API",
    description="The flight recorder for autonomous AI agents.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

# Import routes with optional bearer-token protection
from agentblackbox.api.routes import sessions, events, timeline  # noqa: E402

_auth_deps = [Depends(require_api_token)]
app.include_router(sessions.router, prefix="/api/v1", tags=["sessions"], dependencies=_auth_deps)
app.include_router(events.router, prefix="/api/v1", tags=["events"], dependencies=_auth_deps)
app.include_router(timeline.router, prefix="/api/v1", tags=["timeline"], dependencies=_auth_deps)


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


class ConnectionManager:
    """Manages WebSocket connections for live event streaming."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and track an authenticated WebSocket client."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """Broadcast JSON message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


ws_manager = ConnectionManager()


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming."""
    if not verify_ws_token(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
