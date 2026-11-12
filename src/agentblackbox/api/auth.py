"""Bearer token authentication helpers for the local AgentBlackBox API."""

import hmac
import os
from typing import Optional

from fastapi import HTTPException, Request, WebSocket, status


def resolve_expected_token(app_token: Optional[str] = None) -> Optional[str]:
    """Return configured API token from app state or ABB_API_TOKEN env var.

    Args:
        app_token: Optional token stored on ``app.state.api_token``.

    Returns:
        Token string if configured, None otherwise.
    """
    if app_token:
        return app_token
    env_token = os.environ.get("ABB_API_TOKEN")
    return env_token if env_token else None


async def require_api_token(request: Request) -> None:
    """FastAPI dependency enforcing Bearer token auth when a token is configured.

    Args:
        request: Incoming HTTP request.

    Raises:
        HTTPException: 401 if a token is configured and the request header is
            missing, malformed, or does not match.
    """
    expected = resolve_expected_token(getattr(request.app.state, "api_token", None))
    if not expected:
        return

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided = auth_header[len("Bearer "):].strip()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def verify_ws_token(websocket: WebSocket) -> bool:
    """Verify Bearer header or ``?token=`` query param for WebSocket clients.

    Args:
        websocket: Incoming WebSocket connection.

    Returns:
        True if unauthenticated mode is active or token matches; False otherwise.
    """
    expected = resolve_expected_token(getattr(websocket.app.state, "api_token", None))
    if not expected:
        return True

    auth_header = websocket.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        provided = auth_header[len("Bearer "):].strip()
        return hmac.compare_digest(provided, expected)

    query_token = websocket.query_params.get("token", "")
    if query_token:
        return hmac.compare_digest(query_token, expected)

    return False
