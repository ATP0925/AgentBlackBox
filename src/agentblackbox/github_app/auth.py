"""GitHub App Authentication & Installation Token Manager.

Handles RS256 App JWT signing and cached installation access token retrieval.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import httpx
import jwt
import structlog

logger = structlog.get_logger(__name__)


class GitHubAppAuth:
    """Manages GitHub App JWTs and cached installation tokens."""

    def __init__(
        self,
        app_id: Optional[str] = None,
        private_key: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        api_base_url: str = "https://api.github.com",
    ) -> None:
        self.app_id = app_id or os.environ.get("GITHUB_APP_ID", "")
        self.webhook_secret = webhook_secret or os.environ.get("GITHUB_WEBHOOK_SECRET", "")
        self.api_base_url = api_base_url.rstrip("/")

        raw_key = private_key or os.environ.get("GITHUB_PRIVATE_KEY", "")
        if not raw_key and os.environ.get("GITHUB_PRIVATE_KEY_PATH"):
            key_path = Path(os.environ["GITHUB_PRIVATE_KEY_PATH"])
            if key_path.is_file():
                raw_key = key_path.read_text(encoding="utf-8")

        self.private_key = raw_key.strip() if raw_key else ""
        # In-memory token cache: {installation_id: (access_token, expires_at_timestamp)}
        self._token_cache: Dict[int, Tuple[str, float]] = {}

    def is_configured(self) -> bool:
        """Check if minimum required credentials for GitHub App auth are present."""
        return bool(self.app_id and self.private_key)

    def create_app_jwt(self, expiration_seconds: int = 540) -> str:
        """Generate a signed RS256 JWT for authenticating as the GitHub App.

        Args:
            expiration_seconds: Lifetime of the JWT in seconds (max 600s/10m).

        Returns:
            The signed JWT string.
        """
        if not self.app_id:
            raise ValueError("GITHUB_APP_ID is not configured.")
        if not self.private_key:
            raise ValueError("GITHUB_PRIVATE_KEY is not configured.")

        now = int(time.time())
        payload = {
            # 60s clock drift buffer
            "iat": now - 60,
            "exp": now + expiration_seconds,
            "iss": str(self.app_id),
        }

        token = jwt.encode(payload, self.private_key, algorithm="RS256")
        return token if isinstance(token, str) else token.decode("utf-8")

    async def get_installation_token(
        self,
        installation_id: int,
        client: Optional[httpx.AsyncClient] = None,
    ) -> str:
        """Fetch or return cached installation access token.

        Tokens expire in 1 hour; this cache refreshes when less than 60s remain.

        Args:
            installation_id: The GitHub installation ID.
            client: Optional httpx.AsyncClient to use for the HTTP request.

        Returns:
            A valid installation access token string.
        """
        now = time.time()
        cached = self._token_cache.get(installation_id)
        if cached:
            token, expires_at = cached
            if expires_at - now > 60:
                return token

        # Fetch new token via GitHub App JWT
        app_jwt = self.create_app_jwt()
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AgentBlackBox-App",
        }
        url = f"{self.api_base_url}/app/installations/{installation_id}/access_tokens"

        async def _request(c: httpx.AsyncClient) -> str:
            resp = await c.post(url, headers=headers)
            if resp.status_code != 201:
                logger.error(
                    "github_token_exchange_failed",
                    installation_id=installation_id,
                    status_code=resp.status_code,
                    body=resp.text,
                )
                resp.raise_for_status()

            data = resp.json()
            access_token = data["token"]
            # Parse expires_at ISO format or default to now + 3600
            exp_str = data.get("expires_at")
            if exp_str:
                import datetime
                try:
                    dt = datetime.datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    expires_at_epoch = dt.timestamp()
                except Exception:
                    expires_at_epoch = now + 3500
            else:
                expires_at_epoch = now + 3500

            self._token_cache[installation_id] = (access_token, expires_at_epoch)
            return access_token

        if client is not None:
            return await _request(client)

        async with httpx.AsyncClient(timeout=15.0) as default_client:
            return await _request(default_client)
