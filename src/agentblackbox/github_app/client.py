"""Async GitHub API Client with Resilient Retry, Rate Limiting, and ETag Caching."""

from __future__ import annotations

import asyncio
import base64
import random
import time
from typing import Any, Dict, List, Optional

import httpx
import structlog

from agentblackbox.github_app.auth import GitHubAppAuth

logger = structlog.get_logger(__name__)


class GitHubClient:
    """Production-grade asynchronous client for GitHub REST API."""

    def __init__(
        self,
        auth: Optional[GitHubAppAuth] = None,
        token: Optional[str] = None,
        base_url: str = "https://api.github.com",
        timeout: float = 30.0,
        max_retries: int = 3,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.auth = auth
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._custom_client = http_client
        # In-memory ETag cache: {url: (etag, cached_json)}
        self._etag_cache: Dict[str, tuple[str, Any]] = {}

    async def _get_auth_header(self, installation_id: Optional[int] = None) -> Dict[str, str]:
        """Resolve Authorization header from installation token or static token."""
        if self.token:
            return {"Authorization": f"token {self.token}"}
        if self.auth and installation_id:
            token = await self.auth.get_installation_token(installation_id, client=self._custom_client)
            return {"Authorization": f"token {token}"}
        if self.auth and self.auth.is_configured():
            jwt_token = self.auth.create_app_jwt()
            return {"Authorization": f"Bearer {jwt_token}"}
        return {}

    async def _request(
        self,
        method: str,
        path: str,
        installation_id: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        expected_status: tuple[int, ...] = (200, 201, 204),
        raw_text: bool = False,
    ) -> Any:
        """Execute HTTP request with exponential backoff and rate limit handling."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        req_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AgentBlackBox-Bot/0.4.0",
        }
        auth_hdr = await self._get_auth_header(installation_id)
        req_headers.update(auth_hdr)
        if headers:
            req_headers.update(headers)

        # ETag cache check for GET requests
        if method.upper() == "GET" and url in self._etag_cache:
            etag, _ = self._etag_cache[url]
            req_headers["If-None-Match"] = etag

        retries = 0
        last_exc: Optional[Exception] = None

        while retries <= self.max_retries:
            try:
                c = self._custom_client or httpx.AsyncClient(timeout=self.timeout)
                try:
                    resp = await c.request(
                        method=method,
                        url=url,
                        headers=req_headers,
                        params=params,
                        json=json_data,
                    )
                finally:
                    if self._custom_client is None:
                        await c.aclose()

                # Handle ETag 304 Not Modified
                if resp.status_code == 304 and url in self._etag_cache:
                    return self._etag_cache[url][1]

                # Handle Rate Limiting (403 secondary rate limit or 429)
                if resp.status_code in (403, 429):
                    retry_after = resp.headers.get("Retry-After")
                    sleep_seconds = float(retry_after) if retry_after else (2 ** retries + random.uniform(0.5, 1.5))
                    logger.warning(
                        "github_rate_limited",
                        status_code=resp.status_code,
                        url=url,
                        retry_after=sleep_seconds,
                    )
                    await asyncio.sleep(sleep_seconds)
                    retries += 1
                    continue

                # Handle Server Errors (5xx)
                if resp.status_code >= 500:
                    sleep_seconds = 2 ** retries + random.uniform(0.2, 0.8)
                    logger.warning("github_server_error", status_code=resp.status_code, url=url, retry=retries)
                    await asyncio.sleep(sleep_seconds)
                    retries += 1
                    continue

                if resp.status_code not in expected_status:
                    if resp.status_code == 404:
                        return None
                    logger.error(
                        "github_api_error",
                        status_code=resp.status_code,
                        url=url,
                        body=resp.text[:500],
                    )
                    resp.raise_for_status()

                # Cache ETag if present
                if method.upper() == "GET" and "ETag" in resp.headers:
                    etag = resp.headers["ETag"]
                    body_val = resp.text if raw_text else (resp.json() if resp.status_code != 204 else None)
                    self._etag_cache[url] = (etag, body_val)

                if raw_text:
                    return resp.text
                if resp.status_code in (204, 404):
                    return None
                return resp.json()

            except httpx.HTTPStatusError:
                raise
            except httpx.RequestError as exc:
                last_exc = exc
                retries += 1
                if retries > self.max_retries:
                    raise
                await asyncio.sleep(2 ** retries + random.uniform(0.1, 0.5))

        if last_exc:
            raise last_exc

    async def get_pull_request(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Fetch Pull Request metadata."""
        return await self._request("GET", f"repos/{owner}/{repo}/pulls/{pull_number}", installation_id=installation_id)

    async def get_pull_request_diff(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> str:
        """Fetch raw unified diff for a pull request."""
        return await self._request(
            "GET",
            f"repos/{owner}/{repo}/pulls/{pull_number}",
            installation_id=installation_id,
            headers={"Accept": "application/vnd.github.v3.diff"},
            raw_text=True,
        )

    async def get_pull_request_files(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """List files changed in a pull request."""
        return await self._request("GET", f"repos/{owner}/{repo}/pulls/{pull_number}/files", installation_id=installation_id)

    async def get_file_contents(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
        installation_id: Optional[int] = None,
    ) -> Optional[str]:
        """Fetch raw content of a file from a specific Git ref (branch/commit)."""
        try:
            data = await self._request(
                "GET",
                f"repos/{owner}/{repo}/contents/{path.lstrip('/')}",
                installation_id=installation_id,
                params={"ref": ref},
                expected_status=(200, 404),
            )
            if isinstance(data, dict) and "content" in data:
                encoded = data["content"]
                return base64.b64decode(encoded).decode("utf-8", errors="replace")
            return None
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def list_issue_comments(self, owner: str, repo: str, issue_number: int, installation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """List comments on an issue/pull request."""
        return await self._request("GET", f"repos/{owner}/{repo}/issues/{issue_number}/comments", installation_id=installation_id)

    async def create_issue_comment(self, owner: str, repo: str, issue_number: int, body: str, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Create a new comment on an issue or pull request."""
        return await self._request(
            "POST",
            f"repos/{owner}/{repo}/issues/{issue_number}/comments",
            installation_id=installation_id,
            json_data={"body": body},
        )

    async def update_issue_comment(self, owner: str, repo: str, comment_id: int, body: str, installation_id: Optional[int] = None) -> Dict[str, Any]:
        """Update an existing issue comment."""
        return await self._request(
            "PATCH",
            f"repos/{owner}/{repo}/issues/comments/{comment_id}",
            installation_id=installation_id,
            json_data={"body": body},
        )

    async def list_review_comments(self, owner: str, repo: str, pull_number: int, installation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """List inline review comments on a pull request."""
        return await self._request("GET", f"repos/{owner}/{repo}/pulls/{pull_number}/comments", installation_id=installation_id)

    async def create_pull_request_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        commit_id: str,
        body: str,
        event: str = "COMMENT",
        comments: Optional[List[Dict[str, Any]]] = None,
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Submit a batch pull request review with inline comments."""
        payload: Dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": event,
        }
        if comments:
            payload["comments"] = comments

        return await self._request(
            "POST",
            f"repos/{owner}/{repo}/pulls/{pull_number}/reviews",
            installation_id=installation_id,
            json_data=payload,
        )

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        name: str,
        head_sha: str,
        status: str = "completed",
        conclusion: Optional[str] = "success",
        output: Optional[Dict[str, Any]] = None,
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a GitHub Check Run with conclusion and annotations."""
        payload: Dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }
        if conclusion:
            payload["conclusion"] = conclusion
        if output:
            payload["output"] = output

        return await self._request(
            "POST",
            f"repos/{owner}/{repo}/check-runs",
            installation_id=installation_id,
            json_data=payload,
        )

    async def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str,
        conclusion: Optional[str] = None,
        output: Optional[Dict[str, Any]] = None,
        installation_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Update an existing GitHub Check Run."""
        payload: Dict[str, Any] = {"status": status}
        if conclusion:
            payload["conclusion"] = conclusion
        if output:
            payload["output"] = output

        return await self._request(
            "PATCH",
            f"repos/{owner}/{repo}/check-runs/{check_run_id}",
            installation_id=installation_id,
            json_data=payload,
        )
