"""FastAPI Webhook Router for GitHub App."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
import structlog

from agentblackbox.github_app.auth import GitHubAppAuth
from agentblackbox.github_app.client import GitHubClient
from agentblackbox.github_app.events import GitHubEventHandler
from agentblackbox.github_app.installations import InstallationStore
from agentblackbox.github_app.queue import IdempotencyStore, ReviewJobDescriptor, ReviewJobQueue
from agentblackbox.github_app.security import verify_github_signature

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["github-webhook"])

# Global singleton managers
auth_manager = GitHubAppAuth()
github_client = GitHubClient(auth=auth_manager)
job_queue = ReviewJobQueue(idempotency_store=IdempotencyStore(ttl_seconds=3600))
event_handler = GitHubEventHandler(client=github_client)
installation_store = InstallationStore()


@router.get("/healthz")
async def healthz() -> dict:
    """Liveness probe endpoint."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz() -> dict:
    """Readiness probe verifying GitHub App configuration."""
    return {
        "status": "ready",
        "app_configured": auth_manager.is_configured(),
        "app_id": auth_manager.app_id or "not_set",
    }


@router.get("/metrics")
async def metrics() -> dict:
    """Observability metrics for background review queue and operations."""
    stats = job_queue.get_queue_stats()
    return {
        "status": "healthy",
        "active_jobs": stats["active_jobs"],
        "total_jobs_tracked": stats["total_tracked"],
        "dead_letter_count": stats["dead_letter_count"],
        "dead_letters": job_queue.dead_letters[-10:],
    }


@router.get("/sarif/{owner}/{repo}/{pull_number}")
async def get_pr_sarif(owner: str, repo: str, pull_number: int) -> JSONResponse:
    """Download the latest SARIF v2.1.0 report for a reviewed pull request."""
    key = (owner.lower(), repo.lower(), pull_number)
    sarif = event_handler.latest_sarif_reports.get(key)
    if not sarif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No SARIF report available for {owner}/{repo} PR #{pull_number}",
        )
    return JSONResponse(content=sarif)


@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def handle_github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
) -> Response:
    """Ingest and verify GitHub webhook deliveries.

    Verifies HMAC-SHA256 signature, enforces delivery idempotency, and dispatches
    background processing immediately, returning 202 Accepted.
    """
    raw_body = await request.body()
    secret = auth_manager.webhook_secret or os.environ.get("GITHUB_WEBHOOK_SECRET", "")

    # In strict mode: verify signature
    # Allow bypass in testing only if ABB_SKIP_WEBHOOK_AUTH=1
    skip_auth = os.environ.get("ABB_SKIP_WEBHOOK_AUTH") == "1"
    if not skip_auth:
        if not secret or not verify_github_signature(raw_body, x_hub_signature_256, secret):
            logger.warning("invalid_webhook_signature", delivery=x_github_delivery)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Hub-Signature-256",
            )

    # Enforce delivery idempotency
    delivery_id = x_github_delivery or "unknown"
    if job_queue.idempotency.is_duplicate(delivery_id):
        logger.info("duplicate_delivery_skipped", delivery=delivery_id)
        return Response(status_code=status.HTTP_202_ACCEPTED, content="Duplicate delivery")

    job_queue.idempotency.record_delivery(delivery_id)

    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception as exc:
        logger.error("invalid_webhook_json", error=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed JSON payload")

    event_type = x_github_event or "unknown"
    logger.info("received_github_event", event_type=event_type, delivery=delivery_id)

    # 1. Handle Ping event
    if event_type == "ping":
        return Response(status_code=status.HTTP_200_OK, content="pong")

    # 2. Handle Pull Request events
    if event_type == "pull_request":
        pr_data = payload.get("pull_request", {})
        repo_data = payload.get("repository", {})
        owner = repo_data.get("owner", {}).get("login", "")
        repo = repo_data.get("name", "")
        pull_number = pr_data.get("number")
        head_sha = pr_data.get("head", {}).get("sha", "")
        installation_id = payload.get("installation", {}).get("id")

        if owner and repo and pull_number:
            descriptor = ReviewJobDescriptor(
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                head_sha=head_sha,
                delivery_id=delivery_id,
                installation_id=installation_id,
            )
            job_queue.enqueue_pr_review(
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                coro_func=lambda: event_handler.handle_pull_request_event(payload),
                descriptor=descriptor,
            )
            return Response(status_code=status.HTTP_202_ACCEPTED, content="Pull request review scheduled")

    # 3. Handle Issue Comment events (bot mentions)
    if event_type == "issue_comment":
        import asyncio
        asyncio.create_task(event_handler.handle_issue_comment_event(payload))
        return Response(status_code=status.HTTP_202_ACCEPTED, content="Issue comment processing scheduled")

    # 4. Installation Lifecycle events
    if event_type in ("installation", "installation_repositories"):
        action = payload.get("action")
        install_data = payload.get("installation", {})
        install_id = install_data.get("id")
        account = install_data.get("account", {})

        if install_id:
            if action == "created":
                repos = [r.get("full_name") for r in payload.get("repositories", []) if r.get("full_name")]
                installation_store.record_installation(
                    installation_id=install_id,
                    account_login=account.get("login", "unknown"),
                    account_id=account.get("id", 0),
                    account_type=account.get("type", "User"),
                    repositories=repos,
                )
            elif action == "deleted":
                installation_store.remove_installation(install_id)
            elif action in ("added", "removed"):
                added_repos = [r.get("full_name") for r in payload.get("repositories_added", []) if r.get("full_name")]
                removed_repos = [r.get("full_name") for r in payload.get("repositories_removed", []) if r.get("full_name")]
                installation_store.update_repositories(
                    installation_id=install_id,
                    added=added_repos,
                    removed=removed_repos,
                )

        logger.info("installation_event_processed", action=action, installation_id=install_id)
        return Response(status_code=status.HTTP_202_ACCEPTED, content="Installation event recorded")

    # 5. Review Comment & Reactions Feedback
    if event_type == "pull_request_review_comment":
        import asyncio
        asyncio.create_task(event_handler.handle_review_comment_event(payload))
        return Response(status_code=status.HTTP_202_ACCEPTED, content="Review feedback processed")

    return Response(status_code=status.HTTP_202_ACCEPTED, content="Event received")
