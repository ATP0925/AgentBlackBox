"""Asynchronous Background Job Queue with Delivery Idempotency and In-Flight Cancellation."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Coroutine, Dict, Optional, Set, Tuple

import structlog

logger = structlog.get_logger(__name__)


class IdempotencyStore:
    """In-memory idempotency store with TTL expiration (Redis-compatible interface)."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl_seconds = ttl_seconds
        # {delivery_id: timestamp}
        self._seen: Dict[str, float] = {}

    def is_duplicate(self, delivery_id: str) -> bool:
        """Check if delivery ID has already been seen within TTL window."""
        now = time.time()
        self._evict_expired(now)
        return delivery_id in self._seen

    def record_delivery(self, delivery_id: str) -> None:
        """Record delivery ID as processed."""
        self._seen[delivery_id] = time.time()

    def _evict_expired(self, now: float) -> None:
        """Prune entries older than TTL."""
        expired = [k for k, ts in self._seen.items() if now - ts > self.ttl_seconds]
        for k in expired:
            self._seen.pop(k, None)


class ReviewJobQueue:
    """Manages background review tasks with per-PR concurrency control."""

    def __init__(self, idempotency_store: Optional[IdempotencyStore] = None) -> None:
        self.idempotency = idempotency_store or IdempotencyStore()
        # In-flight tasks: {(owner, repo, pull_number): asyncio.Task}
        self._in_flight: Dict[Tuple[str, str, int], asyncio.Task[Any]] = {}

    def cancel_in_flight_pr_job(self, owner: str, repo: str, pull_number: int) -> bool:
        """Cancel an in-flight review for a PR if a new commit was pushed (synchronize)."""
        key = (owner.lower(), repo.lower(), pull_number)
        task = self._in_flight.get(key)
        if task and not task.done():
            task.cancel()
            logger.info("canceled_obsolete_pr_job", owner=owner, repo=repo, pull_number=pull_number)
            self._in_flight.pop(key, None)
            return True
        return False

    def enqueue_pr_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        coro_func: Callable[[], Coroutine[Any, Any, Any]],
    ) -> asyncio.Task[Any]:
        """Enqueue and launch a PR review task, canceling any existing run for this PR."""
        self.cancel_in_flight_pr_job(owner, repo, pull_number)

        key = (owner.lower(), repo.lower(), pull_number)

        async def _wrapper() -> None:
            try:
                await coro_func()
            except asyncio.CancelledError:
                logger.info("pr_job_cancelled", owner=owner, repo=repo, pull_number=pull_number)
            except Exception as exc:
                logger.error("pr_job_failed", owner=owner, repo=repo, pull_number=pull_number, error=str(exc))
            finally:
                self._in_flight.pop(key, None)

        task = asyncio.create_task(_wrapper())
        self._in_flight[key] = task
        return task
