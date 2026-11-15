"""Asynchronous Background Job Queue with Delivery Idempotency, Dead-Letter Tracking, and Pluggable Backends."""

from __future__ import annotations

import abc
import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ReviewJobDescriptor:
    """Lightweight job descriptor containing IDs and metadata only.
    
    Zero Customer Code Retention: Raw diffs and file contents are NEVER stored in queue state.
    """
    owner: str
    repo: str
    pull_number: int
    head_sha: str
    delivery_id: str
    installation_id: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    is_full_review: bool = False
    retry_count: int = 0
    max_retries: int = 3


class BaseIdempotencyStore(abc.ABC):
    """Abstract interface for webhook delivery deduplication."""

    @abc.abstractmethod
    def is_duplicate(self, delivery_id: str) -> bool:
        """Check if delivery ID has already been recorded."""
        ...

    @abc.abstractmethod
    def record_delivery(self, delivery_id: str) -> None:
        """Record delivery ID with TTL expiration."""
        ...


class IdempotencyStore(BaseIdempotencyStore):
    """In-memory idempotency store with automatic TTL expiration."""

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


class RedisIdempotencyStore(BaseIdempotencyStore):
    """Redis-backed idempotency store utilizing atomic SETNX with expiration."""

    def __init__(self, redis_client: Any, ttl_seconds: int = 3600, key_prefix: str = "abb:delivery:") -> None:
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds
        self.prefix = key_prefix
        self._fallback = IdempotencyStore(ttl_seconds=ttl_seconds)

    def is_duplicate(self, delivery_id: str) -> bool:
        key = f"{self.prefix}{delivery_id}"
        try:
            return bool(self.redis.exists(key))
        except Exception as exc:
            logger.warning("redis_idempotency_fallback", error=str(exc))
            return self._fallback.is_duplicate(delivery_id)

    def record_delivery(self, delivery_id: str) -> None:
        key = f"{self.prefix}{delivery_id}"
        try:
            self.redis.set(key, "1", ex=self.ttl_seconds)
        except Exception as exc:
            logger.warning("redis_idempotency_record_fallback", error=str(exc))
            self._fallback.record_delivery(delivery_id)


class BaseJobQueue(abc.ABC):
    """Abstract interface for background review task dispatch."""

    @abc.abstractmethod
    def cancel_in_flight_pr_job(self, owner: str, repo: str, pull_number: int) -> bool:
        """Cancel any active job superseded by a new commit on the same PR."""
        ...

    @abc.abstractmethod
    def enqueue(
        self,
        descriptor: ReviewJobDescriptor,
        coro_func: Optional[Callable[[], Coroutine[Any, Any, Any]]] = None,
    ) -> asyncio.Task[Any]:
        """Convenience method to enqueue from a ReviewJobDescriptor."""
        async def _noop() -> None:
            pass
        return self.enqueue_pr_review(
            owner=descriptor.owner,
            repo=descriptor.repo,
            pull_number=descriptor.pull_number,
            coro_func=coro_func or _noop,
            descriptor=descriptor,
        )

    def enqueue_pr_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        coro_func: Callable[[], Coroutine[Any, Any, Any]],
        descriptor: Optional[ReviewJobDescriptor] = None,
    ) -> Any:
        """Enqueue and launch a PR review task."""
        ...


class ReviewJobQueue(BaseJobQueue):
    """Manages background review tasks with per-PR concurrency control and dead-letter tracking."""

    def __init__(
        self,
        idempotency_store: Optional[BaseIdempotencyStore] = None,
    ) -> None:
        self.idempotency = idempotency_store or IdempotencyStore()
        # In-flight tasks: {(owner, repo, pull_number): asyncio.Task}
        self._in_flight: Dict[Tuple[str, str, int], asyncio.Task[Any]] = {}
        # Dead-letter queue for failed or exhausted jobs: [{descriptor, error, timestamp}]
        self.dead_letters: List[Dict[str, Any]] = []

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

    def enqueue(
        self,
        descriptor: ReviewJobDescriptor,
        coro_func: Optional[Callable[[], Coroutine[Any, Any, Any]]] = None,
    ) -> asyncio.Task[Any]:
        """Convenience method to enqueue from a ReviewJobDescriptor."""
        async def _noop() -> None:
            pass
        return self.enqueue_pr_review(
            owner=descriptor.owner,
            repo=descriptor.repo,
            pull_number=descriptor.pull_number,
            coro_func=coro_func or _noop,
            descriptor=descriptor,
        )

    def enqueue_pr_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        coro_func: Callable[[], Coroutine[Any, Any, Any]],
        descriptor: Optional[ReviewJobDescriptor] = None,
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
                self.dead_letters.append({
                    "owner": owner,
                    "repo": repo,
                    "pull_number": pull_number,
                    "descriptor": descriptor,
                    "error": str(exc),
                    "failed_at": time.time(),
                })
            finally:
                self._in_flight.pop(key, None)

        task = asyncio.create_task(_wrapper())
        self._in_flight[key] = task
        return task

    def get_queue_stats(self) -> Dict[str, Any]:
        """Return operational metrics for monitoring and health reporting."""
        active_count = sum(1 for t in self._in_flight.values() if not t.done())
        return {
            "active_jobs": active_count,
            "total_tracked": len(self._in_flight),
            "dead_letter_count": len(self.dead_letters),
        }
