"""Rate Limiting and LLM Budget Cap Enforcement for GitHub App.

Enforces per-installation concurrency, hourly review velocity caps, and monthly
LLM cost limits to protect operators from unexpected usage spikes or runaway PR loops.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class InstallationUsage:
    """Tracks review counts and estimated token expenditure for an installation."""
    hourly_reviews: int = 0
    hour_window_start: float = field(default_factory=time.time)
    daily_cost_usd: float = 0.0
    day_window_start: float = field(default_factory=time.time)
    monthly_cost_usd: float = 0.0
    month_window_start: float = field(default_factory=time.time)
    is_paused: bool = False


@dataclass
class BudgetConfig:
    """Configurable budget and velocity limits."""
    max_reviews_per_hour: int = 30
    daily_cost_cap_usd: float = 25.0
    monthly_cost_cap_usd: float = 250.0
    enabled: bool = True


class RateAndBudgetLimiter:
    """Enforces rate limits, cost caps, and circuit-breaker trip states."""

    def __init__(self, config: Optional[BudgetConfig] = None) -> None:
        self.config = config or BudgetConfig()
        # {installation_id: InstallationUsage}
        self._usage: Dict[int, InstallationUsage] = {}
        # Per-PR pause state: {(owner, repo, pull_number): bool}
        self._paused_prs: Dict[Tuple[str, str, int], bool] = {}

    def _get_usage(self, installation_id: int) -> InstallationUsage:
        now = time.time()
        usage = self._usage.get(installation_id)
        if not usage:
            usage = InstallationUsage()
            self._usage[installation_id] = usage
            return usage

        # Reset 1-hour window
        if now - usage.hour_window_start > 3600:
            usage.hourly_reviews = 0
            usage.hour_window_start = now

        # Reset 24-hour day window
        if now - usage.day_window_start > 86400:
            usage.daily_cost_usd = 0.0
            usage.day_window_start = now

        # Reset 30-day month window
        if now - usage.month_window_start > 2592000:
            usage.monthly_cost_usd = 0.0
            usage.month_window_start = now

        return usage

    def is_pr_paused(self, owner: str, repo: str, pull_number: int) -> bool:
        """Check if automated reviews have been paused for this specific PR."""
        key = (owner.lower(), repo.lower(), pull_number)
        return self._paused_prs.get(key, False)

    def set_pr_paused(self, owner: str, repo: str, pull_number: int, paused: bool) -> None:
        """Set pause/resume state for a specific PR."""
        key = (owner.lower(), repo.lower(), pull_number)
        self._paused_prs[key] = paused
        logger.info("pr_review_pause_toggled", owner=owner, repo=repo, pull_number=pull_number, paused=paused)

    def check_limits(self, installation_id: int) -> Tuple[bool, Optional[str]]:
        """Verify whether an installation is permitted to run a review.
        
        Returns:
            Tuple of (is_allowed, reason_if_blocked).
        """
        if not self.config.enabled:
            return True, None

        usage = self._get_usage(installation_id)
        if usage.is_paused:
            return False, "Automated reviews are manually paused for this installation."

        if usage.hourly_reviews >= self.config.max_reviews_per_hour:
            logger.warning("hourly_rate_limit_exceeded", installation_id=installation_id, count=usage.hourly_reviews)
            return False, f"Hourly rate limit exceeded ({usage.hourly_reviews}/{self.config.max_reviews_per_hour} reviews/hr). Circuit breaker tripped."

        if usage.daily_cost_usd >= self.config.daily_cost_cap_usd:
            logger.warning("daily_cost_cap_exceeded", installation_id=installation_id, cost=usage.daily_cost_usd)
            return False, f"Daily LLM cost cap of ${self.config.daily_cost_cap_usd:.2f} reached. Reviews temporarily paused."

        if usage.monthly_cost_usd >= self.config.monthly_cost_cap_usd:
            logger.warning("monthly_cost_cap_exceeded", installation_id=installation_id, cost=usage.monthly_cost_usd)
            return False, f"Monthly LLM budget cap of ${self.config.monthly_cost_cap_usd:.2f} reached."

        return True, None

    def record_review_completion(
        self,
        installation_id: int,
        estimated_cost_usd: float = 0.01,
    ) -> None:
        """Increment usage metrics upon successful review run."""
        usage = self._get_usage(installation_id)
        usage.hourly_reviews += 1
        usage.daily_cost_usd += estimated_cost_usd
        usage.monthly_cost_usd += estimated_cost_usd
