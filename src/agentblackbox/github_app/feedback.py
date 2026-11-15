"""Feedback and Quality Calibration Telemetry for AgentBlackBox GitHub App.

Records developer reactions (thumbs up, thumbs down, heart, confused) on review comments
to calibrate scanner rule precision, confidence thresholds, and false-positive rates.

Zero Code Retention: Retains ONLY rule_id, finding_hash, and reaction type. Zero diff or code storage.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional
import structlog

logger = structlog.get_logger(__name__)

POSITIVE_REACTIONS = {"+1", "heart", "hooray", "rocket"}
NEGATIVE_REACTIONS = {"-1", "confused"}


class FeedbackStore:
    """Manages anonymous review feedback telemetry for continuous rule calibration."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path:
            self.db_path = db_path
        else:
            env_db = os.environ.get("ABB_DB_PATH")
            if env_db:
                self.db_path = Path(env_db)
            else:
                self.db_path = Path.cwd() / ".agentblackbox" / "events.db"

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create feedback table if not exists."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS review_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    finding_hash TEXT NOT NULL,
                    reaction TEXT NOT NULL,
                    comment_id INTEGER,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_feedback_rule ON review_feedback (rule_id)"
            )
            conn.commit()

    def record_feedback(
        self,
        rule_id: str,
        finding_hash: str,
        reaction: str,
        comment_id: Optional[int] = None,
    ) -> None:
        """Record a developer reaction on a review comment."""
        clean_rule = rule_id.strip()[:64]
        clean_hash = finding_hash.strip()[:64]
        clean_reaction = reaction.strip().lower()

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO review_feedback (rule_id, finding_hash, reaction, comment_id, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (clean_rule, clean_hash, clean_reaction, comment_id, time.time()),
            )
            conn.commit()

        logger.info(
            "recorded_review_feedback",
            rule_id=clean_rule,
            reaction=clean_reaction,
            comment_id=comment_id,
        )

    def get_rule_stats(self, rule_id: Optional[str] = None) -> Dict[str, Any]:
        """Calculate approval rates and reaction distributions per rule or overall."""
        query = "SELECT rule_id, reaction, COUNT(*) FROM review_feedback"
        params: List[Any] = []
        if rule_id:
            query += " WHERE rule_id = ?"
            params.append(rule_id.strip())
        query += " GROUP BY rule_id, reaction"

        with sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        stats_by_rule: Dict[str, Dict[str, int]] = {}
        for r_id, reaction, count in rows:
            if r_id not in stats_by_rule:
                stats_by_rule[r_id] = {"positive": 0, "negative": 0, "total": 0}
            stats_by_rule[r_id]["total"] += count
            if reaction in POSITIVE_REACTIONS:
                stats_by_rule[r_id]["positive"] += count
            elif reaction in NEGATIVE_REACTIONS:
                stats_by_rule[r_id]["negative"] += count

        results: Dict[str, Any] = {}
        for r_id, counts in stats_by_rule.items():
            tot = counts["total"]
            pos = counts["positive"]
            approval_rate = (pos / tot) if tot > 0 else 1.0
            results[r_id] = {
                "total_reactions": tot,
                "positive": pos,
                "negative": counts["negative"],
                "approval_rate": round(approval_rate, 3),
            }

        return results
