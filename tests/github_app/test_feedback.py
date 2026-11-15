"""Tests for Developer Feedback Telemetry and Rule Precision Calibration."""

from __future__ import annotations

from pathlib import Path
import pytest

from agentblackbox.github_app.feedback import FeedbackStore


def test_feedback_store_lifecycle_and_calibration(tmp_path: Path) -> None:
    db_file = tmp_path / "events.db"
    store = FeedbackStore(db_path=db_file)

    # 1. Record reactions on various review comments
    store.record_feedback(
        rule_id="SEC-001-SECRET-LEAK",
        finding_hash="hash-123",
        reaction="+1",
        comment_id=9001,
    )
    store.record_feedback(
        rule_id="SEC-001-SECRET-LEAK",
        finding_hash="hash-123",
        reaction="heart",
        comment_id=9002,
    )
    store.record_feedback(
        rule_id="SEC-001-SECRET-LEAK",
        finding_hash="hash-456",
        reaction="+1",
        comment_id=9003,
    )
    store.record_feedback(
        rule_id="DRIFT-LINTER-SUPPRESS",
        finding_hash="hash-789",
        reaction="-1",
        comment_id=9004,
    )
    store.record_feedback(
        rule_id="DRIFT-LINTER-SUPPRESS",
        finding_hash="hash-789",
        reaction="confused",
        comment_id=9005,
    )

    # 2. Query stats for SEC-001-SECRET-LEAK
    sec_stats = store.get_rule_stats("SEC-001-SECRET-LEAK")
    assert "SEC-001-SECRET-LEAK" in sec_stats
    assert sec_stats["SEC-001-SECRET-LEAK"]["total_reactions"] == 3
    assert sec_stats["SEC-001-SECRET-LEAK"]["positive"] == 3
    assert sec_stats["SEC-001-SECRET-LEAK"]["negative"] == 0
    assert sec_stats["SEC-001-SECRET-LEAK"]["approval_rate"] == 1.0

    # 3. Query stats for DRIFT-LINTER-SUPPRESS
    drift_stats = store.get_rule_stats("DRIFT-LINTER-SUPPRESS")
    assert "DRIFT-LINTER-SUPPRESS" in drift_stats
    assert drift_stats["DRIFT-LINTER-SUPPRESS"]["total_reactions"] == 2
    assert drift_stats["DRIFT-LINTER-SUPPRESS"]["positive"] == 0
    assert drift_stats["DRIFT-LINTER-SUPPRESS"]["negative"] == 2
    assert drift_stats["DRIFT-LINTER-SUPPRESS"]["approval_rate"] == 0.0

    # 4. Overall stats
    all_stats = store.get_rule_stats()
    assert len(all_stats) == 2
    assert "SEC-001-SECRET-LEAK" in all_stats
    assert "DRIFT-LINTER-SUPPRESS" in all_stats
