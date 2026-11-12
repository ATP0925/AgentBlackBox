"""Tests for risk scoring."""

import pytest
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.storage.models import Event, EventType, Severity


class TestRiskScoring:
    """Test deterministic risk scoring."""

    def test_file_create_low_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.FILE_CREATE, source_path="src/main.py")
        scored = score_event(event)
        assert scored.risk_score < 3.0
        assert scored.severity == Severity.INFO

    def test_file_delete_medium_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.FILE_DELETE, source_path="src/main.py")
        scored = score_event(event)
        assert scored.risk_score >= 3.0
        assert scored.severity in (Severity.WARNING, Severity.DANGER)

    def test_secret_detected_high_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.SECRET_DETECTED, tags=["secret"])
        scored = score_event(event)
        assert scored.risk_score >= 8.0
        assert scored.severity == Severity.CRITICAL

    def test_rm_rf_critical(self) -> None:
        event = Event(
            session_id="s", event_type=EventType.CMD_EXECUTE,
            payload={"command": "rm -rf /tmp/project"}
        )
        scored = score_event(event)
        assert scored.risk_score >= 5.0
        assert scored.severity in (Severity.DANGER, Severity.CRITICAL)

    def test_force_push_critical(self) -> None:
        event = Event(session_id="s", event_type=EventType.GIT_FORCE_PUSH)
        scored = score_event(event)
        assert scored.risk_score >= 9.0
        assert scored.severity == Severity.CRITICAL

    def test_env_file_delete(self) -> None:
        event = Event(session_id="s", event_type=EventType.FILE_DELETE, source_path=".env")
        scored = score_event(event)
        assert scored.risk_score >= 5.0

    def test_risk_capped_at_10(self) -> None:
        event = Event(
            session_id="s", event_type=EventType.SECRET_DETECTED,
            source_path=".env.production",
            tags=["secret", "sensitive_file"],
        )
        scored = score_event(event)
        assert scored.risk_score <= 10.0

    def test_normal_git_commit_low_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.GIT_COMMIT)
        scored = score_event(event)
        assert scored.risk_score < 3.0

