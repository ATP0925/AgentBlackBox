"""Tests for AI agent attribution hooks (Claude Code PreToolUse adapter)."""

import json
from pathlib import Path

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import EventType, Session, Severity
from agentblackbox.watchers.agent_hooks import ingest_hook_payload, install_claude_hook


class TestAgentHooks:
    """Test hook installer and stdin payload ingestion."""

    def test_install_claude_hook_merges_safely(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.local.json"
        settings.write_text(json.dumps({"permissions": {"allow": ["Read"]}}), encoding="utf-8")

        out_path = install_claude_hook(tmp_path)
        install_claude_hook(tmp_path)  # idempotent second call
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data["permissions"]["allow"] == ["Read"]
        assert len(data["hooks"]["PreToolUse"]) == 1

    def test_ingest_bash_and_write_tool_events(self, tmp_path: Path) -> None:
        config = BlackBoxConfig(workspace_path=tmp_path)
        store = EventStore(config.db_path)
        sess = Session(workspace_path=str(tmp_path), agent_hint="claude-code")
        store.create_session(sess)

        ev1 = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/foo"}},
            agent_id="claude-code",
        )
        ev2 = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Edit", "tool_input": {"file_path": "src/auth.py"}},
            agent_id="claude-code",
        )
        assert ev1 is not None and ev1.event_type == EventType.CMD_EXECUTE
        assert ev1.severity in (Severity.DANGER, Severity.CRITICAL)
        assert ev2 is not None and ev2.event_type == EventType.FILE_MODIFY
        assert ev2.source_path == "src/auth.py"
        assert store.verify_chain(sess.id).valid is True

