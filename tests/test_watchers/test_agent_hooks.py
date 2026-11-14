"""Tests for AI agent attribution hooks (Claude Code PreToolUse adapter)."""

import json
from pathlib import Path

import pytest

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import EventType, Session, Severity
from agentblackbox.watchers.agent_hooks import (
    ingest_hook_payload,
    install_agent_hook,
    install_claude_hook,
    install_codex_hook,
    install_cursor_hook,
    install_gemini_hook,
    UniversalIDECollector,
)


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

    def test_install_agent_hook_supports_all_agents(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        installed = install_agent_hook(tmp_path, agent="all")
        assert "claude-code" in installed
        assert "codex" in installed
        assert "cursor" in installed
        assert "antigravity" in installed
        assert "git" in installed
        assert (tmp_path / ".codex" / "hooks.json").exists()
        assert (tmp_path / ".cursor" / "rules" / "agentblackbox.mdc").exists()
        assert (tmp_path / ".gemini" / "rules" / "agentblackbox.md").exists()
        assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()

    def test_universal_ide_collector_handles_codex_and_cursor(self) -> None:
        codex_payload = {
            "function": {
                "name": "exec_command",
                "arguments": json.dumps({"command": "pytest -q"}),
            }
        }
        event = UniversalIDECollector.parse_hook_payload(codex_payload, source_hint="codex")
        assert event.agent_source == "codex"
        assert event.event_type == EventType.CMD_EXECUTE
        assert event.target_resource == "pytest -q"

        cursor_payload = {
            "composerId": "comp_123",
            "parameters": {"relativeWorkspacePath": "src/core.py"},
        }
        c_event = UniversalIDECollector.parse_hook_payload(cursor_payload, source_hint="cursor")
        assert c_event.agent_source == "cursor"
        assert c_event.target_resource == "src/core.py"

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

    def test_a1_ingest_creates_session_if_none_exists(self, tmp_path: Path) -> None:
        ev = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
            agent_id="claude-code",
        )
        assert ev is not None
        config = BlackBoxConfig(workspace_path=tmp_path)
        store = EventStore(config.db_path)
        sessions = store.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].name == "agent-hooks"
        assert sessions[0].agent_hint == "claude-code"

    def test_a2_ingest_creates_alert_on_high_risk_and_secret(self, tmp_path: Path) -> None:
        config = BlackBoxConfig(workspace_path=tmp_path)
        store = EventStore(config.db_path)
        sess = Session(workspace_path=str(tmp_path), name="test-alerts")
        store.create_session(sess)

        ev_risky = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            agent_id="claude-code",
            session_id=sess.id,
        )
        assert ev_risky is not None
        assert ev_risky.risk_score >= 5.0
        alerts = store.get_alerts(session_id=sess.id)
        assert len(alerts) >= 1
        assert any(a.alert_type == "high_risk_event" for a in alerts)

        ev_secret = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Read", "tool_input": {"file_path": ".env"}},
            agent_id="claude-code",
            session_id=sess.id,
        )
        assert ev_secret is not None
        alerts = store.get_alerts(session_id=sess.id)
        assert any(a.alert_type in ("secret_leak", "high_risk_event") for a in alerts)

    def test_a3_cli_hook_ingest_with_mcp_and_scoring(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentblackbox.cli.main import app as cli_app

        runner = CliRunner()
        payload = json.dumps([
            {"toolName": "mcp_query", "action": "mcp_call", "parameters": {"sql": "SELECT * FROM users"}}
        ])
        res = runner.invoke(cli_app, ["hook-ingest", "--workspace", str(tmp_path), "--source", "cursor"], input=payload)
        assert res.exit_code == 0
        assert "Ingested 1 normalized events" in res.output

        config = BlackBoxConfig(workspace_path=tmp_path)
        store = EventStore(config.db_path)
        sessions = store.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].name == "agent-hooks"
        events = store.query_events(session_id=sessions[0].id)
        assert len(events) == 1
        assert events[0].event_type == EventType.PROCESS_SPAWN
        assert events[0].risk_score is not None

    def test_a5_main_silent_stdout_and_error_logging(self, tmp_path: Path, monkeypatch, capsys) -> None:
        import io
        import sys
        from agentblackbox.watchers.agent_hooks import _main

        monkeypatch.setattr(sys, "stdin", io.StringIO("{broken json"))
        monkeypatch.setattr(sys, "argv", ["agent_hooks", "--workspace", str(tmp_path)])

        with pytest.raises(SystemExit) as exc:
            _main()
        assert exc.value.code == 0

        captured = capsys.readouterr()
        assert captured.out == ""

        err_log = tmp_path / ".agentblackbox" / "hook_errors.log"
        assert err_log.exists()
        log_content = err_log.read_text(encoding="utf-8")
        assert "JSONDecodeError" in log_content

    def test_a6_install_claude_hook_invalid_json_creates_backup(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir(parents=True)
        settings = claude_dir / "settings.local.json"
        settings.write_text("NOT_VALID_JSON{", encoding="utf-8")

        with pytest.raises(ValueError) as excinfo:
            install_claude_hook(tmp_path)

        assert "Corrupt JSON" in str(excinfo.value)
        bak_file = claude_dir / "settings.local.json.bak"
        assert bak_file.exists()
        assert bak_file.read_text(encoding="utf-8") == "NOT_VALID_JSON{"

    def test_b1_normalize_hook_payload_fixtures(self) -> None:
        from agentblackbox.watchers.agent_hooks import normalize_hook_payload

        # Claude Code fixture
        claude_fixture = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "npm test"},
            "cwd": "/project/root"
        })
        n_claude = normalize_hook_payload("claude-code", json.loads(claude_fixture))
        assert n_claude == {
            "kind": "shell",
            "command": "npm test",
            "path": None,
            "tool": "Bash",
            "cwd": "/project/root",
        }

        # Codex CLI Write fixture
        codex_fixture = json.dumps({
            "tool_name": "Write",
            "tool_input": {"file_path": "lib/db.py"},
            "cwd": "/codex/ws"
        })
        n_codex = normalize_hook_payload("codex", json.loads(codex_fixture))
        assert n_codex["kind"] == "file_write"
        assert n_codex["path"] == "lib/db.py"
        assert n_codex["command"] is None

        # Cursor beforeShellExecution fixture (command TOP-LEVEL, workspace_roots)
        cursor_shell_fixture = json.dumps({
            "hook_event_name": "beforeShellExecution",
            "command": "git push --force",
            "workspace_roots": ["/cursor/ws"]
        })
        n_cursor_shell = normalize_hook_payload("cursor", json.loads(cursor_shell_fixture))
        assert n_cursor_shell == {
            "kind": "shell",
            "command": "git push --force",
            "path": None,
            "tool": "beforeShellExecution",
            "cwd": "/cursor/ws",
        }

        # Cursor afterFileEdit fixture
        cursor_edit_fixture = json.dumps({
            "hook_event_name": "afterFileEdit",
            "file_path": "src/index.ts",
            "workspace_roots": ["/cursor/ws"]
        })
        n_cursor_edit = normalize_hook_payload("cursor", json.loads(cursor_edit_fixture))
        assert n_cursor_edit["kind"] == "file_edit"
        assert n_cursor_edit["path"] == "src/index.ts"

        # Gemini CLI BeforeTool run_shell_command fixture
        gemini_fixture = json.dumps({
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls -la"},
            "cwd": "/gemini/ws"
        })
        n_gemini = normalize_hook_payload("gemini", json.loads(gemini_fixture))
        assert n_gemini == {
            "kind": "shell",
            "command": "ls -la",
            "path": None,
            "tool": "run_shell_command",
            "cwd": "/gemini/ws",
        }

    def test_b1_file_read_sensitive_vs_skipped(self, tmp_path: Path) -> None:
        # Non-sensitive read -> None (skipped)
        ev_norm = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Read", "tool_input": {"file_path": "src/utils.py"}},
            agent_id="claude-code"
        )
        assert ev_norm is None

        # Sensitive read -> recorded as EventType.FILE_READ
        ev_env = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Read", "tool_input": {"file_path": ".env"}},
            agent_id="claude-code"
        )
        assert ev_env is not None
        assert ev_env.event_type == EventType.FILE_READ

        ev_ssh = ingest_hook_payload(
            tmp_path,
            {"tool_name": "read_file", "tool_input": {"file_path": "C:/Users/key/.ssh/id_rsa"}},
            agent_id="gemini"
        )
        assert ev_ssh is not None
        assert ev_ssh.event_type == EventType.FILE_READ

    def test_b1_write_tool_create_vs_modify(self, tmp_path: Path) -> None:
        test_file = tmp_path / "hello.py"
        # File does not exist yet -> FILE_CREATE
        ev_create = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Write", "tool_input": {"file_path": str(test_file)}},
            agent_id="claude-code"
        )
        assert ev_create is not None
        assert ev_create.event_type == EventType.FILE_CREATE

        # Now create file on disk -> FILE_MODIFY
        test_file.write_text("print('hello')", encoding="utf-8")
        ev_modify = ingest_hook_payload(
            tmp_path,
            {"tool_name": "Write", "tool_input": {"file_path": str(test_file)}},
            agent_id="claude-code"
        )
        assert ev_modify is not None
        assert ev_modify.event_type == EventType.FILE_MODIFY

    def test_b2_auto_workspace_from_payload(self, tmp_path: Path) -> None:
        ev = ingest_hook_payload(
            workspace=None,
            payload={
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
                "cwd": str(tmp_path)
            },
            agent_id="claude-code"
        )
        assert ev is not None
        config = BlackBoxConfig(workspace_path=tmp_path)
        assert config.db_path.exists()

    def test_b3_hook_installers_idempotency_and_matcher_update(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fake_home")
        
        # Test install claude and matcher update
        c_path = install_claude_hook(tmp_path)
        assert c_path.exists()
        d1 = json.loads(c_path.read_text(encoding="utf-8"))
        assert "mcp__.*" in d1["hooks"]["PreToolUse"][0]["matcher"]

        # Run again -> idempotent
        install_claude_hook(tmp_path)
        d2 = json.loads(c_path.read_text(encoding="utf-8"))
        assert len(d2["hooks"]["PreToolUse"]) == 1

        # Test codex hook
        codex_path = install_codex_hook(tmp_path)
        assert codex_path.exists()
        d_codex = json.loads(codex_path.read_text(encoding="utf-8"))
        assert d_codex["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 10

        # Test cursor hook
        cur_path = install_cursor_hook(tmp_path)
        assert cur_path.exists()
        d_cursor = json.loads(cur_path.read_text(encoding="utf-8"))
        assert "beforeShellExecution" in d_cursor["hooks"]

        # Test gemini hook
        gem_path = install_gemini_hook(tmp_path)
        assert gem_path.exists()
        d_gem = json.loads(gem_path.read_text(encoding="utf-8"))
        assert d_gem["hooks"]["BeforeTool"][0]["hooks"][0]["timeout"] == 5000

    def test_b4_hook_verify_cli(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentblackbox.cli.main import app as cli_app
        from agentblackbox.watchers.agent_hooks import install_agent_hook

        runner = CliRunner()
        # Before installation -> MISSING
        res1 = runner.invoke(cli_app, ["hook-verify", "--workspace", str(tmp_path)])
        assert res1.exit_code == 0
        assert "MISSING" in res1.output

        # Install all project hooks
        install_agent_hook(tmp_path, agent="all")

        # After installation -> OK
        res2 = runner.invoke(cli_app, ["hook-verify", "--workspace", str(tmp_path)])
        assert res2.exit_code == 0
        assert "OK" in res2.output


