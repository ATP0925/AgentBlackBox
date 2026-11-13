# Module: Unit tests verifying all 4 architectural security upgrades for AgentBlackBox.
from __future__ import annotations

import base64
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from keyring.errors import NoKeyringError

from agentblackbox.analysis.key_provider import (
    ENV_HMAC_KEY,
    ENV_TEST_KEY,
    KeyProvider,
    KeyProviderError,
)
from agentblackbox.analysis.secret_scanner import redact_secrets
from agentblackbox.collectors.ide_hooks import UniversalIDECollector
from agentblackbox.storage.tamper_guard import TamperGuard


def test_key_provider_scrubs_env_and_uses_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_TEST_KEY, raising=False)
    monkeypatch.setenv(ENV_HMAC_KEY, "a" * 64)
    mock_store: dict[tuple[str, str], str] = {}

    def fake_get(service: str, user: str) -> str | None:
        return mock_store.get((service, user))

    def fake_set(service: str, user: str, pw: str) -> None:
        mock_store[(service, user)] = pw

    with patch("keyring.get_password", side_effect=fake_get), patch(
        "keyring.set_password", side_effect=fake_set
    ):
        provider = KeyProvider.initialize()
        assert ENV_HMAC_KEY not in os.environ
        sig = provider.sign_payload("tip_checkpoint", b"seq:10|hash:abc")
        assert provider.verify_payload("tip_checkpoint", b"seq:10|hash:abc", sig)
        assert not provider.verify_payload("event_chain", b"seq:10|hash:abc", sig)
        provider.zeroize()


def test_key_provider_fails_closed_when_no_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_TEST_KEY, raising=False)
    with patch("keyring.get_password", side_effect=NoKeyringError("No D-Bus")):
        with pytest.raises(KeyProviderError):
            KeyProvider.initialize()


def test_tamper_guard_detects_deletion_and_rollback(tmp_path: Path) -> None:
    ws_dir = tmp_path / ".agentblackbox"
    shadow_root = tmp_path / "shadow"
    guard = TamperGuard(ws_dir, session_id="sess_01", shadow_root=shadow_root)
    guard.replicate_tip_checkpoint({"seq": 5, "tip_hash": "h5", "mac": "mac_5"})
    ok, _ = guard.verify_workspace_integrity()
    assert ok is True

    # Simulate malicious agent rolling back sequence number
    (ws_dir / "sess_01.tip").write_text('{"seq": 2, "tip_hash": "h2", "mac": "mac_2"}', encoding="utf-8")
    ok_rollback, msg_rollback = guard.verify_workspace_integrity()
    assert ok_rollback is False
    assert "rolled back" in msg_rollback

    # Simulate malicious agent deleting .tip file and verify restoration
    (ws_dir / "sess_01.tip").unlink()
    ok_del, _ = guard.verify_workspace_integrity()
    assert ok_del is False
    assert guard.restore_from_shadow() is True
    assert guard.verify_workspace_integrity()[0] is True


def test_secret_scanner_catches_base64_and_split_secrets() -> None:
    raw_openai = "sk-proj-1234567890abcdefghijklmnop"
    b64_openai = base64.b64encode(raw_openai.encode("utf-8")).decode("ascii")
    redacted_b64, types_b64 = redact_secrets(f"Authorization: Bearer {b64_openai}")
    assert "[REDACTED:BASE64_OPENAI_KEY]" in redacted_b64
    assert "BASE64_OPENAI_KEY" in types_b64

    split_text = 'token = "sk-ant-api03-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"'
    redacted_split, types_split = redact_secrets(split_text)
    assert "[REDACTED:ANTHROPIC_KEY]" in redacted_split
    assert "SPLIT_ANTHROPIC_KEY" in types_split


def test_universal_ide_collector_normalizes_cursor_cline_and_antigravity(tmp_path: Path) -> None:
    cursor_ev = UniversalIDECollector.parse_hook_payload(
        {"composerId": "cmp-1", "mcpServer": "filesystem", "toolName": "edit_file", "parameters": {"relativeWorkspacePath": "src/app.py"}}
    )
    assert cursor_ev.agent_source == "cursor"
    assert cursor_ev.event_type == "mcp_call"
    assert cursor_ev.target_resource == "src/app.py"

    cline_ev = UniversalIDECollector.parse_hook_payload(
        {"cline_task_id": "t-9", "tool": "execute_command", "command": "pytest -q"}
    )
    assert cline_ev.agent_source == "cline"
    assert cline_ev.event_type == "terminal_cmd"

    ag_ev = UniversalIDECollector.parse_hook_payload(
        {"tool": "write_to_file", "args": {"TargetFile": "src/main.py"}}
    )
    assert ag_ev.agent_source == "antigravity"
    assert ag_ev.target_resource == "src/main.py"
