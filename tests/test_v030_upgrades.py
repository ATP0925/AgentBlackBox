"""Unit tests verifying all 4 v0.3.0 architectural security upgrades for AgentBlackBox."""
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
from agentblackbox.analysis.redactor import redact_secrets
from agentblackbox.analysis.secret_detector import SecretDetector
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session
from agentblackbox.storage.tamper_guard import TamperGuard
from agentblackbox.watchers.agent_hooks import UniversalIDECollector


def test_gap1_key_provider_scrubs_env_and_integrates_with_event_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV_TEST_KEY, raising=False)
    monkeypatch.setenv(ENV_HMAC_KEY, "ab" * 32)
    mock_ring: dict[tuple[str, str], str] = {}

    with patch("keyring.get_password", side_effect=lambda s, u: mock_ring.get((s, u))), patch(
        "keyring.set_password", side_effect=lambda s, u, p: mock_ring.__setitem__((s, u), p)
    ):
        provider = KeyProvider.initialize(force_reload=True)
        assert ENV_HMAC_KEY not in os.environ

        db_path = tmp_path / ".agentblackbox" / "events.db"
        store = EventStore(db_path=db_path)
        sess = store.create_session(Session(id="s_keytest", workspace_path=str(tmp_path)))
        store.insert_event(
            Event(session_id=sess.id, event_type=EventType.CMD_EXECUTE, payload={"cmd": "echo ok"})
        )
        res = store.verify_chain(sess.id)
        assert res.valid is True
        provider.zeroize()


def test_gap1_key_provider_fails_closed_without_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_TEST_KEY, raising=False)
    monkeypatch.delenv(ENV_HMAC_KEY, raising=False)
    with patch("keyring.get_password", side_effect=NoKeyringError("No D-Bus")):
        with pytest.raises(KeyProviderError):
            KeyProvider.initialize(force_reload=True)


def test_gap2_tamper_guard_detects_checkpoint_deletion_and_rollback(tmp_path: Path) -> None:
    ws_abb = tmp_path / ".agentblackbox"
    shadow_root = tmp_path / "shadow_mirrors"
    guard = TamperGuard(ws_abb, session_id="sess_tamper", shadow_root=shadow_root)

    guard.replicate_tip_checkpoint({"last_seq": 8, "head_hash": "hash8", "signature": "sig8"})
    ok, _ = guard.verify_workspace_integrity()
    assert ok is True

    guard.workspace_tip_path.write_text(
        '{"last_seq": 3, "head_hash": "hash3", "signature": "sig3"}', encoding="utf-8"
    )
    ok_rb, msg_rb = guard.verify_workspace_integrity()
    assert ok_rb is False
    assert "rolled back" in msg_rb

    guard.workspace_tip_path.unlink()
    assert guard.verify_workspace_integrity()[0] is False
    assert guard.restore_from_shadow() is True
    assert guard.verify_workspace_integrity()[0] is True


def test_gap3_secret_detector_and_redactor_catch_base64_hex_and_split_tokens() -> None:
    detector = SecretDetector()
    raw_openai = "sk-proj-1234567890abcdefghijklmnop"
    b64_openai = base64.b64encode(raw_openai.encode("utf-8")).decode("ascii")

    matches_b64 = detector.scan_text(f"export TOKEN={b64_openai}")
    assert any("base64_openai_api_key" in m.pattern_name for m in matches_b64)

    redacted_b64 = redact_secrets(f"export TOKEN={b64_openai}")
    assert b64_openai not in redacted_b64
    assert "[REDACTED:" in redacted_b64

    split_line = 'api_key = "sk-ant-api03-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"'
    redacted_split = redact_secrets(split_line)
    assert "sk-ant-api03-" not in redacted_split
    assert "[REDACTED:" in redacted_split


def test_gap4_universal_ide_collector_maps_to_valid_storage_events() -> None:
    cursor_norm = UniversalIDECollector.parse_hook_payload(
        {
            "composerId": "c1",
            "mcpServer": "fs",
            "toolName": "edit_file",
            "parameters": {"relativeWorkspacePath": "src/main.py"},
        }
    )
    ev_cursor = cursor_norm.to_storage_event(session_id="sess_ide")
    assert ev_cursor.agent_id == "cursor"
    assert ev_cursor.event_type == EventType.FILE_MODIFY
    assert ev_cursor.source_path == "src/main.py"

    ag_norm = UniversalIDECollector.parse_hook_payload(
        {"tool": "execute_bash", "args": {"command": "pytest -q"}}
    )
    ev_ag = ag_norm.to_storage_event(session_id="sess_ide")
    assert ev_ag.agent_id == "antigravity"
    assert ev_ag.event_type == EventType.CMD_EXECUTE
