"""End-to-end tests for live background BlackBoxDaemon."""

import time
from pathlib import Path

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.daemon.core import (
    get_daemon_state,
    is_pid_alive,
    start_background_daemon,
    stop_background_daemon,
)
from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import EventType


class TestBackgroundDaemon:
    """Test real detached background daemon start/record/stop lifecycle."""

    def test_background_daemon_records_and_stops_cleanly(self, tmp_path: Path) -> None:
        ws = tmp_path / "workspace"
        ws.mkdir()
        config = BlackBoxConfig(workspace_path=ws, debounce_ms=100)

        state = start_background_daemon(config, name="e2e-daemon", agent_hint="claude-code", timeout=8.0)
        assert is_pid_alive(state.pid)
        assert get_daemon_state(config) is not None

        raw_secret = "AKIA" + "IOSFODNN7EXAMPLE"
        store = EventStore(config.db_path)
        try:
            (ws / "secret_cfg.py").write_text(f'AWS="{raw_secret}"\n', encoding="utf-8")
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                evts = store.query_events(session_id=state.session_id)
                if any(e.event_type == EventType.FILE_CREATE and e.blob_hash for e in evts):
                    break
                time.sleep(0.1)
        finally:
            stopped = stop_background_daemon(config, timeout=6.0)

        assert stopped is not None
        assert stopped.session_id == state.session_id
        assert get_daemon_state(config) is None

        sess = store.get_session(state.session_id)
        assert sess is not None
        assert sess.status == "stopped"

        evts = store.query_events(session_id=state.session_id)
        created = [e for e in evts if e.event_type == EventType.FILE_CREATE and e.blob_hash]
        assert len(created) >= 1
        assert created[0].agent_id == "claude-code"

        blobs = BlobStore(config.blobs_dir)
        blob_text = blobs.get_text(created[0].blob_hash)
        assert blob_text is not None
        assert raw_secret not in blob_text
        assert "[REDACTED:aws_access_key]" in blob_text

        alerts = store.get_alerts(session_id=state.session_id)
        assert len(alerts) >= 1
        assert store.verify_chain(state.session_id).valid is True

