"""Tests for CLI verify and export-checkpoint commands."""

import json
from pathlib import Path
from typer.testing import CliRunner

from agentblackbox.cli.main import app
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session

runner = CliRunner()


def test_cli_export_checkpoint_and_verify(tmp_path: Path) -> None:
    db_path = tmp_path / ".agentblackbox" / "blackbox.db"
    store = EventStore(db_path)
    sess = Session(workspace_path=str(tmp_path))
    store.create_session(sess)
    store.insert_event(Event(
        session_id=sess.id,
        event_type=EventType.CMD_EXECUTE,
        payload={"cmd": "git status"},
    ))

    # Test export-checkpoint to stdout
    result = runner.invoke(app, ["export-checkpoint", sess.id, "-w", str(tmp_path)])
    assert result.exit_code == 0
    cp = json.loads(result.stdout)
    assert cp["session_id"] == sess.id
    assert cp["last_seq"] == 1

    # Test export-checkpoint to file
    out_file = tmp_path / "custom.tip"
    res_file = runner.invoke(
        app,
        ["export-checkpoint", sess.id, "-o", str(out_file), "-w", str(tmp_path)],
    )
    assert res_file.exit_code == 0
    assert out_file.exists()

    # Test verify with --checkpoint
    res_verify = runner.invoke(
        app,
        ["verify", sess.id, "--checkpoint", str(out_file), "-w", str(tmp_path)],
    )
    assert res_verify.exit_code == 0
    assert "Chain INTACT" in res_verify.stdout

    # Test verify with --require-checkpoint and missing checkpoint file
    missing_cp = tmp_path / "nonexistent.tip"
    res_missing = runner.invoke(
        app,
        ["verify", sess.id, "--checkpoint", str(missing_cp), "--require-checkpoint", "-w", str(tmp_path)],
    )
    assert res_missing.exit_code == 1
    assert "BROKEN" in res_missing.stdout or "checkpoint required" in res_missing.stdout.lower()

