"""Tests for Cryptographic Signed Review Receipts and Offline Verification."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typer.testing import CliRunner
import pytest

from agentblackbox.cli.main import app as cli_app
from agentblackbox.github_app.receipts import ReviewReceipt, ReviewReceiptManager
from agentblackbox.models.finding import Finding, Severity

runner = CliRunner()


@pytest.fixture
def temp_receipt_manager(tmp_path: Path) -> ReviewReceiptManager:
    db_file = tmp_path / "test_events.db"
    return ReviewReceiptManager(db_path=db_file)


def test_generate_and_verify_signed_receipt(temp_receipt_manager: ReviewReceiptManager) -> None:
    findings = [
        Finding(
            title="Insecure eval usage",
            severity=Severity.HIGH,
            file_path="src/calc.py",
            line_start=10,
            line_end=10,
            rule_id="SEC-DYN-EXEC",
        ),
        Finding(
            title="Exposed test token",
            severity=Severity.CRITICAL,
            file_path="src/config.py",
            line_start=5,
            line_end=5,
            rule_id="SEC-001-SECRET-LEAK",
        ),
    ]

    receipt = temp_receipt_manager.generate_receipt(
        owner="acme",
        repo="anvil",
        pull_number=101,
        head_sha="a1b2c3d4e5f6",
        raw_diff="diff --git a/src/calc.py b/src/calc.py\n+eval(x)",
        config_yaml="reviews:\n  enabled: true",
        findings=findings,
    )

    assert receipt.receipt_id.startswith("abb-rcpt-")
    assert receipt.owner == "acme"
    assert receipt.repo == "anvil"
    assert receipt.pull_number == 101
    assert receipt.head_sha == "a1b2c3d4e5f6"
    assert receipt.total_findings == 2
    assert receipt.critical_count == 1
    assert receipt.high_count == 1
    assert len(receipt.diff_hash) == 64
    assert len(receipt.chain_tip_hash) > 0

    # Verify receipt cryptographically
    is_valid, verified_rcpt, msg = temp_receipt_manager.verify_receipt(receipt.receipt_id)
    assert is_valid is True
    assert verified_rcpt is not None
    assert verified_rcpt.receipt_id == receipt.receipt_id
    assert "verified" in msg.lower()


def test_verify_receipt_tampered_event_chain(temp_receipt_manager: ReviewReceiptManager) -> None:
    findings = [Finding(title="Test", severity=Severity.MEDIUM, file_path="app.py", line_start=1, line_end=1)]
    receipt = temp_receipt_manager.generate_receipt(
        owner="test-org",
        repo="test-repo",
        pull_number=42,
        head_sha="deadbeef",
        raw_diff="diff --git a/app.py b/app.py\n+x = 1",
        config_yaml="",
        findings=findings,
    )

    # Deliberately tamper with the event in SQLite
    import sqlite3
    conn = sqlite3.connect(str(temp_receipt_manager.db_path))
    cur = conn.cursor()
    cur.execute(
        "UPDATE events SET payload = ? WHERE session_id = ?",
        ('{"receipt_id": "' + receipt.receipt_id + '", "tampered": true}', receipt.session_id),
    )
    conn.commit()
    conn.close()

    # Verification must catch the tampering
    is_valid, verified_rcpt, msg = temp_receipt_manager.verify_receipt(receipt.receipt_id)
    assert is_valid is False
    assert "TAMPER" in msg or "broken" in msg.lower()


def test_cli_verify_receipt_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "test_events.db"
    monkeypatch.setenv("ABB_DB_PATH", str(db_file))

    mgr = ReviewReceiptManager(db_path=db_file)
    receipt = mgr.generate_receipt(
        owner="cli-owner",
        repo="cli-repo",
        pull_number=7,
        head_sha="11223344",
        raw_diff="diff --git a/main.py b/main.py\n+pass",
        config_yaml="",
        findings=[],
    )

    # CLI command: abb verify-receipt <id> -w <workspace>
    res = runner.invoke(cli_app, ["verify-receipt", receipt.receipt_id, "--workspace", str(tmp_path)])
    assert res.exit_code == 0
    assert "Cryptographic Receipt Verified" in res.output
    assert receipt.receipt_id in res.output
    assert "cli-owner/cli-repo" in res.output
