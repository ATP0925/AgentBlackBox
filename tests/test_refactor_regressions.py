"""Regression tests verifying refactored components across AgentBlackBox."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agentblackbox.analysis.risk_scorer import score_command_tokens
from agentblackbox.analysis.secret_detector import find_high_entropy_tokens
from agentblackbox.daemon.core import is_pid_alive
from agentblackbox.storage.event_store import EventStore


def test_shlex_risk_scorer_ignores_echo_and_flags_real_rm() -> None:
    benign_score, benign_reasons = score_command_tokens('echo "never run rm -rf /"')
    assert benign_score < 5.0
    assert "destructive_delete:rm_rf" not in benign_reasons
    danger_score, danger_reasons = score_command_tokens("sudo rm -rf /var/tmp/cache")
    assert danger_score >= 8.0
    assert "destructive_delete:rm_rf" in danger_reasons
    assert "privilege_escalation:sudo" in danger_reasons


def test_tokenized_entropy_detector_skips_git_sha_and_catches_secrets() -> None:
    git_sha_log = "commit 0a61078b9c1234567890abcdef1234567890abcd Author: dev"
    assert find_high_entropy_tokens(git_sha_log) == []
    prefix = "sk_" + "live_"
    secret_log = f"export STRIPE_KEY={prefix}9f8a7B6c5D4e3F2g1H0jKlMnOpQrStUvWxYz"
    hits = find_high_entropy_tokens(secret_log, entropy_threshold=4.1)
    assert len(hits) >= 1


def test_sqlite_wal_concurrent_writes_do_not_lock(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    try:
        def _worker(idx: int) -> int:
            with store._connection(write=True) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS t_ping (id INTEGER)")
                conn.execute("INSERT INTO t_ping (id) VALUES (?)", (idx,))
            return idx

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_worker, range(40)))
        assert len(results) == 40
    finally:
        store.close()


def test_stale_pid_guard_rejects_invalid_pid() -> None:
    assert is_pid_alive(-1) is False
    assert is_pid_alive(999_999_999) is False
