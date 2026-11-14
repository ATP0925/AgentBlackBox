"""Comprehensive Enterprise Feature Suite Tests (v0.4.0).

Tests covering:
- Context-Aware Compliance Tracking (SOC2, OWASP-LLM06, GDPR, MIT-LICENSE-GUARD)
- Real-Time Architectural Drift Detection (Layer boundaries, AST signature contracts, Complexity)
- Legacy Refactoring Guard (Snapshots, blast radius, behavioral equivalence, rollbacks)
- SARIF v2.1.0 Export (Schema compliance, driver rules, finding mapping)
- CI/CD Cryptographic Gate CLI (`abb ci-gate` clean and failure modes)
- IDE Bridge FastAPI Endpoints (`/api/v1/status`, `/api/v1/analyze-edit`, `/api/v1/rollback`)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agentblackbox.analysis.compliance_tracker import ComplianceTracker, ComplianceFinding
from agentblackbox.analysis.drift_detector import ArchitecturalDriftDetector, DriftViolation
from agentblackbox.analysis.refactor_guard import LegacyRefactorGuard
from agentblackbox.api.main import app
from agentblackbox.cli.main import app as cli_app
from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.export import export_sarif
from agentblackbox.storage.models import Event, EventType, Session, Severity


@pytest.fixture(autouse=True)
def enable_ephemeral_test_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABB_EPHEMERAL_TEST_KEY", "1")
    monkeypatch.delenv("ABB_API_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def isolate_bridge_storage(tmp_path: Path) -> Any:
    db_file = tmp_path / "test_events.db"
    blobs_folder = tmp_path / "test_blobs"
    app.state.event_store = EventStore(db_file)
    app.state.blob_store = BlobStore(blobs_folder)
    yield
    app.state.event_store = None
    app.state.blob_store = None


# ==============================================================================
# 1. COMPLIANCE TRACKER TESTS
# ==============================================================================

def test_compliance_detects_verify_false() -> None:
    tracker = ComplianceTracker()
    code = (
        "import requests\n"
        "resp = requests.get('https://insecure.internal', verify=False)\n"
    )
    findings = tracker.check_content(code, file_path="api_client.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-NO-VERIFY" in rule_ids
    assert any(f.framework == "OWASP-LLM06" for f in findings)


def test_compliance_detects_shell_true() -> None:
    tracker = ComplianceTracker()
    code = (
        "import subprocess\n"
        "subprocess.run('rm -rf /tmp/test', shell=True)\n"
    )
    findings = tracker.check_content(code, file_path="worker.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-SHELL-TRUE" in rule_ids


def test_compliance_detects_eval_exec() -> None:
    tracker = ComplianceTracker()
    code = (
        "user_input = get_input()\n"
        "eval(user_input)\n"
    )
    findings = tracker.check_content(code, file_path="handler.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-DYN-EXEC" in rule_ids


def test_compliance_detects_sql_interpolation() -> None:
    tracker = ComplianceTracker()
    code = (
        "cursor = db.cursor()\n"
        "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
    )
    findings = tracker.check_content(code, file_path="db.py")
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-SQL-INJECT" in rule_ids


def test_compliance_detects_hardcoded_secrets() -> None:
    tracker = ComplianceTracker()
    code = (
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    )
    findings = tracker.check_content(code, file_path="config.py")
    assert any(f.rule_id == "SOC2-CC6.1" for f in findings)


def test_compliance_detects_ssn_pii() -> None:
    tracker = ComplianceTracker()
    text = "User test SSN is 123-45-6789 in prompt fixture"
    findings = tracker.check_content(text, file_path="fixture.txt")
    assert any(f.rule_id == "GDPR-PII-01" for f in findings)


def test_compliance_detects_restrictive_license_drift() -> None:
    tracker = ComplianceTracker()
    content = '[project]\nname = "test"\nlicense = "gpl-3.0"\n'
    findings = tracker.check_content(content, file_path="pyproject.toml")
    assert any(f.rule_id == "MIT-LICENSE-GUARD" for f in findings)


def test_compliance_binds_chain_hash_proof() -> None:
    tracker = ComplianceTracker()
    event = Event(
        session_id="sess_compliance",
        event_type=EventType.FILE_MODIFY,
        source_path="src/client.py",
        event_hash="abc123sha256proof",
        payload={"content": "requests.get(url, verify=False)"},
    )
    findings = tracker.check_event(event)
    assert len(findings) > 0
    assert findings[0].chain_hash_proof == "abc123sha256proof"


# ==============================================================================
# 2. ARCHITECTURAL DRIFT DETECTOR TESTS
# ==============================================================================

def test_drift_layer_isolation_storage_cannot_import_cli() -> None:
    detector = ArchitecturalDriftDetector()
    code = (
        "from agentblackbox.cli.main import app\n"
        "def query():\n"
        "    return 42\n"
    )
    violations = detector.check_file("src/agentblackbox/storage/query.py", content=code)
    rule_codes = [v.rule_code for v in violations]
    assert "DRIFT-LAYER-STORAGE" in rule_codes


def test_drift_layer_isolation_analysis_cannot_import_daemon() -> None:
    detector = ArchitecturalDriftDetector()
    code = (
        "from agentblackbox.daemon.core import BlackBoxDaemon\n"
    )
    violations = detector.check_file("src/agentblackbox/analysis/pure.py", content=code)
    rule_codes = [v.rule_code for v in violations]
    assert "DRIFT-LAYER-ANALYSIS" in rule_codes


def test_drift_detects_breaking_public_signature_removal() -> None:
    detector = ArchitecturalDriftDetector()
    old_code = "def process_data(data: bytes) -> str:\n    return 'ok'\n"
    new_code = "# function removed entirely\n"
    violations = detector.check_file("service.py", content=new_code, prev_content=old_code)
    assert any(v.rule_code == "DRIFT-SIG-REMOVED" for v in violations)


def test_drift_detects_breaking_signature_added_required_param() -> None:
    detector = ArchitecturalDriftDetector()
    old_code = "def authenticate(username: str) -> bool:\n    return True\n"
    new_code = "def authenticate(username: str, required_secret_token: str) -> bool:\n    return True\n"
    violations = detector.check_file("auth.py", content=new_code, prev_content=old_code)
    assert any(v.rule_code == "DRIFT-SIG-BREAK" for v in violations)


def test_drift_detects_removed_dunder_all_export() -> None:
    detector = ArchitecturalDriftDetector()
    old_code = "__all__ = ['PublicApi', 'Helper']\n"
    new_code = "__all__ = ['PublicApi']\n"
    violations = detector.check_file("init.py", content=new_code, prev_content=old_code)
    assert any(v.rule_code == "DRIFT-ALL-REMOVED" for v in violations)


def test_drift_detects_cyclomatic_complexity_violation() -> None:
    custom_cfg = {"max_cyclomatic_complexity": 3}
    detector = ArchitecturalDriftDetector()
    detector.config = custom_cfg

    complex_func = (
        "def complex_flow(x, y):\n"
        "    if x > 1:\n"
        "        if y > 2:\n"
        "            while x > 0:\n"
        "                for i in range(10):\n"
        "                    pass\n"
    )
    violations = detector.check_file("flow.py", content=complex_func)
    assert any(v.rule_code == "DRIFT-CYCLOMATIC" for v in violations)


# ==============================================================================
# 3. LEGACY REFACTOR GUARD TESTS
# ==============================================================================

def test_refactor_guard_snapshot_creation(tmp_path: Path) -> None:
    blobs_dir = tmp_path / "blobs"
    bs = BlobStore(blobs_dir)
    guard = LegacyRefactorGuard(blob_store=bs, workspace_root=tmp_path)

    test_file = tmp_path / "legacy.py"
    test_file.write_text("def legacy_calculator(a, b):\n    return a * b\n", encoding="utf-8")

    sha, meta = guard.create_pre_refactor_snapshot(test_file)
    assert len(sha) == 64
    assert "legacy_calculator" in meta["symbols"]
    assert bs.exists(sha)


def test_refactor_guard_blast_radius_calculation(tmp_path: Path) -> None:
    blobs_dir = tmp_path / "blobs"
    bs = BlobStore(blobs_dir)
    guard = LegacyRefactorGuard(blob_store=bs, workspace_root=tmp_path)

    mod_a = tmp_path / "mod_a.py"
    mod_a.write_text("def shared_worker():\n    return 'done'\n", encoding="utf-8")

    caller = tmp_path / "caller.py"
    caller.write_text("import mod_a\nmod_a.shared_worker()\n", encoding="utf-8")

    blast = guard.calculate_blast_radius(mod_a, ["shared_worker"])
    assert blast["dependent_files_count"] == 1
    assert "caller.py" in blast["dependent_files"]


def test_refactor_guard_behavioral_equivalence_removed_exception() -> None:
    blobs_dir = Path(tempfile.mkdtemp()) / "blobs"
    bs = BlobStore(blobs_dir)
    guard = LegacyRefactorGuard(blob_store=bs)

    old_code = (
        "def fetch():\n"
        "    raise ValueError('error')\n"
    )
    new_code = (
        "def fetch():\n"
        "    return None\n"
    )
    res = guard.check_behavioral_equivalence(old_code, new_code)
    assert res["is_equivalent"] == False
    assert any("ValueError" in w for w in res["warnings"])


def test_refactor_guard_rollback_to_snapshot_restores_file(tmp_path: Path) -> None:
    blobs_dir = tmp_path / "blobs"
    db_path = tmp_path / "events.db"
    bs = BlobStore(blobs_dir)
    store = EventStore(db_path)
    store.create_session(Session(id="sess_rollback", name="Rollback Test", workspace_path=str(tmp_path)))

    guard = LegacyRefactorGuard(blob_store=bs, event_store=store, workspace_root=tmp_path)

    orig_content = "def perfect_logic():\n    return 100\n"
    target_file = tmp_path / "logic.py"
    target_file.write_text(orig_content, encoding="utf-8")

    sha, _ = guard.create_pre_refactor_snapshot(target_file, session_id="sess_rollback")

    # Agent breaks file
    target_file.write_text("# broken by agent", encoding="utf-8")
    assert target_file.read_text() == "# broken by agent"

    # Deterministic rollback
    success = guard.rollback_to_snapshot(target_file, sha, session_id="sess_rollback")
    assert success == True
    assert target_file.read_text(encoding="utf-8") == orig_content

    # Verify REFACTOR_ROLLBACK event was signed into EventStore
    events = store.query_events(session_id="sess_rollback")
    rollback_events = [e for e in events if e.event_type == EventType.REFACTOR_ROLLBACK]
    assert len(rollback_events) == 1
    assert rollback_events[0].blob_hash == sha
    store.close()


# ==============================================================================
# 4. SARIF V2.1.0 EXPORT TESTS
# ==============================================================================

def test_export_sarif_valid_v210_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "sarif_test.db"
    store = EventStore(db_path)
    store.create_session(Session(id="sess_sarif", name="SARIF Session", workspace_path=str(tmp_path)))

    store.record_event(Event(
        session_id="sess_sarif",
        event_type=EventType.SECRET_DETECTED,
        risk_score=9.0,
        source_path="src/credentials.py",
        payload={
            "secret_matches": [{"pattern_name": "API_KEY", "line_number": 12}],
            "compliance_findings": [{"rule_id": "SOC2-CC6.1", "severity": "critical", "description": "Leaked key"}],
            "drift_violations": [{"rule_code": "DRIFT-LAYER", "description": "Forbidden import"}],
        }
    ))

    sarif_file = tmp_path / "results.sarif"
    sarif = export_sarif(store, session_id="sess_sarif", output_path=sarif_file)
    store.close()

    assert sarif["version"] == "2.1.0"
    assert "https://json.schemastore.org/sarif-2.1.0.json" in sarif["$schema"]
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgentBlackBox"
    assert len(sarif["runs"][0]["results"]) >= 3
    assert sarif_file.exists()


# ==============================================================================
# 5. CLI CI-GATE COMMAND TESTS
# ==============================================================================

def test_ci_gate_cli_clean_session_passes_exit_0(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / ".agentblackbox" / "events.db"
    db_path.parent.mkdir(parents=True)
    store = EventStore(db_path)
    store.create_session(Session(id="clean_sess", name="Clean", workspace_path=str(tmp_path)))
    store.record_event(Event(
        session_id="clean_sess",
        event_type=EventType.FILE_MODIFY,
        risk_score=1.0,
        payload={"action": "clean_edit"}
    ))
    store.close()

    result = runner.invoke(cli_app, ["ci-gate", "--workspace", str(tmp_path), "--session", "clean_sess"])
    assert result.exit_code == 0
    assert "CI GATE APPROVED" in result.output


def test_ci_gate_cli_tampered_chain_fails_exit_1(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / ".agentblackbox" / "events.db"
    db_path.parent.mkdir(parents=True)
    store = EventStore(db_path)
    store.create_session(Session(id="tampered_sess", name="Tampered", workspace_path=str(tmp_path)))
    store.record_event(Event(
        session_id="tampered_sess",
        event_type=EventType.CMD_EXECUTE,
        risk_score=2.0,
        payload={"command": "ls"}
    ))
    store.close()

    # Tamper with the SQLite database row directly
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE events SET payload_hash = 'corrupted_hash' WHERE session_id = 'tampered_sess'")
    conn.commit()
    conn.close()

    result = runner.invoke(cli_app, ["ci-gate", "--workspace", str(tmp_path), "--session", "tampered_sess"])
    assert result.exit_code == 1
    assert "CI GATE REJECTED" in result.output


def test_ci_gate_cli_high_risk_event_fails_exit_1(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / ".agentblackbox" / "events.db"
    db_path.parent.mkdir(parents=True)
    store = EventStore(db_path)
    store.create_session(Session(id="risky_sess", name="Risky", workspace_path=str(tmp_path)))
    store.record_event(Event(
        session_id="risky_sess",
        event_type=EventType.CMD_EXECUTE,
        risk_score=9.5,
        payload={"command": "rm -rf / --no-preserve-root"}
    ))
    store.close()

    result = runner.invoke(cli_app, ["ci-gate", "--workspace", str(tmp_path), "--session", "risky_sess", "--max-risk", "7.0"])
    assert result.exit_code == 1
    assert "exceeds maximum threshold" in result.output


# ==============================================================================
# 6. FASTAPI IDE BRIDGE ENDPOINT TESTS
# ==============================================================================

def test_ide_bridge_status_endpoint() -> None:
    client = TestClient(app)
    resp = client.get("/api/v1/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert "chain_intact" in data
    assert "version" in data


def test_ide_bridge_analyze_edit_endpoint(tmp_path: Path) -> None:
    client = TestClient(app)
    payload = {
        "file_path": "src/service.py",
        "content": "import subprocess\nsubprocess.run('ls', shell=True)\n",
        "agent_name": "antigravity",
        "prompt_summary": "Execute listing command"
    }
    resp = client.post("/api/v1/analyze-edit", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "snapshot_sha256" in data
    assert data["risk_score"] >= 7.0
    assert len(data["compliance_findings"]) > 0


def test_ide_bridge_rollback_endpoint(tmp_path: Path) -> None:
    client = TestClient(app)
    # First analyze edit to get a snapshot SHA
    target_file = tmp_path / "rollback_target.py"
    target_file.write_text("def stable_version(): return 42\n", encoding="utf-8")

    analyze_resp = client.post("/api/v1/analyze-edit", json={
        "file_path": str(target_file),
        "content": "def stable_version(): return 42\n",
        "agent_name": "test-agent"
    })
    assert analyze_resp.status_code == 200
    snapshot_sha = analyze_resp.json()["snapshot_sha256"]

    # Now corrupt file
    target_file.write_text("# corrupted", encoding="utf-8")

    # Request rollback via API
    rollback_resp = client.post("/api/v1/rollback", json={
        "file_path": str(target_file),
        "snapshot_sha256": snapshot_sha
    })
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["success"] == True
    assert "def stable_version" in target_file.read_text(encoding="utf-8")
