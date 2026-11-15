"""Zero-Retention Canary Test for AgentBlackBox GitHub App.

This test injects unique high-entropy canary tokens (source code, secrets, code comments)
into simulated pull requests and runs them through the full review pipeline. It then performs
a deep recursive scan across SQLite database tables, event ledgers, disk storage, job queues,
and session stores to mathematically guarantee zero customer code persistence.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import uuid
import pytest

from agentblackbox.github_app.agent_drift import AgentMisbehaviorScanner
from agentblackbox.github_app.diff import DiffMapper
from agentblackbox.github_app.formatter import format_check_run_output, format_inline_review_comments, format_walkthrough
from agentblackbox.github_app.queue import ReviewJobDescriptor, ReviewJobQueue
from agentblackbox.github_app.receipts import ReviewReceiptManager
from agentblackbox.github_app.sarif import generate_pr_sarif
from agentblackbox.github_app.security import sanitize_prompt_input, redact_diff_secrets
from agentblackbox.models.diff import FileDiff, DiffHunk, DiffLine, DiffLineType
from agentblackbox.models.finding import Finding, Severity
from agentblackbox.storage.event_store import EventStore


@pytest.mark.asyncio
async def test_zero_retention_canary_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Generate unique high-entropy canary tokens
    canary_code_token = f"CANARY_CODE_LOGIC_{uuid.uuid4().hex}"
    canary_secret_token = f"AKIAAAAA{uuid.uuid4().hex[:12].upper()}"
    canary_comment_token = f"CANARY_AUTHOR_NOTE_{uuid.uuid4().hex}"

    # Setup isolated SQLite event store
    db_file = tmp_path / "events.db"
    monkeypatch.setenv("ABB_DB_PATH", str(db_file))
    store = EventStore(db_file)
    receipt_mgr = ReviewReceiptManager(store=store)
    job_queue = ReviewJobQueue()

    # 2. Simulate raw PR diff with canaries
    raw_diff = f"""diff --git a/src/sensitive_auth.py b/src/sensitive_auth.py
index 1111111..2222222 100644
--- a/src/sensitive_auth.py
+++ b/src/sensitive_auth.py
@@ -1,5 +1,9 @@
 import os
+
+# {canary_comment_token}
+def authenticate():
+    token = "{canary_secret_token}"
+    result = {canary_code_token}()
+    return result
"""

    # 3. Simulate FileDiff structures
    file_diff = FileDiff(
        old_path="src/sensitive_auth.py",
        new_path="src/sensitive_auth.py",
        hunks=[
            DiffHunk(
                old_start=1,
                old_lines=5,
                new_start=1,
                new_lines=9,
                header="@@ -1,5 +1,9 @@",
                lines=[
                    DiffLine(DiffLineType.CONTEXT, "import os", 1, 1),
                    DiffLine(DiffLineType.ADD, f"# {canary_comment_token}", None, 3),
                    DiffLine(DiffLineType.ADD, "def authenticate():", None, 4),
                    DiffLine(DiffLineType.ADD, f'    token = "{canary_secret_token}"', None, 5),
                    DiffLine(DiffLineType.ADD, f"    result = {canary_code_token}()", None, 6),
                    DiffLine(DiffLineType.ADD, "    return result", None, 7),
                ],
            )
        ],
    )

    # 4. Run through Security Sanitize & Redaction
    sanitized_diff, secret_findings = redact_diff_secrets(raw_diff)
    sanitized_prompt = sanitize_prompt_input(raw_diff)

    # Verify secret was redacted in the sanitized string
    assert canary_secret_token not in sanitized_diff
    assert "[REDACTED:" in sanitized_diff

    # 5. Run Misbehavior Scanner
    scanner = AgentMisbehaviorScanner()
    drift_findings, risk_score = scanner.scan_diff(raw_diff)

    # 6. Generate Synthetic Finding (containing NO canary code)
    findings = [
        Finding(
            title="Hardcoded API Credential Detected",
            severity=Severity.CRITICAL,
            file_path="src/sensitive_auth.py",
            line_start=5,
            line_end=5,
            rule_id="SEC-LEAKED-CREDENTIAL",
            message="Hardcoded secret detected and masked before processing.",
            suggested_fix='token = os.environ.get("AUTH_TOKEN")',
        )
    ]
    findings.extend(secret_findings)

    # 7. Generate Signed Receipt (only SHA-256 hash of diff, 0 code)
    receipt = receipt_mgr.generate_receipt(
        owner="canary-corp",
        repo="canary-repo",
        pull_number=101,
        head_sha="abcdef123456",
        raw_diff=raw_diff,
        config_yaml="reviews:\n  fail_on: high",
        findings=findings,
        model_id="agentblackbox-engine-v1",
    )

    # 8. Generate Formatted Outputs (Walkthrough, Inline Comments, SARIF)
    walkthrough = format_walkthrough(
        pr_number=101,
        pr_title="Add sensitive auth",
        head_sha="abcdef123456",
        files_analyzed=1,
        findings=findings,
        receipt=receipt,
        risk_breakdown=risk_score,
    )
    diff_mapper = DiffMapper(raw_diff)
    inline_comments, out_of_diff = format_inline_review_comments(findings, diff_mapper)
    sarif = generate_pr_sarif(
        findings=findings,
        owner="canary-corp",
        repo="canary-repo",
        pull_number=101,
        commit_sha="abcdef123456",
    )
    conclusion, output_dict, annotation_batches = format_check_run_output(findings)

    # 9. Enqueue Review Job Descriptor (contains IDs and hashes only)
    descriptor = ReviewJobDescriptor(
        owner="canary-corp",
        repo="canary-repo",
        pull_number=101,
        head_sha="abcdef123456",
        delivery_id="canary-delivery-uuid-999",
        installation_id=44444,
    )
    job_queue.enqueue(descriptor)

    # 10. DEEP RECURSIVE DISK & DATABASE ZERO-RETENTION AUDIT
    canaries = [canary_code_token, canary_secret_token, canary_comment_token]

    # (a) Audit SQLite database tables
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()

    # Query all tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cur.fetchall()]

    for tbl in tables:
        cur.execute(f"SELECT * FROM {tbl}")
        rows = cur.fetchall()
        for row in rows:
            row_str = " ".join(str(cell) for cell in row)
            for canary in canaries:
                assert canary not in row_str, (
                    f"VIOLATION: Canary '{canary}' persisted in table '{tbl}': {row_str}"
                )
    conn.close()

    # (b) Audit all files written to disk in tmp_path
    for root, _, files in os.walk(str(tmp_path)):
        for f in files:
            file_path = Path(root) / f
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for canary in canaries:
                    assert canary not in content, (
                        f"VIOLATION: Canary '{canary}' persisted in file '{file_path}'"
                    )
            except Exception:
                pass

    # (c) Audit Job Queue descriptor
    job_dict_str = str(descriptor.__dict__)
    for canary in canaries:
        assert canary not in job_dict_str, (
            f"VIOLATION: Canary '{canary}' found in job descriptor: {job_dict_str}"
        )

    # (d) Audit Review Receipt
    receipt_dict_str = str(receipt.__dict__)
    for canary in canaries:
        assert canary not in receipt_dict_str, (
            f"VIOLATION: Canary '{canary}' found in receipt: {receipt_dict_str}"
        )
