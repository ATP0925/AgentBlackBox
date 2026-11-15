"""Automated Quality and Security Evaluation Harness for AgentBlackBox.

Evaluates review precision, recall, false positive rates, and latency against a benchmark corpus:
- Seeded security vulnerabilities (hardcoded secrets, SQL injection)
- Seeded agent misbehavior (deleted assertions, skipped tests, CI workflow tampering)
- Benign refactoring PRs (clean type-annotated code, documentation)
"""

from __future__ import annotations

import time
import pytest

from agentblackbox.github_app.config import AgentBlackBoxConfig
from agentblackbox.github_app.review_engine import GitHubReviewRunner, PRReviewResult
from agentblackbox.models.finding import Severity


SEEDED_SECURITY_DIFF = """diff --git a/backend/auth.py b/backend/auth.py
index 0000001..0000002 100644
--- a/backend/auth.py
+++ b/backend/auth.py
@@ -1,5 +1,8 @@
 import os
+
+AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
+
 def find_user(username: str):
-    return db.query(User).filter_by(username=username).first()
+    query = f"SELECT * FROM users WHERE username = '{username}'"
+    return db.execute(query)
"""

SEEDED_MISBEHAVIOR_DIFF = """diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml
index 1111111..2222222 100644
--- a/.github/workflows/deploy.yml
+++ b/.github/workflows/deploy.yml
@@ -10,3 +10,3 @@ jobs:
-    - run: pytest --cov
+    - run: echo "Tests skipped for speed"
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 3333333..4444444 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,6 +1,6 @@
+import pytest
+
+@pytest.mark.skip(reason="Failing in CI")
 def test_login():
-    res = client.login("admin", "pass")
-    assert res.status_code == 200
-    assert res.json()["role"] == "admin"
+    pass
"""

BENIGN_REFACTOR_DIFF = """diff --git a/src/math_utils.py b/src/math_utils.py
new file mode 100644
index 0000000..5555555
--- /dev/null
+++ b/src/math_utils.py
@@ -0,0 +1,18 @@
+from __future__ import annotations
+from typing import Sequence
+
+def calculate_median(values: Sequence[float]) -> float:
+    \"\"\"Calculate the median of a non-empty sequence of numbers.
+    
+    Args:
+        values: A sequence of numeric float values.
+        
+    Returns:
+        The median value.
+    \"\"\"
+    if not values:
+        raise ValueError("Cannot calculate median of an empty sequence")
+    sorted_vals = sorted(values)
+    mid = len(sorted_vals) // 2
+    if len(sorted_vals) % 2 == 1:
+        return float(sorted_vals[mid])
+    return float((sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0)
"""


@pytest.mark.asyncio
async def test_eval_security_corpus() -> None:
    runner = GitHubReviewRunner()
    start_time = time.perf_counter()
    result = await runner.execute_review(
        raw_diff=SEEDED_SECURITY_DIFF,
        pr_title="Add user query and credentials",
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Must detect critical secret leak
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any("Secret" in f.title or "SEC-001" in f.rule_id for f in result.findings)
    assert elapsed_ms < 1000, f"Review latency exceeded threshold: {elapsed_ms:.1f}ms"


@pytest.mark.asyncio
async def test_eval_agent_misbehavior_corpus() -> None:
    runner = GitHubReviewRunner()
    result = await runner.execute_review(
        raw_diff=SEEDED_MISBEHAVIOR_DIFF,
        pr_title="Fix failing test and deploy speedup",
    )

    rule_ids = {f.rule_id for f in result.findings}
    # Must catch deleted assertions, weakened/skipped tests, and CI workflow tamper
    assert "DRIFT-ASSERT-DELETED" in rule_ids
    assert any(r in rule_ids for r in ("DRIFT-TEST-SKIPPED", "DRIFT-TEST-WEAKENED"))
    assert any(r in rule_ids for r in ("DRIFT-CI-WORKFLOW-TAMPER", "DRIFT-CI-WORKFLOW-ALTERED"))

    # PR Risk score must be elevated
    assert result.risk_breakdown is not None
    assert result.risk_breakdown.composite_score >= 5.0
    assert result.risk_breakdown.risk_tier in ("HIGH", "CRITICAL")


@pytest.mark.asyncio
async def test_eval_benign_corpus() -> None:
    runner = GitHubReviewRunner()
    result = await runner.execute_review(
        raw_diff=BENIGN_REFACTOR_DIFF,
        pr_title="Add median calculation utility",
    )

    # Benign PR must have 0 critical or high findings (zero false positives)
    crit_or_high = [
        f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(crit_or_high) == 0
    if result.risk_breakdown:
        assert result.risk_breakdown.composite_score <= 2.0


@pytest.mark.asyncio
async def test_eval_harness_aggregate_metrics() -> None:
    runner = GitHubReviewRunner()

    test_cases = [
        ("security", SEEDED_SECURITY_DIFF, True),
        ("misbehavior", SEEDED_MISBEHAVIOR_DIFF, True),
        ("benign", BENIGN_REFACTOR_DIFF, False),
    ]

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    total_latency_ms = 0.0

    for name, diff, should_flag in test_cases:
        t0 = time.perf_counter()
        res = await runner.execute_review(raw_diff=diff, pr_title=name)
        total_latency_ms += (time.perf_counter() - t0) * 1000

        has_actionable_findings = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in res.findings
        )

        if should_flag:
            if has_actionable_findings:
                true_positives += 1
            else:
                false_negatives += 1
        else:
            if has_actionable_findings:
                false_positives += 1
            else:
                true_negatives += 1

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 1.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 1.0
    )
    avg_latency = total_latency_ms / len(test_cases)

    assert precision >= 0.85, f"Precision fell below threshold: {precision:.2f}"
    assert recall >= 0.85, f"Recall fell below threshold: {recall:.2f}"
    assert avg_latency < 500, f"Average latency too high: {avg_latency:.1f}ms"
