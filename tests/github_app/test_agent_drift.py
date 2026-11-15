"""Tests for Agent-Misbehavior Drift Detection and PR Risk Scoring."""

from __future__ import annotations

import pytest

from agentblackbox.github_app.agent_drift import AgentMisbehaviorScanner
from agentblackbox.models.finding import Severity


def test_detect_deleted_test_file() -> None:
    scanner = AgentMisbehaviorScanner()
    diff = (
        "diff --git a/tests/test_auth.py b/tests/test_auth.py\n"
        "deleted file mode 100644\n"
        "--- a/tests/test_auth.py\n"
        "+++ /dev/null\n"
        "@@ -1,5 +0,0 @@\n"
        "-def test_login():\n"
        "-    assert True\n"
    )
    findings, risk = scanner.scan_diff(diff)

    assert any(f.rule_id == "DRIFT-TEST-FILE-DELETED" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert risk.total_score >= 5.0
    assert any(f["factor"] == "test_file_deleted" for f in risk.factors)


def test_detect_deleted_assertions_in_test() -> None:
    scanner = AgentMisbehaviorScanner()
    diff = (
        "diff --git a/tests/test_payment.py b/tests/test_payment.py\n"
        "--- a/tests/test_payment.py\n"
        "+++ b/tests/test_payment.py\n"
        "@@ -10,6 +10,2 @@\n"
        " def test_charge():\n"
        "-    assert balance == 100\n"
        "-    assert charge.status == 'ok'\n"
        "+    pass\n"
    )
    findings, risk = scanner.scan_diff(diff)

    assert any(f.rule_id == "DRIFT-ASSERT-DELETED" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any(f["factor"] == "asserts_deleted" for f in risk.factors)


def test_detect_weakened_test_with_skip_marker() -> None:
    scanner = AgentMisbehaviorScanner()
    diff = (
        "diff --git a/tests/test_orders.py b/tests/test_orders.py\n"
        "--- a/tests/test_orders.py\n"
        "+++ b/tests/test_orders.py\n"
        "@@ -1,3 +1,4 @@\n"
        "+@pytest.mark.skip(reason='temporarily skipped by agent')\n"
        " def test_checkout():\n"
        "     assert False\n"
    )
    findings, risk = scanner.scan_diff(diff)

    assert any(f.rule_id == "DRIFT-TEST-WEAKENED" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_detect_linter_suppression() -> None:
    scanner = AgentMisbehaviorScanner()
    diff = (
        "diff --git a/src/service.py b/src/service.py\n"
        "--- a/src/service.py\n"
        "+++ b/src/service.py\n"
        "@@ -20,3 +20,3 @@\n"
        "-def process(data: dict) -> bool:\n"
        "+def process(data) -> bool:  # type: ignore\n"
    )
    findings, risk = scanner.scan_diff(diff)

    assert any(f.rule_id == "DRIFT-LINTER-SUPPRESSION" for f in findings)


def test_detect_ci_workflow_modification() -> None:
    scanner = AgentMisbehaviorScanner()
    diff = (
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
        "--- a/.github/workflows/ci.yml\n"
        "+++ b/.github/workflows/ci.yml\n"
        "@@ -15,3 +15,2 @@\n"
        "-    - run: pytest\n"
    )
    findings, risk = scanner.scan_diff(diff)

    assert any(f.rule_id == "DRIFT-CI-WORKFLOW-ALTERED" for f in findings)
    assert risk.total_score >= 4.0
