"""Unit and integration tests for AgentBlackBox Autonomous 1-Click Fix PR Generator."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from agentblackbox.github_app.autofix import AutoFixEngine, RemediationResult
from agentblackbox.github_app.client import GitHubClient
from agentblackbox.github_app.events import GitHubEventHandler
from agentblackbox.models.finding import Finding, Severity


def test_filter_safe_fixable_findings() -> None:
    client = MagicMock(spec=GitHubClient)
    engine = AutoFixEngine(client=client)

    f1 = Finding(
        title="Valid fixable issue",
        severity=Severity.HIGH,
        file_path="src/utils.py",
        line_start=10,
        line_end=10,
        rule_id="SEC-001",
        suggested_fix="safe_token = os.environ.get('TOKEN')",
    )
    f2 = Finding(
        title="Unfixable issue",
        severity=Severity.CRITICAL,
        file_path="src/auth.py",
        line_start=5,
        line_end=5,
        rule_id="ARCH-DRIFT",
        suggested_fix="",  # empty
    )
    f3 = Finding(
        title="Lockfile issue",
        severity=Severity.LOW,
        file_path="package-lock.json",
        line_start=1,
        line_end=1,
        rule_id="DEP-001",
        suggested_fix="{}",
    )

    fixable = engine.filter_safe_fixable_findings([f1, f2, f3])
    assert len(fixable) == 1
    assert fixable[0].rule_id == "SEC-001"


def test_apply_patches_to_content_descending() -> None:
    client = MagicMock(spec=GitHubClient)
    engine = AutoFixEngine(client=client)

    original_code = (
        "line 1\n"
        "line 2: bad code a\n"
        "line 3\n"
        "line 4: bad code b\n"
        "line 5\n"
    )

    f_line2 = Finding(
        title="Fix A",
        severity=Severity.MEDIUM,
        file_path="test.py",
        line_start=2,
        line_end=2,
        suggested_fix="line 2: fixed a",
    )
    f_line4 = Finding(
        title="Fix B",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=4,
        line_end=4,
        suggested_fix="line 4: fixed b",
    )

    # Even if provided in ascending order, engine must apply descending to preserve line offsets
    patched = engine.apply_patches_to_content(original_code, [f_line2, f_line4])
    assert "line 2: fixed a" in patched
    assert "line 4: fixed b" in patched
    assert "line 1" in patched
    assert "line 3" in patched
    assert "line 5" in patched


@pytest.mark.asyncio
async def test_create_remediation_pr_flow() -> None:
    client = MagicMock(spec=GitHubClient)
    client.create_branch = AsyncMock(return_value={"ref": "refs/heads/agentblackbox/autofix-pr-42"})
    client.get_file_metadata = AsyncMock(return_value={"sha": "blobsha123"})
    client.get_file_contents = AsyncMock(return_value="import os\ntoken = 'hardcoded'\n")
    client.update_file_contents = AsyncMock(return_value={"commit": {"sha": "newcommitsha"}})
    client.create_pull_request = AsyncMock(return_value={
        "number": 99,
        "html_url": "https://github.com/org/repo/pull/99",
    })

    engine = AutoFixEngine(client=client)

    finding = Finding(
        title="Hardcoded token",
        severity=Severity.CRITICAL,
        file_path="src/config.py",
        line_start=2,
        line_end=2,
        rule_id="SEC-SECRET",
        suggested_fix="token = os.environ.get('AUTH_TOKEN')",
    )

    result = await engine.create_remediation_pr(
        owner="test-org",
        repo="test-repo",
        pull_number=42,
        head_sha="head123456",
        head_branch="feature-branch",
        findings=[finding],
        installation_id=123,
    )

    assert result.success is True
    assert result.pr_number == 99
    assert result.pr_url == "https://github.com/org/repo/pull/99"
    assert result.applied_fixes_count == 1
    assert "src/config.py" in result.modified_files

    client.create_branch.assert_called_once()
    client.update_file_contents.assert_called_once()
    client.create_pull_request.assert_called_once()


@pytest.mark.asyncio
async def test_create_remediation_pr_no_fixable_findings() -> None:
    client = MagicMock(spec=GitHubClient)
    engine = AutoFixEngine(client=client)

    finding = Finding(
        title="Manual fix only",
        severity=Severity.CRITICAL,
        file_path="src/config.py",
        line_start=2,
        line_end=2,
        rule_id="MANUAL-REQ",
        suggested_fix="",  # None
    )

    result = await engine.create_remediation_pr(
        owner="test-org",
        repo="test-repo",
        pull_number=42,
        head_sha="head123456",
        head_branch="feature-branch",
        findings=[finding],
    )

    assert result.success is False
    assert result.applied_fixes_count == 0
    assert "No automated 1-click fixes" in result.message


@pytest.mark.asyncio
async def test_event_handler_issue_comment_fix_trigger() -> None:
    client = MagicMock(spec=GitHubClient)
    client.create_issue_comment = AsyncMock(return_value={"id": 1})
    client.get_pull_request = AsyncMock(return_value={
        "number": 10,
        "title": "Add feature",
        "head": {"sha": "sha_pr_10", "ref": "feat-branch"},
    })

    mock_autofix = MagicMock(spec=AutoFixEngine)
    mock_autofix.create_remediation_pr = AsyncMock(return_value=RemediationResult(
        success=True,
        branch_name="agentblackbox/autofix-pr-10-abc",
        pr_url="https://github.com/org/repo/pull/11",
        pr_number=11,
        applied_fixes_count=2,
        modified_files=["app.py"],
    ))

    handler = GitHubEventHandler(client=client, autofix_engine=mock_autofix)

    # Pre-populate findings in cache
    handler.latest_review_findings[("myorg", "myrepo", 10)] = [
        Finding(title="Fix 1", severity=Severity.HIGH, file_path="app.py", line_start=1, line_end=1, suggested_fix="safe()", rule_id="SEC-001"),
    ]

    payload = {
        "action": "created",
        "issue": {"number": 10, "pull_request": {}},
        "comment": {"body": "@agentblackbox fix"},
        "repository": {"name": "myrepo", "owner": {"login": "myorg"}},
        "installation": {"id": 999},
    }

    await handler.handle_issue_comment_event(payload)

    mock_autofix.create_remediation_pr.assert_called_once()
    client.create_issue_comment.assert_called_once()
    comment_body = client.create_issue_comment.call_args[1]["body"]
    assert "Automated Remediation PR Created!" in comment_body
    assert "https://github.com/org/repo/pull/11" in comment_body
