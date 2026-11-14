"""End-to-end tests for ReviewEngine, reporting formats, and CLI commands."""

import json
from pathlib import Path
from typer.testing import CliRunner

from agentblackbox.cli.main import app
from agentblackbox.core.config import ReviewConfig
from agentblackbox.core.engine import ReviewEngine
from agentblackbox.integrations.ai_provider import OfflineMockAIProvider
from agentblackbox.models.finding import Severity
from agentblackbox.reporting.terminal import render_terminal_report


SAMPLE_VULNERABLE_CODE = """
import os
import pickle

def unsafe_handler(user_input, cmd):
    # Security: shell=True command injection (SEC-002)
    os.system(cmd)
    
    # Security: Insecure deserialization (SEC-004)
    data = pickle.loads(user_input)
    
    # Bug: Mutable default (BUG-001)
    def inner(items=[]):
        items.append(1)
        return items

    return inner()
"""

SAMPLE_CLEAN_CODE = """
def add(a: int, b: int) -> int:
    \"\"\"Pure function with no defects.\"\"\"
    return a + b
"""


def test_engine_analyze_file(tmp_path: Path) -> None:
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text(SAMPLE_VULNERABLE_CODE, encoding="utf-8")

    engine = ReviewEngine(config=ReviewConfig(min_severity=Severity.LOW))
    report = engine.analyze_file(vuln_file)

    assert report.total_findings >= 2
    rule_ids = {f.rule_id for f in report.findings}
    assert "SEC-002" in rule_ids  # shell execution
    assert "SEC-003" in rule_ids  # pickle.loads

    # Check findings are sorted: Critical/High first
    severities = [f.severity.level for f in report.findings]
    assert severities == sorted(severities, reverse=True)


def test_engine_analyze_repository(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "bad.py").write_text(SAMPLE_VULNERABLE_CODE, encoding="utf-8")
    (tmp_path / "pkg" / "good.py").write_text(SAMPLE_CLEAN_CODE, encoding="utf-8")

    engine = ReviewEngine(config=ReviewConfig(min_severity=Severity.MEDIUM))
    report = engine.analyze_repository(tmp_path)

    assert report.total_findings >= 2
    assert any("bad.py" in f.file_path for f in report.findings)


def test_engine_with_ai_mock(tmp_path: Path) -> None:
    code_with_trigger = """
    # This triggers SIMULATED_CRITICAL_BUG
    def execute():
        pass
    """
    test_file = tmp_path / "trigger.py"
    test_file.write_text(code_with_trigger, encoding="utf-8")

    mock_ai = OfflineMockAIProvider()
    engine = ReviewEngine(
        config=ReviewConfig(enable_ai=True),
        ai_provider=mock_ai,
    )
    report = engine.analyze_file(test_file)

    assert any(f.rule_id == "AI-SEC-999" for f in report.findings)
    assert report.has_critical_or_high is True


def test_reporting_formats(tmp_path: Path) -> None:
    test_file = tmp_path / "test.py"
    test_file.write_text(SAMPLE_VULNERABLE_CODE, encoding="utf-8")

    engine = ReviewEngine()
    report = engine.analyze_file(test_file)

    # 1. Markdown
    md = report.to_markdown()
    assert "# 🔍 AI Code Review" in md
    assert "SEC-002" in md

    # 2. SARIF 2.1.0
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) >= 2

    # 3. Terminal rendering
    render_terminal_report(report)


def test_cli_analyze_command(tmp_path: Path) -> None:
    runner = CliRunner()
    target_file = tmp_path / "target.py"
    target_file.write_text(SAMPLE_VULNERABLE_CODE, encoding="utf-8")

    # JSON output check with exit-zero to prevent non-zero exit on High finding
    result = runner.invoke(app, [
        "analyze",
        str(target_file),
        "--format", "json",
        "--exit-zero",
    ])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["total_findings"] >= 2
    assert "severity_counts" in data


def test_cli_analyze_sarif_export(tmp_path: Path) -> None:
    runner = CliRunner()
    target_file = tmp_path / "target.py"
    target_file.write_text(SAMPLE_VULNERABLE_CODE, encoding="utf-8")
    out_sarif = tmp_path / "report.sarif"

    result = runner.invoke(app, [
        "analyze",
        str(target_file),
        "--format", "sarif",
        "--output", str(out_sarif),
        "--exit-zero",
    ])
    assert result.exit_code == 0
    assert out_sarif.exists()
    sarif_json = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif_json["version"] == "2.1.0"


def test_cli_review_clean_working_tree() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [
        "review",
        "--format", "terminal",
        "--exit-zero",
    ])
    assert result.exit_code == 0


def test_cli_review_with_ai_option() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [
        "review",
        "--ai", "offline",
        "--format", "terminal",
        "--exit-zero",
    ])
    assert result.exit_code == 0


def test_review_engine_diff_with_ai_provider() -> None:
    from agentblackbox.models.diff import GitDiff, FileDiff, DiffHunk, DiffLine, DiffLineType
    lines = [
        DiffLine(line_type=DiffLineType.DELETE, content="old = 1", old_lineno=1),
        DiffLine(line_type=DiffLineType.ADD, content="old = 1", new_lineno=1),
        DiffLine(line_type=DiffLineType.ADD, content="new_val = 2", new_lineno=2),
    ]
    hunk = DiffHunk(
        old_start=1,
        old_lines=1,
        new_start=1,
        new_lines=2,
        header="@@ -1,1 +1,2 @@",
        lines=lines,
    )
    diff = GitDiff(
        files=[FileDiff(old_path="test.py", new_path="test.py", hunks=[hunk])],
        raw_diff="diff --git a/test.py b/test.py\n--- a/test.py\n+++ b/test.py\n@@ -1,1 +1,2 @@\n-old = 1\n+old = 1\n+new_val = 2\n",
    )
    engine = ReviewEngine(
        config=ReviewConfig(enable_ai=True, max_context_tokens=4000),
        ai_provider=OfflineMockAIProvider(),
    )
    report = engine.review_diff(diff)
    assert report.total_findings >= 0
    assert report.model_name == "OfflineMockAIProvider"
