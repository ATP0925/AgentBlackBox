"""Unit tests for finding, severity, and report serialization."""

from agentblackbox.models.finding import Finding, Severity
from agentblackbox.models.report import ReviewReport


def test_finding_and_severity() -> None:
    f = Finding(
        title="SQL Injection Vulnerability",
        severity=Severity.CRITICAL,
        file_path="src/db.py",
        line_start=45,
        line_end=48,
        category="security",
        message="Unsanitized string interpolation in SQL execute call.",
        why_it_matters="Allows arbitrary database access and data leakage.",
        suggested_fix="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        rule_id="SEC-001",
        cwe_id="CWE-89",
    )

    assert f.severity.level == 5
    assert f.severity.value == "Critical"
    d = f.to_dict()
    assert d["severity"] == "Critical"
    assert d["cwe_id"] == "CWE-89"


def test_review_report_markdown_and_sarif() -> None:
    f1 = Finding(
        title="SQL Injection Vulnerability",
        severity=Severity.CRITICAL,
        file_path="src/db.py",
        line_start=45,
        line_end=48,
        category="security",
        message="Unsanitized string interpolation in SQL query.",
        why_it_matters="Allows attackers to manipulate queries.",
        suggested_fix="Use parameterized queries.",
        rule_id="SEC-001",
        cwe_id="CWE-89",
    )
    f2 = Finding(
        title="Broad Exception Catch",
        severity=Severity.LOW,
        file_path="src/main.py",
        line_start=12,
        line_end=15,
        category="quality",
        message="Catching bare Exception hides unexpected bugs.",
        why_it_matters="Can mask system errors and KeyboardInterrupt.",
        suggested_fix="Catch specific exception types.",
        rule_id="QUAL-002",
    )

    report = ReviewReport(
        target="feature/auth-revamp",
        findings=[f1, f2],
        analyzed_files=["src/db.py", "src/main.py"],
        execution_time_ms=124.5,
        model_name="deterministic-engine",
    )

    assert report.total_findings == 2
    assert report.has_critical_or_high is True
    assert report.severity_counts["Critical"] == 1
    assert report.severity_counts["Low"] == 1

    # Markdown export test
    md = report.to_markdown()
    assert "# 🔍 AI Code Review: `feature/auth-revamp`" in md
    assert "🔴 Critical: 1" in md
    assert "SQL Injection Vulnerability" in md
    assert "```python" in md

    # SARIF export test
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "SEC-001"
    assert results[0]["level"] == "error"
    assert results[1]["ruleId"] == "QUAL-002"
    assert results[1]["level"] == "note"
