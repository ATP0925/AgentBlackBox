"""Unit tests for GitHub Walkthrough markdown, inline review comments, and check run outputs."""

from agentblackbox.github_app.diff import DiffMapper
from agentblackbox.github_app.formatter import (
    WALKTHROUGH_MARKER,
    format_check_run_output,
    format_inline_review_comments,
    format_walkthrough,
)
from agentblackbox.models.finding import Finding, Severity

SAMPLE_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 def test():
+    password = "123"
     return True
"""


def test_format_walkthrough() -> None:
    findings = [
        Finding(
            title="Hardcoded Password",
            severity=Severity.HIGH,
            file_path="app.py",
            line_start=2,
            line_end=2,
            category="security",
            message="Found plain text password.",
            why_it_matters="Compromises system access.",
            suggested_fix="password = os.getenv('PASS')",
            rule_id="SEC-002",
        )
    ]
    wt = format_walkthrough(
        pr_number=10,
        pr_title="Add Authentication",
        head_sha="abcdef123456",
        files_analyzed=1,
        findings=findings,
        ai_summary="Reviewed user authentication logic.",
    )

    assert WALKTHROUGH_MARKER in wt
    assert "PR #10" in wt
    assert "High" in wt
    assert "@agentblackbox review" in wt


def test_format_inline_review_comments() -> None:
    diff_mapper = DiffMapper(SAMPLE_DIFF)
    findings = [
        Finding(
            title="Hardcoded Secret",
            severity=Severity.CRITICAL,
            file_path="app.py",
            line_start=2,
            line_end=2,
            category="security",
            message="Do not hardcode secrets.",
            why_it_matters="Credential exposure.",
            suggested_fix="password = os.getenv('PASSWORD')",
            rule_id="SEC-001",
        ),
        # Out-of-hunk finding
        Finding(
            title="Old Smell",
            severity=Severity.LOW,
            file_path="app.py",
            line_start=500,
            line_end=500,
            category="quality",
            message="Outside diff.",
            why_it_matters="Maintainability.",
            suggested_fix="",
            rule_id="QUAL-001",
        ),
    ]

    inline, out_of_diff = format_inline_review_comments(findings, diff_mapper)

    assert len(inline) == 1
    assert inline[0]["path"] == "app.py"
    assert inline[0]["line"] == 2
    assert "```suggestion" in inline[0]["body"]
    assert "password = os.getenv('PASSWORD')" in inline[0]["body"]

    assert len(out_of_diff) == 1
    assert out_of_diff[0].line_start == 500


def test_format_check_run_annotation_batching() -> None:
    # Generate 65 findings to verify 50-item batching
    findings = [
        Finding(
            title=f"Smell #{i}",
            severity=Severity.LOW,
            file_path="app.py",
            line_start=i,
            line_end=i,
            category="quality",
            message="Testing batching limit.",
            why_it_matters="Noise reduction.",
            suggested_fix="",
            rule_id=f"QUAL-{i}",
        )
        for i in range(1, 66)
    ]

    conclusion, output_dict, extra_batches = format_check_run_output(findings, fail_on="high")

    assert conclusion == "success"  # all are LOW
    assert len(output_dict["annotations"]) == 50
    assert len(extra_batches) == 1
    assert len(extra_batches[0]) == 15
