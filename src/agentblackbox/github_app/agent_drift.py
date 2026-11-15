"""Agent-Misbehavior Drift Detection & PR Risk Scoring Engine.

Specialized static analyzers targeting common autonomous agent failure modes:
- Wiping or weakening unit tests to force passing builds
- Altering CI/CD workflows and flight-gate configurations
- Introducing suspicious/typosquatted third-party dependencies
- Disabling linters, typecheckers, and security suppressions (`noqa`, `type: ignore`)
- Tampering with permissions or security-critical configurations
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from agentblackbox.context.diff_parser import parse_unified_diff
from agentblackbox.models.diff import DiffLineType, FileDiff, GitDiff
from agentblackbox.models.finding import Finding, Severity

KNOWN_SAFE_PYPI_TOP = {
    "requests", "httpx", "fastapi", "uvicorn", "pydantic", "pytest", "numpy",
    "pandas", "scipy", "click", "typer", "rich", "pyyaml", "structlog",
    "cryptography", "pyjwt", "aiohttp", "flask", "django", "sqlalchemy",
    "redis", "celery", "boto3", "google-api-python-client", "anthropic", "openai",
}


@dataclass
class PRRiskScoreBreakdown:
    """Detailed explainable risk score calculation for a Pull Request."""
    total_score: float  # 0.0 to 10.0
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    factors: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def composite_score(self) -> float:
        """Alias for total_score."""
        return self.total_score

    @property
    def risk_tier(self) -> str:
        """Alias for risk_level."""
        return self.risk_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "factors": self.factors,
        }


class AgentMisbehaviorScanner:
    """Analyzes PR diffs specifically for agent shortcuts, regressions, and evasion attempts."""

    def __init__(self) -> None:
        pass

    def scan_diff(
        self,
        raw_diff: str,
        pr_title: str = "",
        pr_body: str = "",
    ) -> Tuple[List[Finding], PRRiskScoreBreakdown]:
        """Scan raw unified diff for agent-misbehavior patterns and compute PR risk score."""
        findings: List[Finding] = []
        git_diff: GitDiff = parse_unified_diff(raw_diff) if raw_diff else GitDiff()

        risk_points: float = 1.0  # Base line score
        factors: List[Dict[str, Any]] = []

        total_lines_added = 0
        total_lines_deleted = 0

        for fdiff in git_diff.files:
            target_path = (fdiff.target_path or fdiff.source_path or "").replace("\\", "/").lstrip("/")
            is_test_file = "test" in target_path.lower()
            is_ci_file = target_path.startswith(".github/workflows/") or "circleci" in target_path or "gitlab-ci" in target_path
            is_dep_file = target_path in ("requirements.txt", "pyproject.toml", "package.json", "setup.py", "Pipfile")

            # 1. Detect Deleted Test Files
            if fdiff.is_deleted and is_test_file:
                findings.append(
                    Finding(
                        title=f"Test Suite File Deleted: {target_path}",
                        severity=Severity.CRITICAL,
                        file_path=target_path,
                        line_start=1,
                        line_end=1,
                        category="agent_drift",
                        message=(
                            f"The test file `{target_path}` was completely deleted. Autonomous agents frequently delete "
                            f"failing test files to bypass test runner failures and satisfy exit-code 0 goals."
                        ),
                        why_it_matters="Deleting test suites introduces silent regression vulnerabilities and destroys quality gates.",
                        suggested_fix="Restore the deleted test file and resolve the underlying implementation defect.",
                        rule_id="DRIFT-TEST-FILE-DELETED",
                        cwe_id="CWE-489",
                    )
                )
                risk_points += 4.0
                factors.append({"factor": "test_file_deleted", "path": target_path, "points": 4.0})

            # 2. Inspect individual hunks
            deleted_asserts_count = 0
            for hunk in fdiff.hunks:
                for line in hunk.lines:
                    if line.line_type == DiffLineType.ADD:
                        total_lines_added += 1
                        added_txt = line.content.strip()

                        # Check disabled linters / security checks
                        if re.search(r"#\s*(noqa|type:\s*ignore|nosec|ruff:\s*noqa)", added_txt, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Static Analysis Linter or Security Suppression Added",
                                    severity=Severity.MEDIUM,
                                    file_path=target_path,
                                    line_start=line.new_lineno or 1,
                                    line_end=line.new_lineno or 1,
                                    category="agent_drift",
                                    message=f"Added suppression tag (`{added_txt}`) disabling static analysis or security linter checks.",
                                    why_it_matters="Agents commonly insert `# noqa` or `# type: ignore` to silence typechecker or linter warnings rather than writing correct code.",
                                    suggested_fix="Address the underlying type or linting defect instead of suppressing compiler warnings.",
                                    rule_id="DRIFT-LINTER-SUPPRESSION",
                                )
                            )
                            risk_points += 0.8
                            factors.append({"factor": "linter_suppression", "line": line.new_lineno, "points": 0.8})

                        # Check weakened tests (skip, xfail)
                        if is_test_file and re.search(r"@pytest\.mark\.(skip|xfail)|unittest\.skip", added_txt):
                            findings.append(
                                Finding(
                                    title="Test Skip or Xfail Marker Added",
                                    severity=Severity.HIGH,
                                    file_path=target_path,
                                    line_start=line.new_lineno or 1,
                                    line_end=line.new_lineno or 1,
                                    category="agent_drift",
                                    message=f"Test was weakened or disabled using skip/xfail marker: `{added_txt}`.",
                                    why_it_matters="Disabling failing tests masks regressions and gives a false sense of test pass compliance.",
                                    suggested_fix="Fix the failing assertion instead of skipping the test.",
                                    rule_id="DRIFT-TEST-WEAKENED",
                                )
                            )
                            risk_points += 2.0
                            factors.append({"factor": "test_skipped", "line": line.new_lineno, "points": 2.0})

                    elif line.line_type == DiffLineType.DELETE:
                        total_lines_deleted += 1
                        del_txt = line.content.strip()
                        if is_test_file and del_txt.startswith("assert ") or "self.assert" in del_txt:
                            deleted_asserts_count += 1

            # Report significant assert deletions
            if deleted_asserts_count >= 2:
                findings.append(
                    Finding(
                        title=f"Multiple Test Assertions Removed in {target_path}",
                        severity=Severity.HIGH,
                        file_path=target_path,
                        line_start=1,
                        line_end=1,
                        category="agent_drift",
                        message=f"{deleted_asserts_count} test assertion(s) were removed from `{target_path}` without replacement.",
                        why_it_matters="Stripping assertions from tests hollows out verification coverage, allowing defects to slip through undetected.",
                        suggested_fix="Ensure all business logic assertions are preserved and properly maintained.",
                        rule_id="DRIFT-ASSERT-DELETED",
                    )
                )
                risk_points += 2.5
                factors.append({"factor": "asserts_deleted", "count": deleted_asserts_count, "points": 2.5})

            # 3. Detect CI Workflow Modifications
            if is_ci_file:
                findings.append(
                    Finding(
                        title=f"CI/CD Workflow Modified: {target_path}",
                        severity=Severity.HIGH,
                        file_path=target_path,
                        line_start=1,
                        line_end=1,
                        category="security",
                        message=(
                            f"CI/CD pipeline workflow `{target_path}` was modified. Autonomous agents must not alter CI/CD "
                            f"flight-gate configurations or disable test jobs without explicit security review."
                        ),
                        why_it_matters="Unchecked changes to CI workflows can introduce malicious steps, exfiltrate repo secrets, or disable gates.",
                        suggested_fix="Verify workflow alterations carefully to ensure pipeline security gates remain enforced.",
                        rule_id="DRIFT-CI-WORKFLOW-ALTERED",
                    )
                )
                risk_points += 3.0
                factors.append({"factor": "ci_workflow_modified", "path": target_path, "points": 3.0})

            # 4. Detect Dependency File Changes
            if is_dep_file:
                risk_points += 1.5
                factors.append({"factor": "dependency_file_modified", "path": target_path, "points": 1.5})

        # Final score calculation bounded 0.0 - 10.0
        final_score = min(10.0, round(risk_points, 1))
        if final_score >= 8.0:
            level = "CRITICAL"
        elif final_score >= 5.5:
            level = "HIGH"
        elif final_score >= 3.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        breakdown = PRRiskScoreBreakdown(
            total_score=final_score,
            risk_level=level,
            factors=factors,
        )

        return findings, breakdown
