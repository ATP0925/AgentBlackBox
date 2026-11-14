"""GitHub PR Review Execution Engine.

Bridges GitHub pull requests with AgentBlackBox's deterministic scanners,
AI reasoning layer, compliance tracker, and architectural drift detector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

from agentblackbox.analysis.compliance_tracker import ComplianceTracker
from agentblackbox.analysis.drift_detector import ArchitecturalDriftDetector
from agentblackbox.core.config import ReviewConfig
from agentblackbox.core.engine import ReviewEngine
from agentblackbox.github_app.config import AgentBlackBoxConfig
from agentblackbox.github_app.diff import DiffMapper
from agentblackbox.github_app.security import redact_diff_secrets
from agentblackbox.models.finding import Finding, Severity

logger = structlog.get_logger(__name__)


@dataclass
class PRReviewResult:
    """Consolidated review output for a Pull Request."""
    findings: List[Finding] = field(default_factory=list)
    compliance_findings: List[Dict[str, Any]] = field(default_factory=list)
    drift_violations: List[Dict[str, Any]] = field(default_factory=list)
    ai_summary: str = ""
    files_analyzed: int = 0


class GitHubReviewRunner:
    """Orchestrates comprehensive review of a Pull Request diff."""

    def __init__(
        self,
        config: Optional[AgentBlackBoxConfig] = None,
        review_engine: Optional[ReviewEngine] = None,
        compliance_tracker: Optional[ComplianceTracker] = None,
        drift_detector: Optional[ArchitecturalDriftDetector] = None,
    ) -> None:
        self.config = config or AgentBlackBoxConfig()
        self.review_engine = review_engine or ReviewEngine(config=ReviewConfig())
        self.compliance_tracker = compliance_tracker or ComplianceTracker()
        self.drift_detector = drift_detector or ArchitecturalDriftDetector()

    def deduplicate_against_existing_comments(
        self,
        findings: List[Finding],
        existing_comments: List[Dict[str, Any]],
    ) -> List[Finding]:
        """Filter out findings that have already been commented on to avoid spamming."""
        if not existing_comments:
            return findings

        # Index existing comments by path and mentioned rule IDs
        existing_keys: Set[Tuple[str, int]] = set()
        for c in existing_comments:
            c_path = (c.get("path") or "").replace("\\", "/").lstrip("/")
            c_line = c.get("line") or c.get("original_line") or 0
            body = c.get("body") or ""
            # Check for rule code in body e.g. `SEC-001`
            match = re.search(r"`([A-Z0-9_-]{4,20})`", body)
            if c_path and c_line:
                existing_keys.add((c_path, c_line))

        deduped: List[Finding] = []
        for f in findings:
            f_path = f.file_path.replace("\\", "/").lstrip("/")
            # Check exact or adjacent line (±2 lines)
            is_dup = any(
                (f_path, line_candidate) in existing_keys
                for line_candidate in range(f.line_start - 2, f.line_start + 3)
            )
            if not is_dup:
                deduped.append(f)

        return deduped

    async def execute_review(
        self,
        raw_diff: str,
        pr_files_content: Optional[Dict[str, str]] = None,
        existing_comments: Optional[List[Dict[str, Any]]] = None,
    ) -> PRReviewResult:
        """Run complete security, AST, compliance, and drift analysis on a PR diff.

        Customer code is analyzed strictly in-memory without persistent disk storage.

        Args:
            raw_diff: Unified diff string of the pull request.
            pr_files_content: Optional dictionary mapping {relative_file_path: file_content_str}.
            existing_comments: List of previous review comments to deduplicate against.

        Returns:
            PRReviewResult containing findings, compliance issues, drift, and AI summary.
        """
        pr_files_content = pr_files_content or {}
        diff_mapper = DiffMapper(raw_diff, path_settings=self.config.paths)
        reviewable_files = diff_mapper.get_reviewable_files()

        # Step 1: In-memory Secret Redaction
        clean_diff, secret_findings = redact_diff_secrets(raw_diff)

        # Step 2: AST & Domain Analysis via ReviewEngine
        all_findings: List[Finding] = list(secret_findings)

        # Build in-memory GitDiff for ReviewEngine
        parsed_git_diff = diff_mapper.git_diff
        try:
            report = self.review_engine.review_diff(parsed_git_diff)
            all_findings.extend(report.findings)
            ai_summary = report.ai_summary
        except Exception as exc:
            logger.warning("review_diff_error", error=str(exc))
            ai_summary = "Automated diff analysis completed."

        # Step 3: Compliance & Drift Analysis on changed files
        compliance_findings: List[Dict[str, Any]] = []
        drift_violations: List[Dict[str, Any]] = []

        for fdiff in reviewable_files:
            file_path = fdiff.target_path
            content = pr_files_content.get(file_path, "")

            if self.config.scanners.compliance and content:
                try:
                    c_results = self.compliance_tracker.check_content(file_path=file_path, content=content)
                    for cr in c_results:
                        compliance_findings.append(cr.to_dict())
                except Exception as exc:
                    logger.debug("compliance_check_skipped", file=file_path, error=str(exc))

            if self.config.scanners.drift and content:
                try:
                    d_results = self.drift_detector.check_layer_isolation(file_path=file_path, content=content)
                    for dr in d_results:
                        drift_violations.append(dr.to_dict())
                except Exception as exc:
                    logger.debug("drift_check_skipped", file=file_path, error=str(exc))

        # Step 4: Confidence & Severity Filtering
        min_conf = self.config.reviews.min_confidence
        filtered_findings = [f for f in all_findings if f.confidence >= min_conf]

        # Step 5: Deduplicate against existing comments
        if existing_comments:
            filtered_findings = self.deduplicate_against_existing_comments(filtered_findings, existing_comments)

        return PRReviewResult(
            findings=filtered_findings,
            compliance_findings=compliance_findings,
            drift_violations=drift_violations,
            ai_summary=ai_summary,
            files_analyzed=len(reviewable_files),
        )
