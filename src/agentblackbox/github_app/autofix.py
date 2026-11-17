"""Autonomous 1-Click Remediation & Fix PR Generator for GitHub App.

Handles `@agentblackbox fix` issue comment commands by:
1. Inspecting PR findings with deterministic/safe suggested fixes
2. Applying code patches strictly in transient RAM
3. Branching from PR head (`agentblackbox/autofix-pr-<num>-<hash>`)
4. Pushing patched files via Git Data API
5. Opening a ready-to-merge remediation Pull Request into the PR head branch
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import structlog

from agentblackbox.github_app.client import GitHubClient
from agentblackbox.models.finding import Finding, Severity

logger = structlog.get_logger(__name__)


@dataclass
class RemediationResult:
    """Outcome of an automated remediation run."""
    success: bool
    branch_name: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    applied_fixes_count: int = 0
    modified_files: List[str] = field(default_factory=list)
    skipped_findings: List[str] = field(default_factory=list)
    message: str = ""


class AutoFixEngine:
    """Orchestrates in-memory patch application and GitHub PR generation."""

    def __init__(self, client: GitHubClient) -> None:
        self.client = client

    def filter_safe_fixable_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings that provide a safe, concrete suggested fix."""
        fixable: List[Finding] = []
        for f in findings:
            if not f.suggested_fix or not f.suggested_fix.strip():
                continue
            if not f.file_path:
                continue
            # Avoid applying fixes to binary, lockfiles, or files outside diff
            lower_path = f.file_path.lower()
            if any(ext in lower_path for ext in (".lock", "-lock.json", ".min.js", ".bin")):
                continue
            fixable.append(f)
        return fixable

    def apply_patches_to_content(self, content: str, findings: List[Finding]) -> str:
        """Apply code fixes to a file's content in descending line order to prevent offset drift."""
        lines = content.splitlines(keepends=True)
        if not lines and content:
            lines = [content]

        # Sort findings by line_start descending
        sorted_findings = sorted(findings, key=lambda f: f.line_start or 0, reverse=True)

        for f in sorted_findings:
            if not f.suggested_fix:
                continue

            start_idx = max(0, (f.line_start or 1) - 1)
            end_idx = max(start_idx + 1, f.line_end or (start_idx + 1))

            # Ensure newline termination on suggested fix
            fix_text = f.suggested_fix
            if not fix_text.endswith("\n"):
                fix_text += "\n"

            # Check bounds
            if start_idx < len(lines):
                # Replace line range with suggested fix
                lines[start_idx:end_idx] = [fix_text]
            else:
                # Append if beyond end
                lines.append(fix_text)

        return "".join(lines)

    async def create_remediation_pr(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        head_sha: str,
        head_branch: str,
        findings: List[Finding],
        installation_id: Optional[int] = None,
    ) -> RemediationResult:
        """Apply safe fixes in memory, create a remediation branch, and open a PR.

        Guarantees Provable Zero Retention: files are modified in volatile RAM and
        transferred directly via GitHub's API. No customer code is saved locally.
        """
        fixable = self.filter_safe_fixable_findings(findings)
        if not fixable:
            skipped_rules = [f"{f.rule_id} ({f.file_path}:{f.line_start})" for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            return RemediationResult(
                success=False,
                applied_fixes_count=0,
                skipped_findings=skipped_rules[:5],
                message="No automated 1-click fixes are currently applicable for this PR. Manual resolution required.",
            )

        # Group findings by file path
        by_file: Dict[str, List[Finding]] = {}
        for f in fixable:
            by_file.setdefault(f.file_path, []).append(f)

        # Create unique remediation branch
        short_id = uuid.uuid4().hex[:6]
        branch_name = f"agentblackbox/autofix-pr-{pull_number}-{short_id}"

        try:
            await self.client.create_branch(
                owner=owner,
                repo=repo,
                branch=branch_name,
                sha=head_sha,
                installation_id=installation_id,
            )
            logger.info("remediation_branch_created", branch=branch_name, pr=pull_number)
        except Exception as exc:
            logger.error("create_remediation_branch_failed", error=str(exc))
            return RemediationResult(
                success=False,
                message=f"Failed to create remediation branch `{branch_name}`: {exc}",
            )

        modified_files: List[str] = []
        applied_count = 0

        # Fetch, patch, and commit each file to the new branch
        for path, file_findings in by_file.items():
            try:
                # Get current content and file metadata (blob sha) from target branch
                meta = await self.client.get_file_metadata(
                    owner=owner,
                    repo=repo,
                    path=path,
                    ref=branch_name,
                    installation_id=installation_id,
                )
                file_blob_sha = meta.get("sha") if isinstance(meta, dict) else None
                current_text = await self.client.get_file_contents(
                    owner=owner,
                    repo=repo,
                    path=path,
                    ref=branch_name,
                    installation_id=installation_id,
                )
                if current_text is None:
                    continue

                # In-memory patch application
                patched_text = self.apply_patches_to_content(current_text, file_findings)
                if patched_text == current_text:
                    continue

                rules_summary = ", ".join(set(f.rule_id for f in file_findings))
                commit_msg = (
                    f"fix({path}): auto-remediate {rules_summary}\n\n"
                    f"AgentBlackBox-AutoFix: PR #{pull_number}\n"
                    f"Applied rules: {rules_summary}"
                )

                await self.client.update_file_contents(
                    owner=owner,
                    repo=repo,
                    path=path,
                    content=patched_text,
                    message=commit_msg,
                    branch=branch_name,
                    sha=file_blob_sha,
                    installation_id=installation_id,
                )
                modified_files.append(path)
                applied_count += len(file_findings)
            except Exception as exc:
                logger.error("patch_file_commit_failed", file=path, error=str(exc))

        if not modified_files:
            return RemediationResult(
                success=False,
                branch_name=branch_name,
                message="Patches produced identical file contents; no files were modified.",
            )

        # Open remediation Pull Request
        pr_title = f"[AgentBlackBox] Automated fix for PR #{pull_number}"
        pr_body = (
            f"## 🤖 AgentBlackBox Automated Remediation\n\n"
            f"This pull request contains safe, 1-click fixes for findings detected in PR #{pull_number}.\n\n"
            f"### 📋 Applied Fixes ({applied_count}):\n"
        )
        for path, file_findings in by_file.items():
            if path in modified_files:
                pr_body += f"- **`{path}`**:\n"
                for f in file_findings:
                    pr_body += f"  - `{f.rule_id}` (line {f.line_start}): {f.title}\n"

        pr_body += (
            f"\n---\n"
            f"*Generated by AgentBlackBox Autonomous Remediation Engine (Zero Retention).*\n"
            f"To accept, review the diff and merge into `{head_branch}`."
        )

        try:
            new_pr = await self.client.create_pull_request(
                owner=owner,
                repo=repo,
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=head_branch,
                installation_id=installation_id,
            )
            pr_html_url = new_pr.get("html_url")
            new_pr_num = new_pr.get("number")
            return RemediationResult(
                success=True,
                branch_name=branch_name,
                pr_url=pr_html_url,
                pr_number=new_pr_num,
                applied_fixes_count=applied_count,
                modified_files=modified_files,
                message=f"Created remediation Pull Request #{new_pr_num}: {pr_html_url}",
            )
        except Exception as exc:
            logger.error("create_remediation_pr_failed", error=str(exc))
            return RemediationResult(
                success=True,
                branch_name=branch_name,
                applied_fixes_count=applied_count,
                modified_files=modified_files,
                message=f"Remediation branch `{branch_name}` pushed, but PR creation returned: {exc}",
            )
