"""Event Router for GitHub Webhook Events.

Orchestrates PR lifecycle events, issue comment bot commands, in-flight rate limiting,
agent-session linkage, cryptographic review receipts, SARIF exports, and check runs.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

import structlog

from agentblackbox.github_app.autofix import AutoFixEngine, RemediationResult
from agentblackbox.github_app.client import GitHubClient
from agentblackbox.github_app.config import load_repo_config
from agentblackbox.github_app.diff import DiffMapper
from agentblackbox.github_app.feedback import FeedbackStore
from agentblackbox.github_app.formatter import (
    WALKTHROUGH_MARKER,
    format_check_run_output,
    format_inline_review_comments,
    format_walkthrough,
)
from agentblackbox.github_app.rate_limiter import RateAndBudgetLimiter
from agentblackbox.github_app.receipts import ReviewReceiptManager
from agentblackbox.github_app.review_engine import GitHubReviewRunner
from agentblackbox.github_app.sarif import generate_pr_sarif
from agentblackbox.github_app.session_linker import AgentSessionLinker
from agentblackbox.models.finding import Finding

logger = structlog.get_logger(__name__)


class GitHubEventHandler:
    """Dispatches and processes GitHub webhook events with cryptographic verification."""

    def __init__(
        self,
        client: GitHubClient,
        review_runner: Optional[GitHubReviewRunner] = None,
        limiter: Optional[RateAndBudgetLimiter] = None,
        receipt_manager: Optional[ReviewReceiptManager] = None,
        session_linker: Optional[AgentSessionLinker] = None,
        feedback_store: Optional[FeedbackStore] = None,
        autofix_engine: Optional[AutoFixEngine] = None,
    ) -> None:
        self.client = client
        self.review_runner = review_runner or GitHubReviewRunner()
        self.limiter = limiter or RateAndBudgetLimiter()
        self.receipt_manager = receipt_manager or ReviewReceiptManager()
        self.session_linker = session_linker or AgentSessionLinker()
        self.feedback_store = feedback_store or FeedbackStore()
        self.autofix_engine = autofix_engine or AutoFixEngine(client=self.client)
        # Track last reviewed SHA: {(owner, repo, pull_number): sha}
        self._last_reviewed_sha: Dict[Tuple[str, str, int], str] = {}
        # In-memory store for generated SARIF reports: {(owner, repo, pull_number): sarif_doc}
        self.latest_sarif_reports: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        # In-memory cache of findings from latest review for 1-click remediation: {(owner, repo, pull_number): findings}
        self.latest_review_findings: Dict[Tuple[str, str, int], List[Finding]] = {}

    async def handle_review_comment_event(self, payload: Dict[str, Any]) -> None:
        """Handle review comment reactions (+1, -1, confused) for quality calibration."""
        reaction_info = payload.get("reaction") or {}
        reaction_content = reaction_info.get("content") or ""
        comment = payload.get("comment") or {}
        body = comment.get("body") or ""

        rule_match = re.search(r"`([A-Z0-9_\-]+)`", body)
        rule_id = rule_match.group(1) if rule_match else "GENERAL-REVIEW"
        finding_hash = hashlib.sha256(body.encode()).hexdigest()[:16]

        if reaction_content:
            self.feedback_store.record_feedback(
                rule_id=rule_id,
                finding_hash=finding_hash,
                reaction=reaction_content,
                comment_id=comment.get("id"),
            )

    async def handle_pull_request_event(self, payload: Dict[str, Any]) -> None:
        """Handle pull_request webhook events (opened, reopened, synchronize, ready_for_review)."""
        action = payload.get("action")
        supported_actions = {"opened", "reopened", "synchronize", "ready_for_review"}
        if action not in supported_actions:
            logger.debug("pr_action_skipped", action=action)
            return

        pr = payload.get("pull_request", {})
        repo_data = payload.get("repository", {})
        owner = repo_data.get("owner", {}).get("login", "")
        repo = repo_data.get("name", "")
        pull_number = pr.get("number")
        is_draft = pr.get("draft", False)
        head_sha = pr.get("head", {}).get("sha", "")
        base_ref = pr.get("base", {}).get("ref", "main")
        installation_id = payload.get("installation", {}).get("id")

        if not (owner and repo and pull_number and head_sha):
            logger.warning("incomplete_pr_payload", owner=owner, repo=repo, pull_number=pull_number)
            return

        pr_key = (owner.lower(), repo.lower(), pull_number)

        # Check if automated reviews have been paused for this PR
        if self.limiter.is_pr_paused(owner, repo, pull_number):
            logger.info("pr_review_skipped_paused", owner=owner, repo=repo, pull_number=pull_number)
            return

        # Check rate and budget limits (circuit breaker)
        if installation_id:
            allowed, block_reason = self.limiter.check_limits(installation_id)
            if not allowed:
                logger.warning("rate_limit_circuit_breaker", reason=block_reason, installation_id=installation_id)
                # Post non-spammy neutral check run
                try:
                    await self.client.create_check_run(
                        owner=owner,
                        repo=repo,
                        name="AgentBlackBox Review",
                        head_sha=head_sha,
                        status="completed",
                        conclusion="neutral",
                        output={
                            "title": "AgentBlackBox: Review Skipped",
                            "summary": f"Automated review temporarily skipped: {block_reason}",
                        },
                        installation_id=installation_id,
                    )
                except Exception:
                    pass
                return

        # 1. Load config from base branch
        config = await load_repo_config(
            client=self.client,
            owner=owner,
            repo=repo,
            base_ref=base_ref,
            installation_id=installation_id,
        )

        if not config.reviews.enabled:
            logger.info("pr_review_disabled_in_config", owner=owner, repo=repo, pull_number=pull_number)
            return

        if is_draft and not config.reviews.draft_prs:
            logger.info("draft_pr_skipped", owner=owner, repo=repo, pull_number=pull_number)
            return

        # 2. Create in-progress Check Run
        check_run_id: Optional[int] = None
        try:
            cr = await self.client.create_check_run(
                owner=owner,
                repo=repo,
                name="AgentBlackBox Review",
                head_sha=head_sha,
                status="in_progress",
                installation_id=installation_id,
            )
            check_run_id = cr.get("id")
        except Exception as exc:
            logger.warning("create_check_run_failed", error=str(exc))

        try:
            # 3. Check for linked Agent Session
            pr_body = pr.get("body", "") or ""
            branch_name = pr.get("head", {}).get("ref", "") or ""
            session_id = self.session_linker.extract_session_id(pr_body=pr_body, branch_name=branch_name)
            linked_session = None
            if session_id:
                linked_session = self.session_linker.audit_session(session_id)
                logger.info("linked_agent_session_audited", session_id=session_id, valid=linked_session.is_valid)

            # 4. Fetch PR raw diff
            raw_diff = await self.client.get_pull_request_diff(
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                installation_id=installation_id,
            )

            # 5. Fetch changed files contents strictly into volatile RAM
            diff_mapper = DiffMapper(raw_diff, path_settings=config.paths)
            reviewable_files = diff_mapper.get_reviewable_files()

            files_content: Dict[str, str] = {}
            for f in reviewable_files:
                try:
                    f_text = await self.client.get_file_contents(
                        owner=owner,
                        repo=repo,
                        path=f.target_path,
                        ref=head_sha,
                        installation_id=installation_id,
                    )
                    if f_text is not None:
                        files_content[f.target_path] = f_text
                except Exception as exc:
                    logger.debug("fetch_file_content_skipped", file=f.target_path, error=str(exc))

            # 6. Fetch existing comments for deduplication
            existing_comments: List[Dict[str, Any]] = []
            try:
                existing_comments = await self.client.list_review_comments(
                    owner=owner,
                    repo=repo,
                    pull_number=pull_number,
                    installation_id=installation_id,
                )
            except Exception as exc:
                logger.debug("list_review_comments_failed", error=str(exc))

            # 7. Execute Review Runner
            self.review_runner.config = config
            review_res = await self.review_runner.execute_review(
                raw_diff=raw_diff,
                pr_files_content=files_content,
                existing_comments=existing_comments,
                pr_title=pr.get("title", ""),
                pr_body=pr_body,
            )

            # If linked agent session detected tampering, escalate to critical finding
            if linked_session and linked_session.findings:
                review_res.findings.extend(linked_session.findings)

            # 8. Cryptographically Seal Signed Review Receipt
            receipt = None
            try:
                receipt = self.receipt_manager.generate_receipt(
                    owner=owner,
                    repo=repo,
                    pull_number=pull_number,
                    head_sha=head_sha,
                    raw_diff=raw_diff,
                    config_yaml=getattr(config, "raw_yaml", ""),
                    findings=review_res.findings,
                )
            except Exception as exc:
                logger.warning("generate_receipt_skipped", error=str(exc))

            # 9. Format inline review comments & submit batch review
            inline_comments, out_of_diff_findings = format_inline_review_comments(
                findings=review_res.findings,
                diff_mapper=diff_mapper,
                max_comments=config.reviews.max_comments,
            )

            if inline_comments:
                try:
                    await self.client.create_pull_request_review(
                        owner=owner,
                        repo=repo,
                        pull_number=pull_number,
                        commit_id=head_sha,
                        body="AgentBlackBox has completed inline code review findings.",
                        event="COMMENT",
                        comments=inline_comments,
                        installation_id=installation_id,
                    )
                except Exception as exc:
                    logger.error("submit_pr_review_failed", error=str(exc))

            # 10. Post or update single Walkthrough comment
            walkthrough_body = format_walkthrough(
                pr_number=pull_number,
                pr_title=pr.get("title", ""),
                head_sha=head_sha,
                files_analyzed=review_res.files_analyzed,
                findings=review_res.findings,
                compliance_findings=review_res.compliance_findings,
                drift_violations=review_res.drift_violations,
                ai_summary=review_res.ai_summary,
                config_warnings=config.warnings,
                out_of_diff_findings=out_of_diff_findings,
                receipt=receipt,
                linked_session=linked_session,
                risk_breakdown=review_res.risk_breakdown,
            )

            try:
                issue_comments = await self.client.list_issue_comments(
                    owner=owner,
                    repo=repo,
                    issue_number=pull_number,
                    installation_id=installation_id,
                )
                existing_wt = next(
                    (c for c in issue_comments if WALKTHROUGH_MARKER in (c.get("body") or "")),
                    None,
                )
                if existing_wt:
                    await self.client.update_issue_comment(
                        owner=owner,
                        repo=repo,
                        comment_id=existing_wt["id"],
                        body=walkthrough_body,
                        installation_id=installation_id,
                    )
                else:
                    await self.client.create_issue_comment(
                        owner=owner,
                        repo=repo,
                        issue_number=pull_number,
                        body=walkthrough_body,
                        installation_id=installation_id,
                    )
            except Exception as exc:
                logger.error("post_walkthrough_failed", error=str(exc))

            # 11. Generate SARIF report for Advanced Security
            sarif_doc = generate_pr_sarif(
                findings=review_res.findings,
                compliance_findings=review_res.compliance_findings,
                drift_violations=review_res.drift_violations,
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                commit_sha=head_sha,
            )
            self.latest_sarif_reports[pr_key] = sarif_doc

            # 12. Update Check Run conclusion and annotations
            conclusion, cr_output, extra_batches = format_check_run_output(
                findings=review_res.findings,
                fail_on=config.reviews.fail_on,
                compliance_findings=review_res.compliance_findings,
                drift_violations=review_res.drift_violations,
            )

            if check_run_id:
                await self.client.update_check_run(
                    owner=owner,
                    repo=repo,
                    check_run_id=check_run_id,
                    status="completed",
                    conclusion=conclusion,
                    output=cr_output,
                    installation_id=installation_id,
                )
                for batch in extra_batches:
                    try:
                        await self.client.update_check_run(
                            owner=owner,
                            repo=repo,
                            check_run_id=check_run_id,
                            status="completed",
                            output={"title": cr_output["title"], "summary": cr_output["summary"], "annotations": batch},
                            installation_id=installation_id,
                        )
                    except Exception:
                        pass

            # Update tracked last reviewed SHA & record rate usage
            self._last_reviewed_sha[pr_key] = head_sha
            self.latest_review_findings[pr_key] = list(review_res.findings)
            if installation_id:
                self.limiter.record_review_completion(installation_id)

        except Exception as exc:
            logger.error("pr_review_failed", owner=owner, repo=repo, pull_number=pull_number, error=str(exc))
            if check_run_id:
                try:
                    await self.client.update_check_run(
                        owner=owner,
                        repo=repo,
                        check_run_id=check_run_id,
                        status="completed",
                        conclusion="neutral",
                        output={
                            "title": "AgentBlackBox: Review Incomplete",
                            "summary": f"Automated in-memory review encountered an internal processing error: {exc}",
                        },
                        installation_id=installation_id,
                    )
                except Exception:
                    pass

    async def handle_issue_comment_event(self, payload: Dict[str, Any]) -> None:
        """Handle comment mentions e.g. '@agentblackbox review', 'full review', 'pause', 'resume', 'help'."""
        if payload.get("action") != "created":
            return

        issue = payload.get("issue", {})
        if "pull_request" not in issue:
            return

        comment = payload.get("comment", {})
        body = (comment.get("body") or "").strip().lower()
        if "@agentblackbox" not in body:
            return

        repo_data = payload.get("repository", {})
        owner = repo_data.get("owner", {}).get("login", "")
        repo = repo_data.get("name", "")
        pull_number = issue.get("number")
        installation_id = payload.get("installation", {}).get("id")

        if "help" in body:
            help_text = (
                "### 🛸 AgentBlackBox Bot Commands\n"
                "- `@agentblackbox fix`: Automatically generate a remediation PR with safe 1-click fixes for active findings.\n"
                "- `@agentblackbox review`: Re-run automated review on the latest commit.\n"
                "- `@agentblackbox full review`: Force full analysis of all changed files without cache.\n"
                "- `@agentblackbox pause`: Temporarily pause automated PR reviews on this pull request.\n"
                "- `@agentblackbox resume`: Resume automated PR reviews on this pull request.\n"
                "- `@agentblackbox resolve`: Mark active review findings as acknowledged.\n"
                "- `@agentblackbox help`: Display this command reference.\n"
            )
            await self.client.create_issue_comment(
                owner=owner,
                repo=repo,
                issue_number=pull_number,
                body=help_text,
                installation_id=installation_id,
            )
            return

        pr_key = (owner.lower(), repo.lower(), pull_number)

        if "fix" in body or "autofix" in body:
            try:
                pr = await self.client.get_pull_request(owner=owner, repo=repo, pull_number=pull_number, installation_id=installation_id)
                head_sha = pr.get("head", {}).get("sha", "")
                head_branch = pr.get("head", {}).get("ref", "main")

                findings = self.latest_review_findings.get(pr_key, [])
                if not findings:
                    # Scan diff on-demand if no cached findings
                    raw_diff = await self.client.get_pull_request_diff(owner=owner, repo=repo, pull_number=pull_number, installation_id=installation_id)
                    res = await self.review_runner.execute_review(raw_diff=raw_diff, pr_title=pr.get("title", ""))
                    findings = res.findings
                    self.latest_review_findings[pr_key] = findings

                remediation = await self.autofix_engine.create_remediation_pr(
                    owner=owner,
                    repo=repo,
                    pull_number=pull_number,
                    head_sha=head_sha,
                    head_branch=head_branch,
                    findings=findings,
                    installation_id=installation_id,
                )

                if remediation.success and remediation.pr_url:
                    comment_body = (
                        f"✅ **Automated Remediation PR Created!**\n\n"
                        f"- **Fix PR**: [{remediation.pr_url}]({remediation.pr_url})\n"
                        f"- **Branch**: `{remediation.branch_name}`\n"
                        f"- **Applied**: {remediation.applied_fixes_count} fix(es) across `{len(remediation.modified_files)}` file(s).\n\n"
                        f"Review the diff and merge into `{head_branch}` to apply."
                    )
                else:
                    comment_body = f"ℹ️ **AgentBlackBox AutoFix**: {remediation.message}"

                await self.client.create_issue_comment(
                    owner=owner,
                    repo=repo,
                    issue_number=pull_number,
                    body=comment_body,
                    installation_id=installation_id,
                )
            except Exception as exc:
                logger.error("autofix_execution_failed", error=str(exc))
                await self.client.create_issue_comment(
                    owner=owner,
                    repo=repo,
                    issue_number=pull_number,
                    body=f"❌ Failed to generate automated remediation: {exc}",
                    installation_id=installation_id,
                )
            return

        if "pause" in body:
            self.limiter.set_pr_paused(owner, repo, pull_number, True)
            await self.client.create_issue_comment(
                owner=owner,
                repo=repo,
                issue_number=pull_number,
                body="⏸️ **AgentBlackBox reviews paused** on PR #" + str(pull_number) + ". Mention `@agentblackbox resume` to re-enable.",
                installation_id=installation_id,
            )
            return

        if "resume" in body:
            self.limiter.set_pr_paused(owner, repo, pull_number, False)
            await self.client.create_issue_comment(
                owner=owner,
                repo=repo,
                issue_number=pull_number,
                body="▶️ **AgentBlackBox reviews resumed** on PR #" + str(pull_number) + ". Triggering fresh audit...",
                installation_id=installation_id,
            )
            # Trigger fresh review
            pr = await self.client.get_pull_request(owner=owner, repo=repo, pull_number=pull_number, installation_id=installation_id)
            synthetic_payload = {
                "action": "synchronize",
                "pull_request": pr,
                "repository": repo_data,
                "installation": payload.get("installation"),
            }
            await self.handle_pull_request_event(synthetic_payload)
            return

        if "review" in body:
            try:
                pr = await self.client.get_pull_request(owner=owner, repo=repo, pull_number=pull_number, installation_id=installation_id)
                synthetic_payload = {
                    "action": "synchronize",
                    "pull_request": pr,
                    "repository": repo_data,
                    "installation": payload.get("installation"),
                }
                await self.handle_pull_request_event(synthetic_payload)
            except Exception as exc:
                logger.error("manual_review_trigger_failed", error=str(exc))
