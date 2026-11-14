"""Event Router for GitHub Webhook Events."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog

from agentblackbox.github_app.client import GitHubClient
from agentblackbox.github_app.config import load_repo_config
from agentblackbox.github_app.diff import DiffMapper
from agentblackbox.github_app.formatter import (
    WALKTHROUGH_MARKER,
    format_check_run_output,
    format_inline_review_comments,
    format_walkthrough,
)
from agentblackbox.github_app.review_engine import GitHubReviewRunner

logger = structlog.get_logger(__name__)


class GitHubEventHandler:
    """Dispatches and processes GitHub webhook events."""

    def __init__(
        self,
        client: GitHubClient,
        review_runner: Optional[GitHubReviewRunner] = None,
    ) -> None:
        self.client = client
        self.review_runner = review_runner or GitHubReviewRunner()

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
            # 3. Fetch PR raw diff
            raw_diff = await self.client.get_pull_request_diff(
                owner=owner,
                repo=repo,
                pull_number=pull_number,
                installation_id=installation_id,
            )

            # 4. Fetch changed files contents from head_sha (strictly in-memory)
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

            # 5. Fetch existing comments for deduplication
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

            # 6. Execute Review Runner
            self.review_runner.config = config
            review_res = await self.review_runner.execute_review(
                raw_diff=raw_diff,
                pr_files_content=files_content,
                existing_comments=existing_comments,
            )

            # 7. Format inline review comments & submit batch review
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

            # 8. Post or update single Walkthrough comment
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
            )

            # Look for existing walkthrough comment to edit in place
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

            # 9. Update Check Run conclusion and annotations
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
                # Send extra batches if any (>50 annotations)
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
                            "summary": f"Automated review encountered an internal processing error: {exc}",
                        },
                        installation_id=installation_id,
                    )
                except Exception:
                    pass

    async def handle_issue_comment_event(self, payload: Dict[str, Any]) -> None:
        """Handle comment mentions e.g. '@agentblackbox review', 'help', 'resolve'."""
        if payload.get("action") != "created":
            return

        issue = payload.get("issue", {})
        if "pull_request" not in issue:
            # Issue comment on standard issue, not a pull request
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
                "### 🐰 AgentBlackBox Bot Commands\n"
                "- `@agentblackbox review`: Re-run full review on the latest commit.\n"
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

        if "review" in body:
            # Fetch latest PR state and trigger review
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
