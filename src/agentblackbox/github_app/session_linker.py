"""Agent-Session Linkage & PreToolUse Audit Verification.

Extracts AgentBlackBox-Session trailers from PR descriptions, commit messages, or branch names,
verifies the integrity of the agent's local flight chain, and audits what the agent did in the dark.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

from agentblackbox.models.finding import Finding, Severity
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import EventType

logger = structlog.get_logger(__name__)

SESSION_ID_PATTERNS = [
    re.compile(r"(?i)AgentBlackBox-Session:\s*([a-zA-Z0-9_\-\.]+)", re.MULTILINE),
    re.compile(r"(?i)ABB-Session:\s*([a-zA-Z0-9_\-\.]+)", re.MULTILINE),
    re.compile(r"(?i)session[-_]id:\s*([a-zA-Z0-9_\-\.]+)", re.MULTILINE),
    re.compile(r"(?i)\babb-session-([a-zA-Z0-9_\-\.]+)\b"),
]


@dataclass
class LinkedSessionSummary:
    """Summary of local agent activity linked to a pull request."""
    session_id: str
    is_valid: bool
    verification_message: str
    total_events: int = 0
    tools_called: int = 0
    commands_executed: int = 0
    files_modified: int = 0
    files_deleted: int = 0
    tests_touched: List[str] = field(default_factory=list)
    blocked_actions: int = 0
    high_risk_actions: int = 0
    tamper_detected: bool = False
    findings: List[Finding] = field(default_factory=list)


class AgentSessionLinker:
    """Discovers and audits agent sessions linked to pull requests."""

    def __init__(self, store: Optional[EventStore] = None, db_path: Optional[Path] = None) -> None:
        if store:
            self.store = store
        else:
            import os
            env_db = os.environ.get("ABB_DB_PATH")
            p = db_path or (Path(env_db) if env_db else Path.cwd() / ".agentblackbox" / "events.db")
            p.parent.mkdir(parents=True, exist_ok=True)
            self.store = EventStore(p)

    def extract_session_id(
        self,
        pr_body: str = "",
        branch_name: str = "",
        commit_messages: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Extract session ID from PR body, branch name, or git trailers."""
        # 1. Search PR body
        if pr_body:
            for pat in SESSION_ID_PATTERNS:
                m = pat.search(pr_body)
                if m:
                    return m.group(1).strip()

        # 2. Search commit trailers
        for msg in (commit_messages or []):
            for pat in SESSION_ID_PATTERNS:
                m = pat.search(msg)
                if m:
                    return m.group(1).strip()

        # 3. Search branch name
        if branch_name:
            for pat in SESSION_ID_PATTERNS:
                m = pat.search(branch_name)
                if m:
                    return m.group(1).strip()

        return None

    def audit_session(self, session_id: str) -> LinkedSessionSummary:
        """Verify session chain integrity and summarize intermediate agent activity."""
        session = self.store.get_session(session_id)
        if not session:
            return LinkedSessionSummary(
                session_id=session_id,
                is_valid=False,
                verification_message=f"Session '{session_id}' not found in local flight recorder.",
                findings=[
                    Finding(
                        title="Referenced Agent Session Not Found in Ledger",
                        severity=Severity.HIGH,
                        file_path=".agentblackbox/sessions",
                        line_start=1,
                        line_end=1,
                        category="security",
                        message=f"PR metadata references AgentBlackBox-Session '{session_id}', but no corresponding cryptographic flight record exists in the ledger.",
                        why_it_matters="Missing flight records prevent verification of intermediate shell commands, uncommitted file modifications, and potential exfiltration.",
                        suggested_fix="Ensure local flight recorder (`abb start` or PreToolUse hooks) was active during the agent's session.",
                        rule_id="SEC-SESSION-NOT-FOUND",
                    )
                ],
            )

        # Verify cryptographic hash chain
        verif = self.store.verify_chain(session_id)
        if not verif.valid:
            logger.warning("tampered_agent_session", session_id=session_id, error=verif.reason)
            return LinkedSessionSummary(
                session_id=session_id,
                is_valid=False,
                tamper_detected=True,
                verification_message=f"CRITICAL: Hash chain broken at sequence #{verif.broken_at_seq}! {verif.reason}",
                findings=[
                    Finding(
                        title="Cryptographic Flight Recorder Tampering Detected",
                        severity=Severity.CRITICAL,
                        file_path=".agentblackbox/events.db",
                        line_start=1,
                        line_end=1,
                        category="security",
                        message=(
                            f"The cryptographic flight chain for session '{session_id}' has been tampered with or modified out-of-order at seq #{verif.broken_at_seq}. "
                            f"An unauthorized process or rogue agent modified historical events."
                        ),
                        why_it_matters="Tampering with flight recorder logs indicates an active attempt to conceal unauthorized shell executions, file deletions, or credential exposure.",
                        suggested_fix="Reject this PR immediately. Inspect system logs and the out-of-tree shadow checkpoint using `abb verify --shadow`.",
                        rule_id="SEC-TAMPERED-AGENT-SESSION",
                        cwe_id="CWE-353",
                    )
                ],
            )

        # Audit events in session
        events = self.store.query_events(session_id=session_id, limit=50000)
        tools_called = 0
        commands_executed = 0
        files_modified = 0
        files_deleted = 0
        tests_touched: Set[str] = set()
        blocked_actions = 0
        high_risk_actions = 0

        for e in events:
            if e.event_type == EventType.CMD_EXECUTE:
                commands_executed += 1
                tools_called += 1
            elif e.event_type == EventType.FILE_MODIFY:
                files_modified += 1
                if "test" in (e.source_path or "").lower():
                    tests_touched.add(e.source_path)
            elif e.event_type == EventType.FILE_DELETE:
                files_deleted += 1
                if "test" in (e.source_path or "").lower():
                    tests_touched.add(e.source_path)
            elif e.event_type in (EventType.TOOL_USE, "tool_use", "mcp_call"):
                tools_called += 1

            # Check if event was blocked or had high risk
            if e.risk_score >= 7.0:
                high_risk_actions += 1
            payload = e.payload if isinstance(e.payload, dict) else {}
            if payload.get("blocked") or payload.get("action") == "blocked":
                blocked_actions += 1

        return LinkedSessionSummary(
            session_id=session_id,
            is_valid=True,
            verification_message=f"Session chain cryptographically verified ({verif.total_events} events).",
            total_events=len(events),
            tools_called=tools_called,
            commands_executed=commands_executed,
            files_modified=files_modified,
            files_deleted=files_deleted,
            tests_touched=sorted(list(tests_touched)),
            blocked_actions=blocked_actions,
            high_risk_actions=high_risk_actions,
        )
