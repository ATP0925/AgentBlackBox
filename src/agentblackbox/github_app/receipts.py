"""Cryptographic Signed Review Receipts.

Records tamper-evident review receipts in the AgentBlackBox Merkle flight ledger.
Preserves provable zero retention: hashes only (diff SHA-256, config hash, finding hashes),
never storing customer source code or diffs.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity

logger = structlog.get_logger(__name__)


@dataclass
class ReviewReceipt:
    """Cryptographic receipt proving an automated review was performed with specific inputs."""
    receipt_id: str
    owner: str
    repo: str
    pull_number: int
    head_sha: str
    diff_hash: str  # SHA-256 of raw diff (hash only, never diff content)
    config_hash: str  # SHA-256 of .agentblackbox.yaml
    model_id: str
    finding_hashes: List[str]
    total_findings: int
    critical_count: int
    high_count: int
    created_at: float
    session_id: str
    chain_tip_hash: str = ""
    event_seq: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReviewReceiptManager:
    """Generates and cryptographically seals review receipts into the local flight recorder."""

    def __init__(self, db_path: Optional[Path] = None, store: Optional[EventStore] = None) -> None:
        if store:
            self.store = store
            self.db_path = store.db_path
            return
        if db_path:
            self.db_path = db_path
        else:
            env_db = os.environ.get("ABB_DB_PATH")
            if env_db:
                self.db_path = Path(env_db)
            else:
                self.db_path = Path.cwd() / ".agentblackbox" / "events.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.store = EventStore(self.db_path)

    def generate_receipt(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        head_sha: str,
        raw_diff: str,
        config_yaml: str,
        findings: List[Any],
        model_id: str = "agentblackbox-engine-v0.5.0",
    ) -> ReviewReceipt:
        """Create and commit a signed review receipt into the HMAC-SHA256 flight chain.
        
        Zero Customer Code Retention: Hashes the diff and config, immediately discarding them.
        """
        diff_sha = hashlib.sha256(raw_diff.encode("utf-8")).hexdigest() if raw_diff else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        config_sha = hashlib.sha256(config_yaml.encode("utf-8")).hexdigest() if config_yaml else "empty-config"

        finding_hashes = [
            hashlib.sha256(f"{f.rule_id}:{f.file_path}:{f.line_start}:{f.severity.name}".encode("utf-8")).hexdigest()[:16]
            for f in findings
        ]

        crit_count = sum(1 for f in findings if getattr(f, "severity", None) and f.severity.name == "CRITICAL")
        high_count = sum(1 for f in findings if getattr(f, "severity", None) and f.severity.name == "HIGH")

        receipt_id = f"abb-rcpt-{uuid.uuid4().hex[:12]}"
        session_id = f"gh-{owner.lower()}-{repo.lower()}"

        # Ensure session exists
        session = self.store.get_session(session_id)
        if not session:
            session = Session(
                id=session_id,
                name=f"GitHub Reviews: {owner}/{repo}",
                workspace_path=f"github://{owner}/{repo}",
                agent_hint="agentblackbox-pr-reviewer",
            )
            self.store.create_session(session)

        now = time.time()
        payload = {
            "receipt_id": receipt_id,
            "owner": owner,
            "repo": repo,
            "pull_number": pull_number,
            "head_sha": head_sha,
            "diff_hash": diff_sha,
            "config_hash": config_sha,
            "model_id": model_id,
            "finding_hashes": finding_hashes,
            "total_findings": len(findings),
            "critical_count": crit_count,
            "high_count": high_count,
            "timestamp": now,
        }

        event = Event(
            session_id=session_id,
            event_type="review_receipt",
            severity=Severity.INFO,
            source_path=f"pulls/{pull_number}",
            payload=payload,
            tags="pr-review,receipt,signed",
        )
        saved_event = self.store.record_event(event)

        return ReviewReceipt(
            receipt_id=receipt_id,
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            head_sha=head_sha,
            diff_hash=diff_sha,
            config_hash=config_sha,
            model_id=model_id,
            finding_hashes=finding_hashes,
            total_findings=len(findings),
            critical_count=crit_count,
            high_count=high_count,
            created_at=now,
            session_id=session_id,
            chain_tip_hash=saved_event.event_hash or "",
            event_seq=saved_event.seq,
        )

    def verify_receipt(self, receipt_id: str) -> Tuple[bool, Optional[ReviewReceipt], str]:
        """Verify the integrity of a review receipt against the cryptographic event chain.
        
        Returns:
            Tuple of (is_valid, receipt_object, verification_message).
        """
        # Find event matching receipt_id
        import sqlite3
        conn = sqlite3.connect(str(self.db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT session_id, payload, event_hash, seq FROM events WHERE payload LIKE ?",
                (f'%"{receipt_id}"%',),
            )
            row = cur.fetchone()
        finally:
            conn.close()

        if not row:
            return False, None, f"Receipt '{receipt_id}' not found in flight ledger."

        session_id, payload_json, event_hash, seq = row
        try:
            data = json.loads(payload_json) if isinstance(payload_json, str) else payload_json
        except Exception:
            return False, None, "Corrupted receipt payload in database."

        if data.get("receipt_id") != receipt_id:
            return False, None, f"Receipt ID mismatch: expected {receipt_id}"

        # Verify hash chain of session
        verif = self.store.verify_chain(session_id)
        if not verif.valid:
            return False, None, f"TAMPER DETECTED: Hash chain broken at seq #{verif.broken_at_seq}! Details: {verif.reason}"

        receipt = ReviewReceipt(
            receipt_id=receipt_id,
            owner=data.get("owner", ""),
            repo=data.get("repo", ""),
            pull_number=data.get("pull_number", 0),
            head_sha=data.get("head_sha", ""),
            diff_hash=data.get("diff_hash", ""),
            config_hash=data.get("config_hash", ""),
            model_id=data.get("model_id", ""),
            finding_hashes=data.get("finding_hashes", []),
            total_findings=data.get("total_findings", 0),
            critical_count=data.get("critical_count", 0),
            high_count=data.get("high_count", 0),
            created_at=data.get("timestamp", 0.0),
            session_id=session_id,
            chain_tip_hash=event_hash or "",
            event_seq=seq,
        )

        return True, receipt, f"Cryptographic receipt {receipt_id} verified against tamper-evident chain ({verif.total_events} events)."
