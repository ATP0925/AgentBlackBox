"""Data models for AgentBlackBox events, sessions, snapshots, and alerts."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
import hashlib
import hmac
import json
import os
import uuid


def _utcnow() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    """Generate a new session ID."""
    return f"sess-{uuid.uuid4().hex[:12]}"


def _hash_payload(payload: dict) -> str:
    """SHA256 hash of payload for integrity verification.

    Args:
        payload: Dictionary to hash.

    Returns:
        Hex digest string.
    """
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _compute_event_hash_v1(event: "Event") -> str:
    """Compute legacy v1 SHA256 hash without version field or tags for backward compatibility."""
    canonical = {
        "session_id": event.session_id,
        "seq": event.seq,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "severity": event.severity,
        "risk_score": round(float(event.risk_score), 4),
        "source_path": event.source_path,
        "payload_hash": event.payload_hash,
        "prev_hash": event.prev_hash,
        "agent_id": event.agent_id,
        "pid": event.pid,
        "parent_event_id": event.parent_event_id,
        "blob_hash": event.blob_hash,
    }
    raw = json.dumps(canonical, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _compute_event_hash(event: "Event", hmac_key: Optional[bytes] = None) -> str:
    """Compute SHA256 (or HMAC-SHA256) hash chaining this event to its predecessor.

    Canonical v2 hash covers sequence number, previous hash, session ID,
    timestamp, event type, payload hash, source path, attribution fields
    (agent_id, pid, parent_event_id), blob reference, severity, risk score,
    and sorted tags. Uses deterministic JSON with sorted keys and tight separators.

    If ``hmac_key`` or environment variable ``ABB_HMAC_KEY`` is set, produces an
    HMAC-SHA256 digest preventing recomputation attacks by agents with local DB access.

    Args:
        event: Event with ``seq``, ``prev_hash``, and ``payload_hash`` populated.
        hmac_key: Optional bytes key for HMAC signing.

    Returns:
        Hex digest string.
    """
    canonical = {
        "v": 2,
        "seq": event.seq,
        "prev_hash": event.prev_hash,
        "session_id": event.session_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "payload_hash": event.payload_hash or "",
        "source_path": event.source_path,
        "agent_id": event.agent_id,
        "pid": event.pid,
        "parent_event_id": event.parent_event_id,
        "blob_hash": event.blob_hash,
        "severity": event.severity.value if hasattr(event.severity, "value") else str(event.severity),
        "risk_score": round(float(event.risk_score), 4),
        "tags": sorted(event.tags) if event.tags else [],
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    if hmac_key is None:
        key_env = os.environ.get("ABB_HMAC_KEY")
        if key_env:
            hmac_key = key_env.encode("utf-8")
    if hmac_key:
        return hmac.new(hmac_key, raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------- Event Types ----------
# Use ONLY these constants. Never use raw strings.

class EventType:
    """Enumeration of all valid event types."""
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    CMD_EXECUTE = "cmd_execute"
    CMD_OUTPUT = "cmd_output"
    GIT_ADD = "git_add"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    GIT_FORCE_PUSH = "git_force_push"
    GIT_RESET = "git_reset"
    PROCESS_SPAWN = "process_spawn"
    PROCESS_EXIT = "process_exit"
    SECRET_DETECTED = "secret_detected"

    ALL = [
        FILE_CREATE, FILE_MODIFY, FILE_DELETE, FILE_RENAME,
        CMD_EXECUTE, CMD_OUTPUT,
        GIT_ADD, GIT_COMMIT, GIT_PUSH, GIT_FORCE_PUSH, GIT_RESET,
        PROCESS_SPAWN, PROCESS_EXIT,
        SECRET_DETECTED,
    ]


class Severity:
    """Enumeration of severity levels."""
    INFO = "info"
    WARNING = "warning"
    DANGER = "danger"
    CRITICAL = "critical"


# ---------- Data Classes ----------

@dataclass
class Event:
    """A single recorded event in a session.

    Attributes:
        session_id: ID of the parent session.
        event_type: Type from EventType constants.
        timestamp: ISO 8601 UTC timestamp.
        severity: Severity level.
        risk_score: Numeric risk 0.0-10.0.
        source_path: File path if applicable.
        payload: Event-specific data dictionary.
        tags: List of string tags for categorization.
        id: Auto-assigned database row ID.
        payload_hash: SHA256 of payload for integrity.
        seq: Monotonic per-session sequence number (1-indexed once stored).
        prev_hash: Hash of previous event in session (``GENESIS`` for seq 1).
        event_hash: SHA256 chain hash of this event.
        agent_id: Attributed agent identifier (e.g., ``claude-code``, ``cursor``).
        pid: Process ID attributed to the event.
        parent_event_id: Parent event ID linking file/git mutations to commands.
        blob_hash: SHA256 content hash in BlobStore if a snapshot was saved.
    """

    session_id: str
    event_type: str
    timestamp: str = field(default_factory=_utcnow)
    severity: str = Severity.INFO
    risk_score: float = 0.0
    source_path: Optional[str] = None
    payload: dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    id: Optional[int] = None
    payload_hash: str = ""
    seq: int = 0
    prev_hash: str = ""
    event_hash: str = ""
    hash_version: int = 2
    agent_id: Optional[str] = None
    pid: Optional[int] = None
    parent_event_id: Optional[int] = None
    blob_hash: Optional[str] = None

    def __post_init__(self) -> None:
        """Compute payload hash after init."""
        if not self.payload_hash and self.payload:
            self.payload_hash = _hash_payload(self.payload)


@dataclass
class FileSnapshot:
    """Metadata linking an event to a content-addressed file blob.

    Attributes:
        session_id: Parent session ID.
        file_path: Path of the snapshotted file.
        blob_hash: SHA256 digest in BlobStore.
        size_bytes: Size of stored (redacted) blob in bytes.
        event_id: Database ID of the triggering event.
        timestamp: ISO 8601 UTC timestamp.
        id: Auto-assigned database row ID.
    """

    session_id: str
    file_path: str
    blob_hash: str
    size_bytes: int = 0
    event_id: Optional[int] = None
    timestamp: str = field(default_factory=_utcnow)
    id: Optional[int] = None


@dataclass
class ChainVerificationResult:
    """Result of verifying a session's tamper-evident event hash chain.

    Attributes:
        session_id: Verified session identifier.
        valid: True if every event passes sequence, payload, and hash-chain checks.
        total_events: Number of events checked.
        broken_at_seq: Sequence number where verification first failed, if any.
        reason: Human-readable explanation when invalid.
    """

    session_id: str
    valid: bool
    total_events: int = 0
    broken_at_seq: Optional[int] = None
    reason: Optional[str] = None


@dataclass
class Session:
    """A recording session — one per `abb start` invocation.

    Attributes:
        id: Unique session identifier.
        name: Human-readable name.
        workspace_path: Directory being monitored.
        agent_hint: Which AI agent is running (optional).
        started_at: ISO 8601 start time.
        ended_at: ISO 8601 end time (None if recording).
        status: Current state: recording | stopped.
        total_events: Count of events in this session.
        risk_score: Aggregate risk score.
    """

    workspace_path: str
    id: str = field(default_factory=_new_id)
    name: Optional[str] = None
    agent_hint: Optional[str] = None
    started_at: str = field(default_factory=_utcnow)
    ended_at: Optional[str] = None
    status: str = "recording"
    total_events: int = 0
    risk_score: float = 0.0
    v1_max_seq: int = 0
    is_keyed: bool = False

    def stop(self) -> None:
        """Mark session as stopped."""
        self.ended_at = _utcnow()
        self.status = "stopped"


@dataclass
class Alert:
    """A flagged high-risk event.

    Attributes:
        event_id: ID of the triggering event.
        session_id: Parent session.
        alert_type: Category of alert.
        description: Human-readable explanation.
        acknowledged: Whether user has seen this.
        created_at: When the alert was raised.
        id: Auto-assigned database row ID.
    """

    event_id: int
    session_id: str
    alert_type: str
    description: str
    acknowledged: bool = False
    created_at: str = field(default_factory=_utcnow)
    id: Optional[int] = None
