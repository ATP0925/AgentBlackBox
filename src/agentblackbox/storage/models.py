"""Data models for AgentBlackBox events and sessions."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
import hashlib
import json
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

    def __post_init__(self) -> None:
        """Compute payload hash after init."""
        if not self.payload_hash and self.payload:
            self.payload_hash = _hash_payload(self.payload)


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

