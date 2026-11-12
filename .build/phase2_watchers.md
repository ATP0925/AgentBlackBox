# PHASE 2: Watchers & Analysis
# ============================
# Prerequisites: Phase 1 complete, 12 tests passing.
# After this phase: File watching, secret detection, risk scoring work.
# New tests: 22 (total: 34)
#
# READ AGENTS.md FIRST.

## STEP 1: Create src/agentblackbox/watchers/base.py

```python
"""Abstract base class for all watchers."""

from abc import ABC, abstractmethod
from typing import Callable, List

from agentblackbox.storage.models import Event


class BaseWatcher(ABC):
    """Base class that all watchers must inherit.

    Args:
        session_id: The active session ID.
        on_event: Callback invoked with each new Event.
    """

    def __init__(self, session_id: str, on_event: Callable[[Event], None]) -> None:
        self.session_id = session_id
        self.on_event = on_event
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """Begin watching. Must be non-blocking or run in a thread."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop watching and clean up resources."""
        ...

    @property
    def is_running(self) -> bool:
        """Whether this watcher is currently active."""
        return self._running
```

## STEP 2: Create src/agentblackbox/watchers/filesystem.py

This is the MOST important watcher. Uses `watchdog` library:

```python
"""Filesystem watcher — tracks file create/modify/delete/rename events."""

import fnmatch
import hashlib
import time
from pathlib import Path
from threading import Timer
from typing import Callable, Dict, List, Optional, Set

import structlog
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from agentblackbox.storage.models import Event, EventType, Severity
from agentblackbox.watchers.base import BaseWatcher

logger = structlog.get_logger()


def _should_ignore(path: str, patterns: List[str]) -> bool:
    """Check if a path matches any ignore pattern.

    Args:
        path: File path to check.
        patterns: List of glob patterns to match against.

    Returns:
        True if path should be ignored.
    """
    parts = Path(path).parts
    for pattern in patterns:
        # Check against each path component
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
        # Check against full path
        if fnmatch.fnmatch(path, pattern):
            return True
    return False


def _file_hash(path: Path) -> Optional[str]:
    """Compute SHA256 hash of a file's content.

    Args:
        path: File to hash.

    Returns:
        Hex digest string, or None if file can't be read.
    """
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, PermissionError):
        return None


class _DebouncedHandler(FileSystemEventHandler):
    """Watchdog event handler with debouncing to avoid event storms.

    Groups rapid changes to the same file within a time window.

    Args:
        session_id: Active session ID.
        on_event: Callback for processed events.
        ignore_patterns: Patterns to skip.
        debounce_seconds: Time window for grouping events.
        max_file_size: Skip files larger than this (bytes).
    """

    def __init__(
        self,
        session_id: str,
        on_event: Callable[[Event], None],
        ignore_patterns: List[str],
        debounce_seconds: float = 0.5,
        max_file_size: int = 1_048_576,
    ) -> None:
        super().__init__()
        self.session_id = session_id
        self.on_event = on_event
        self.ignore_patterns = ignore_patterns
        self.debounce_seconds = debounce_seconds
        self.max_file_size = max_file_size
        self._timers: Dict[str, Timer] = {}
        self._last_hashes: Dict[str, str] = {}

    def _debounced_emit(self, path: str, event_type: str) -> None:
        """Emit an event after debounce period, deduplicating by content hash."""
        file_path = Path(path)

        # Skip directories
        if file_path.is_dir():
            return

        # Skip large files
        try:
            if file_path.exists() and file_path.stat().st_size > self.max_file_size:
                return
        except OSError:
            return

        # Content hash dedup for modifications
        if event_type == EventType.FILE_MODIFY and file_path.exists():
            current_hash = _file_hash(file_path)
            if current_hash and current_hash == self._last_hashes.get(path):
                return  # File content didn't actually change
            if current_hash:
                self._last_hashes[path] = current_hash

        # Determine severity
        severity = Severity.INFO
        tags: List[str] = []

        if any(s in path.lower() for s in [".env", "secret", "credential", "token", ".pem", ".key"]):
            severity = Severity.WARNING
            tags.append("sensitive_file")

        event = Event(
            session_id=self.session_id,
            event_type=event_type,
            source_path=path,
            severity=severity,
            payload={
                "file_size": file_path.stat().st_size if file_path.exists() else 0,
                "content_hash": self._last_hashes.get(path, ""),
            },
            tags=tags,
        )
        self.on_event(event)

    def _schedule(self, path: str, event_type: str) -> None:
        """Schedule a debounced event emission."""
        key = f"{path}:{event_type}"
        if key in self._timers:
            self._timers[key].cancel()
        timer = Timer(self.debounce_seconds, self._debounced_emit, args=[path, event_type])
        timer.daemon = True
        timer.start()
        self._timers[key] = timer

    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle file creation."""
        if not _should_ignore(event.src_path, self.ignore_patterns):
            self._schedule(event.src_path, EventType.FILE_CREATE)

    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file modification."""
        if not _should_ignore(event.src_path, self.ignore_patterns):
            self._schedule(event.src_path, EventType.FILE_MODIFY)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        """Handle file deletion."""
        if not _should_ignore(event.src_path, self.ignore_patterns):
            self._schedule(event.src_path, EventType.FILE_DELETE)

    def on_moved(self, event: FileMovedEvent) -> None:
        """Handle file rename/move."""
        if not _should_ignore(event.src_path, self.ignore_patterns):
            e = Event(
                session_id=self.session_id,
                event_type=EventType.FILE_RENAME,
                source_path=event.src_path,
                payload={"dest_path": event.dest_path},
                tags=[],
            )
            self.on_event(e)

    def cancel_all_timers(self) -> None:
        """Cancel all pending debounce timers."""
        for timer in self._timers.values():
            timer.cancel()
        self._timers.clear()


class FileSystemWatcher(BaseWatcher):
    """Watches a directory tree for file changes using watchdog.

    Args:
        session_id: Active session ID.
        on_event: Callback for new events.
        watch_path: Directory to monitor.
        ignore_patterns: Glob patterns to skip.
        debounce_seconds: Debounce window.
        max_file_size: Skip files larger than this.
    """

    def __init__(
        self,
        session_id: str,
        on_event: Callable[[Event], None],
        watch_path: Path,
        ignore_patterns: Optional[List[str]] = None,
        debounce_seconds: float = 0.5,
        max_file_size: int = 1_048_576,
    ) -> None:
        super().__init__(session_id, on_event)
        self.watch_path = watch_path
        self.ignore_patterns = ignore_patterns or []
        self._handler = _DebouncedHandler(
            session_id=session_id,
            on_event=on_event,
            ignore_patterns=self.ignore_patterns,
            debounce_seconds=debounce_seconds,
            max_file_size=max_file_size,
        )
        self._observer = Observer()

    def start(self) -> None:
        """Start watching the directory tree."""
        self._observer.schedule(self._handler, str(self.watch_path), recursive=True)
        self._observer.start()
        self._running = True
        logger.info("filesystem_watcher_started", path=str(self.watch_path))

    def stop(self) -> None:
        """Stop watching and clean up."""
        self._handler.cancel_all_timers()
        self._observer.stop()
        self._observer.join(timeout=5)
        self._running = False
        logger.info("filesystem_watcher_stopped")
```

## STEP 3: Create src/agentblackbox/analysis/secret_detector.py

```python
"""Detect secrets (API keys, tokens, passwords) in event payloads and file content."""

import math
import re
from dataclasses import dataclass
from typing import List, Optional

# Pre-compiled patterns for known secret formats
_SECRET_PATTERNS = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*\S{20,}"), "aws_secret_key"),
    # GitHub
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "github_token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "github_pat"),
    # OpenAI
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_api_key"),
    # Stripe
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "stripe_live_key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{20,}"), "stripe_test_key"),
    # Google
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
    # Slack
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "slack_token"),
    # Generic patterns
    (re.compile(r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?\S{16,}['\"]?", re.IGNORECASE), "generic_api_key"),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?\S{8,}['\"]?", re.IGNORECASE), "password"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "private_key"),
    (re.compile(r"(?:bearer|token)\s+[A-Za-z0-9\-._~+/]{20,}", re.IGNORECASE), "bearer_token"),
    # Database URLs
    (re.compile(r"(?:postgres|mysql|mongodb)://\S+:\S+@\S+"), "database_url"),
]

# Patterns that look like secrets but are actually placeholders
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"sk-[xX]{16,}"),  # sk-xxxxxxxx
    re.compile(r"your[_-]?api[_-]?key", re.IGNORECASE),
    re.compile(r"<[A-Z_]+>"),  # <API_KEY>
    re.compile(r"\$\{[A-Z_]+\}"),  # ${API_KEY}
    re.compile(r"process\.env\.\w+"),
    re.compile(r"os\.environ"),
    re.compile(r"REPLACE_ME|TODO|FIXME|CHANGEME|INSERT_HERE", re.IGNORECASE),
]


@dataclass
class SecretMatch:
    """A detected secret match.

    Attributes:
        secret_type: Category of secret (e.g., 'aws_access_key').
        matched_text: The actual matched text (redacted in logs).
        confidence: 0.0-1.0 confidence score.
        source: Where it was found ('payload', 'file_content', etc.).
    """

    secret_type: str
    matched_text: str
    confidence: float
    source: str


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    High entropy (>4.5) suggests random/encrypted data like API keys.

    Args:
        text: String to analyze.

    Returns:
        Entropy value (bits per character).
    """
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_false_positive(text: str) -> bool:
    """Check if matched text is a known false positive.

    Args:
        text: The matched text to check.

    Returns:
        True if this is likely a placeholder, not a real secret.
    """
    for pattern in _FALSE_POSITIVE_PATTERNS:
        if pattern.search(text):
            return True
    return False


def detect_secrets(text: str, source: str = "unknown") -> List[SecretMatch]:
    """Scan text for secrets using pattern matching and entropy analysis.

    Args:
        text: Text content to scan.
        source: Label for where the text came from.

    Returns:
        List of SecretMatch objects found.
    """
    matches: List[SecretMatch] = []

    for pattern, secret_type in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            matched_text = match.group(0)
            if _is_false_positive(matched_text):
                continue
            confidence = 0.9  # Pattern match = high confidence
            matches.append(SecretMatch(
                secret_type=secret_type,
                matched_text=matched_text[:8] + "..." + matched_text[-4:] if len(matched_text) > 16 else matched_text,
                confidence=confidence,
                source=source,
            ))

    # Entropy-based detection for unmatched high-entropy strings
    # Look for assignments like KEY = "very-random-string"
    assign_pattern = re.compile(
        r'(?:key|secret|token|password|credential|auth)\s*[:=]\s*["\']([^"\']{16,})["\']',
        re.IGNORECASE,
    )
    for match in assign_pattern.finditer(text):
        value = match.group(1)
        if _is_false_positive(value):
            continue
        entropy = _shannon_entropy(value)
        if entropy > 4.0:
            # Check it wasn't already caught by pattern matching
            already_found = any(value[:8] in m.matched_text for m in matches)
            if not already_found:
                matches.append(SecretMatch(
                    secret_type="high_entropy_secret",
                    matched_text=value[:8] + "...",
                    confidence=min(0.5 + (entropy - 4.0) * 0.2, 0.95),
                    source=source,
                ))

    return matches
```

## STEP 4: Create src/agentblackbox/analysis/risk_scorer.py

```python
"""Risk scoring for events — assigns 0-10 risk score based on event characteristics."""

from agentblackbox.storage.models import Event, EventType, Severity


# Risk score rules — deterministic, no ambiguity
_BASE_RISK: dict[str, float] = {
    EventType.FILE_CREATE: 0.5,
    EventType.FILE_MODIFY: 1.0,
    EventType.FILE_DELETE: 3.0,
    EventType.FILE_RENAME: 1.0,
    EventType.CMD_EXECUTE: 2.0,
    EventType.CMD_OUTPUT: 0.5,
    EventType.GIT_ADD: 1.0,
    EventType.GIT_COMMIT: 1.5,
    EventType.GIT_PUSH: 2.0,
    EventType.GIT_FORCE_PUSH: 9.0,
    EventType.GIT_RESET: 5.0,
    EventType.PROCESS_SPAWN: 1.5,
    EventType.PROCESS_EXIT: 0.5,
    EventType.SECRET_DETECTED: 8.0,
}

# Patterns that increase risk score
_DANGEROUS_COMMANDS = [
    ("rm -rf", 4.0),
    ("rm -r", 3.0),
    ("git push --force", 5.0),
    ("git push -f", 5.0),
    ("git reset --hard", 4.0),
    ("chmod 777", 3.0),
    ("curl | bash", 5.0),
    ("curl | sh", 5.0),
    ("wget | bash", 5.0),
    ("eval(", 3.0),
    ("exec(", 3.0),
    ("> /dev/null", 1.0),  # output suppression
    ("DROP TABLE", 5.0),
    ("DELETE FROM", 3.0),
    ("TRUNCATE", 4.0),
]

_SENSITIVE_PATHS = [
    (".env", 3.0),
    (".pem", 4.0),
    (".key", 4.0),
    ("id_rsa", 5.0),
    ("credentials", 3.0),
    ("secret", 2.0),
    (".git/config", 2.0),
]


def score_event(event: Event) -> Event:
    """Calculate and assign risk score to an event.

    Modifies the event in-place: sets risk_score and severity.
    Scoring is additive:
      base_risk + command_bonus + path_bonus + tag_bonus

    Args:
        event: Event to score.

    Returns:
        The same event with risk_score and severity updated.
    """
    risk = _BASE_RISK.get(event.event_type, 1.0)

    # Check payload for dangerous commands
    payload_str = str(event.payload).lower()
    for pattern, bonus in _DANGEROUS_COMMANDS:
        if pattern.lower() in payload_str:
            risk += bonus

    # Check source path for sensitive files
    if event.source_path:
        path_lower = event.source_path.lower()
        for pattern, bonus in _SENSITIVE_PATHS:
            if pattern in path_lower:
                risk += bonus

    # Check tags
    if "secret" in event.tags or "sensitive_file" in event.tags:
        risk += 2.0

    # Clamp to 0-10
    risk = min(max(risk, 0.0), 10.0)
    event.risk_score = round(risk, 1)

    # Set severity based on risk score
    if risk >= 8.0:
        event.severity = Severity.CRITICAL
    elif risk >= 5.0:
        event.severity = Severity.DANGER
    elif risk >= 3.0:
        event.severity = Severity.WARNING
    else:
        event.severity = Severity.INFO

    return event
```

## STEP 5: Create src/agentblackbox/analysis/pattern_matcher.py

```python
"""Pattern matching for known dangerous operations."""

import re
from typing import List, Optional

from agentblackbox.storage.models import Event, EventType


# Dangerous command patterns
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"rm\s+(-[rRf]+\s+|--recursive|--force)"),
    re.compile(r"git\s+push\s+.*(-f|--force)"),
    re.compile(r"git\s+reset\s+--hard"),
    re.compile(r"git\s+clean\s+-[fFdDxX]"),
    re.compile(r"chmod\s+777"),
    re.compile(r"curl\s.*\|\s*(ba)?sh"),
    re.compile(r"wget\s.*\|\s*(ba)?sh"),
    re.compile(r"dd\s+if=.*of="),
    re.compile(r"mkfs\.", re.IGNORECASE),
    re.compile(r":()\{\s*:\|\s*:&\s*\};\s*:"),  # fork bomb
]


def is_destructive_command(command: str) -> bool:
    """Check if a shell command matches known destructive patterns.

    Args:
        command: The command string to check.

    Returns:
        True if the command is potentially destructive.
    """
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return True
    return False


def classify_event(event: Event) -> List[str]:
    """Add classification tags to an event based on its content.

    Args:
        event: Event to classify.

    Returns:
        List of tags added.
    """
    added_tags: List[str] = []

    if event.event_type == EventType.CMD_EXECUTE:
        cmd = event.payload.get("command", "")
        if is_destructive_command(cmd):
            added_tags.append("destructive")

    if event.event_type in (EventType.GIT_FORCE_PUSH, EventType.GIT_RESET):
        added_tags.append("destructive")

    if event.event_type == EventType.FILE_DELETE:
        added_tags.append("deletion")

    if event.source_path and any(
        s in event.source_path.lower()
        for s in [".env", ".key", ".pem", "secret", "credential", "token"]
    ):
        added_tags.append("sensitive_file")

    event.tags = list(set(event.tags + added_tags))
    return added_tags
```

## STEP 6: Create tests/test_watchers/test_filesystem.py

```python
"""Tests for filesystem watcher."""

import time
from pathlib import Path
from typing import List

import pytest

from agentblackbox.storage.models import Event, EventType
from agentblackbox.watchers.filesystem import (
    FileSystemWatcher,
    _should_ignore,
    _file_hash,
)


class TestShouldIgnore:
    """Test the ignore pattern matching."""

    def test_ignore_pycache(self) -> None:
        assert _should_ignore("/project/__pycache__/mod.pyc", ["__pycache__"])

    def test_ignore_node_modules(self) -> None:
        assert _should_ignore("/project/node_modules/pkg/index.js", ["node_modules"])

    def test_ignore_glob_pattern(self) -> None:
        assert _should_ignore("/project/file.pyc", ["*.pyc"])

    def test_no_ignore_normal_file(self) -> None:
        assert not _should_ignore("/project/src/main.py", ["__pycache__", "*.pyc"])

    def test_ignore_git_dir(self) -> None:
        assert _should_ignore("/project/.git/objects/abc", [".git"])

    def test_ignore_env_file(self) -> None:
        assert _should_ignore("/project/.env", [".env"])


class TestFileHash:
    """Test file content hashing."""

    def test_hash_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = _file_hash(f)
        assert h is not None
        assert len(h) == 64  # SHA256 hex length

    def test_hash_nonexistent(self, tmp_path: Path) -> None:
        f = tmp_path / "nope.txt"
        assert _file_hash(f) is None

    def test_same_content_same_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("same content")
        f2.write_text("same content")
        assert _file_hash(f1) == _file_hash(f2)


class TestFileSystemWatcher:
    """Integration tests for the watcher (requires brief sleep for events)."""

    def test_detect_file_create(self, tmp_path: Path) -> None:
        events: List[Event] = []
        watcher = FileSystemWatcher(
            session_id="test-sess",
            on_event=lambda e: events.append(e),
            watch_path=tmp_path,
            ignore_patterns=["__pycache__"],
            debounce_seconds=0.1,
        )
        watcher.start()
        try:
            (tmp_path / "new_file.py").write_text("hello")
            time.sleep(0.5)
        finally:
            watcher.stop()

        create_events = [e for e in events if e.event_type == EventType.FILE_CREATE]
        assert len(create_events) >= 1
        assert "new_file.py" in (create_events[0].source_path or "")
```

## STEP 7: Create tests/test_analysis/test_secret_detector.py

```python
"""Tests for secret detection."""

import pytest
from agentblackbox.analysis.secret_detector import detect_secrets, _shannon_entropy


class TestSecretDetection:
    """Test pattern-based secret detection."""

    def test_detect_aws_key(self) -> None:
        text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "aws_access_key" for m in matches)

    def test_detect_github_token(self) -> None:
        text = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "github_token" for m in matches)

    def test_detect_openai_key(self) -> None:
        text = 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "openai_api_key" for m in matches)

    def test_detect_stripe_key(self) -> None:
        prefix = "sk_" + "live_"
        text = f'stripe.api_key = "{prefix}abcdefghijklmnopqrstuvwxyz"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "stripe_live_key" for m in matches)

    def test_detect_private_key(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "private_key" for m in matches)

    def test_no_false_positive_placeholder(self) -> None:
        text = 'API_KEY = "your-api-key-here"'
        matches = detect_secrets(text)
        # Should not flag "your-api-key-here" as a real secret
        secret_matches = [m for m in matches if m.confidence > 0.8]
        # Placeholder should not be high confidence
        assert all(
            "your" not in m.matched_text.lower() for m in secret_matches
        )

    def test_detect_database_url(self) -> None:
        text = 'DATABASE_URL = "postgres://user:pass123@db.example.com/mydb"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "database_url" for m in matches)


class TestEntropy:
    """Test Shannon entropy calculation."""

    def test_low_entropy(self) -> None:
        assert _shannon_entropy("aaaaaa") < 1.0

    def test_high_entropy(self) -> None:
        # Random-looking string
        assert _shannon_entropy("aB3$kL9!mZ2@xQ7&") > 3.5

    def test_empty_string(self) -> None:
        assert _shannon_entropy("") == 0.0
```

## STEP 8: Create tests/test_analysis/test_risk_scorer.py

```python
"""Tests for risk scoring."""

import pytest
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.storage.models import Event, EventType, Severity


class TestRiskScoring:
    """Test deterministic risk scoring."""

    def test_file_create_low_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.FILE_CREATE, source_path="src/main.py")
        scored = score_event(event)
        assert scored.risk_score < 3.0
        assert scored.severity == Severity.INFO

    def test_file_delete_medium_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.FILE_DELETE, source_path="src/main.py")
        scored = score_event(event)
        assert scored.risk_score >= 3.0
        assert scored.severity in (Severity.WARNING, Severity.DANGER)

    def test_secret_detected_high_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.SECRET_DETECTED, tags=["secret"])
        scored = score_event(event)
        assert scored.risk_score >= 8.0
        assert scored.severity == Severity.CRITICAL

    def test_rm_rf_critical(self) -> None:
        event = Event(
            session_id="s", event_type=EventType.CMD_EXECUTE,
            payload={"command": "rm -rf /tmp/project"}
        )
        scored = score_event(event)
        assert scored.risk_score >= 5.0
        assert scored.severity in (Severity.DANGER, Severity.CRITICAL)

    def test_force_push_critical(self) -> None:
        event = Event(session_id="s", event_type=EventType.GIT_FORCE_PUSH)
        scored = score_event(event)
        assert scored.risk_score >= 9.0
        assert scored.severity == Severity.CRITICAL

    def test_env_file_delete(self) -> None:
        event = Event(session_id="s", event_type=EventType.FILE_DELETE, source_path=".env")
        scored = score_event(event)
        assert scored.risk_score >= 5.0

    def test_risk_capped_at_10(self) -> None:
        event = Event(
            session_id="s", event_type=EventType.SECRET_DETECTED,
            source_path=".env.production",
            tags=["secret", "sensitive_file"],
        )
        scored = score_event(event)
        assert scored.risk_score <= 10.0

    def test_normal_git_commit_low_risk(self) -> None:
        event = Event(session_id="s", event_type=EventType.GIT_COMMIT)
        scored = score_event(event)
        assert scored.risk_score < 3.0
```

## STEP 9: Run Phase 2 tests

```bash
cd AgentBlackBox
python -m pytest tests/ -v --tb=short
```

### Expected: 34 total tests passing (12 from Phase 1 + 22 new)

## ✅ PHASE 2 COMPLETE CHECKLIST
- [ ] watchers/base.py — BaseWatcher ABC
- [ ] watchers/filesystem.py — FileSystemWatcher with debouncing
- [ ] analysis/secret_detector.py — 15 regex patterns + entropy
- [ ] analysis/risk_scorer.py — deterministic 0-10 scoring
- [ ] analysis/pattern_matcher.py — destructive command detection
- [ ] test_filesystem.py — 10 tests (ignore + hash + watcher)
- [ ] test_secret_detector.py — 10 tests
- [ ] test_risk_scorer.py — 8 tests
- [ ] ALL 34 tests PASS

## NEXT: Read `.build/phase3_investigation.md`

