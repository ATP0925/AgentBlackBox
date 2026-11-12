"""Filesystem watcher — tracks file create/modify/delete/rename events."""

import fnmatch
import hashlib
import sys
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
from watchdog.observers.polling import PollingObserver

from agentblackbox.storage.blob_store import BlobStore
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
        blob_store: Optional[BlobStore] = None,
        agent_id: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.session_id = session_id
        self.on_event = on_event
        self.ignore_patterns = ignore_patterns
        self.debounce_seconds = debounce_seconds
        self.max_file_size = max_file_size
        self.blob_store = blob_store
        self.agent_id = agent_id
        self._timers: Dict[str, Timer] = {}
        self._last_hashes: Dict[str, str] = {}

    def _debounced_emit(self, path: str, event_type: str) -> None:
        """Emit an event after debounce period, saving a redacted blob snapshot."""
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
        risk_score = 0.0
        tags: List[str] = []
        blob_hash: Optional[str] = None
        file_size = file_path.stat().st_size if file_path.exists() else 0

        if any(s in path.lower() for s in [".env", "secret", "credential", "token", ".pem", ".key"]):
            severity = Severity.WARNING
            tags.append("sensitive_file")

        # Save redacted file snapshot into BlobStore for create/modify
        if (
            self.blob_store is not None
            and event_type in (EventType.FILE_CREATE, EventType.FILE_MODIFY)
            and file_path.exists()
        ):
            try:
                raw_bytes = file_path.read_bytes()
                blob_hash, file_size, matches = self.blob_store.put_bytes(raw_bytes, redact=True)
                if matches:
                    severity = Severity.CRITICAL
                    risk_score = 8.0
                    tags.extend(["secret", "secret_redacted"])
            except OSError:
                pass

        event = Event(
            session_id=self.session_id,
            event_type=event_type,
            source_path=path,
            severity=severity,
            risk_score=risk_score,
            agent_id=self.agent_id,
            blob_hash=blob_hash,
            payload={
                "file_size": file_size,
                "content_hash": self._last_hashes.get(path, ""),
            },
            tags=list(dict.fromkeys(tags)),
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
        blob_store: Optional[BlobStore] = None,
        agent_id: Optional[str] = None,
        use_polling: Optional[bool] = None,
        poll_interval: float = 0.2,
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
            blob_store=blob_store,
            agent_id=agent_id,
        )
        polling = (sys.platform in ("win32", "darwin")) if use_polling is None else use_polling
        self._observer = PollingObserver(timeout=poll_interval) if polling else Observer()

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

