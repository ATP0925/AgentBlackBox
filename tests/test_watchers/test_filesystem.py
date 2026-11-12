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
            time.sleep(0.3)
            (tmp_path / "new_file.py").write_text("hello")
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and not any(
                e.event_type == EventType.FILE_CREATE for e in events
            ):
                time.sleep(0.05)
        finally:
            watcher.stop()

        create_events = [e for e in events if e.event_type == EventType.FILE_CREATE]
        assert len(create_events) >= 1
        assert "new_file.py" in (create_events[0].source_path or "")

