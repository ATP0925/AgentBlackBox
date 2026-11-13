"""Data structures representing parsed Git unified diffs."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class DiffLineType(str, Enum):
    """Type of line in a unified diff hunk."""

    ADD = "+"
    DELETE = "-"
    CONTEXT = " "


@dataclass
class DiffLine:
    """A single line within a diff hunk with source and target line numbers."""

    line_type: DiffLineType
    content: str
    old_lineno: Optional[int] = None
    new_lineno: Optional[int] = None


@dataclass
class DiffHunk:
    """A contiguous hunk of changes in a file diff."""

    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    header: str
    lines: List[DiffLine] = field(default_factory=list)

    @property
    def added_lines(self) -> List[Tuple[int, str]]:
        """Return (new_lineno, content) for all added lines in this hunk."""
        return [
            (line.new_lineno, line.content)
            for line in self.lines
            if line.line_type == DiffLineType.ADD and line.new_lineno is not None
        ]

    def contains_line(self, lineno: int) -> bool:
        """Check if a line number falls within the new file range of this hunk."""
        return self.new_start <= lineno < self.new_start + max(1, self.new_lines)


@dataclass
class FileDiff:
    """Represents changes to a single file in a Git commit/diff."""

    old_path: Optional[str]
    new_path: Optional[str]
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    is_rename: bool = False
    hunks: List[DiffHunk] = field(default_factory=list)

    @property
    def target_path(self) -> str:
        """The active file path after changes."""
        return self.new_path or self.old_path or "unknown"

    def get_added_line_numbers(self) -> List[int]:
        """Return all new line numbers added in this file diff."""
        nums: List[int] = []
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.line_type == DiffLineType.ADD and line.new_lineno is not None:
                    nums.append(line.new_lineno)
        return nums

    def touches_line(self, lineno: int) -> bool:
        """Check if this file diff added or modified the specified target line."""
        for hunk in self.hunks:
            if hunk.new_start <= lineno < hunk.new_start + max(1, hunk.new_lines):
                return True
        return False


@dataclass
class GitDiff:
    """Collection of file diffs in a changesets/pull request."""

    files: List[FileDiff] = field(default_factory=list)
    raw_diff: str = ""

    def get_file(self, path: str) -> Optional[FileDiff]:
        """Find FileDiff by path matching target_path."""
        normalized = path.replace("\\", "/")
        for f in self.files:
            if f.target_path.replace("\\", "/") == normalized:
                return f
        return None

    @property
    def changed_files(self) -> List[str]:
        """Return list of file paths touched by this diff."""
        return [f.target_path for f in self.files]
