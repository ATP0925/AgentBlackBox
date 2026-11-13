"""Parser for Git unified diffs, extracting files, hunks, and line mappings."""

import re
from typing import List, Optional

from agentblackbox.models.diff import DiffHunk, DiffLine, DiffLineType, FileDiff, GitDiff

_HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$"
)


def parse_unified_diff(raw_diff: str) -> GitDiff:
    """Parse raw Git unified diff text into a structured GitDiff object.

    Args:
        raw_diff: Raw unified diff output from git diff or pull request.

    Returns:
        Structured GitDiff containing individual FileDiff objects and hunks.
    """
    if not raw_diff or not raw_diff.strip():
        return GitDiff(files=[], raw_diff="")

    files: List[FileDiff] = []
    current_file: Optional[FileDiff] = None
    current_hunk: Optional[DiffHunk] = None
    old_lineno = 0
    new_lineno = 0

    lines = raw_diff.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # File boundary: diff --git a/... b/...
        if line.startswith("diff --git "):
            if current_hunk and current_file:
                current_file.hunks.append(current_hunk)
                current_hunk = None
            if current_file:
                files.append(current_file)

            # Extract old and new file paths
            parts = line[len("diff --git ") :].strip().split(" ")
            old_path = parts[0][2:] if len(parts) >= 1 and parts[0].startswith("a/") else None
            new_path = parts[1][2:] if len(parts) >= 2 and parts[1].startswith("b/") else None

            current_file = FileDiff(
                old_path=old_path,
                new_path=new_path,
                is_new=False,
                is_deleted=False,
                is_binary=False,
                is_rename=False,
                hunks=[],
            )
            i += 1
            continue

        if current_file is None:
            # Standalone diff chunk without diff --git header
            if line.startswith("--- "):
                current_file = FileDiff(
                    old_path=line[4:].strip().lstrip("a/"),
                    new_path=None,
                    hunks=[],
                )
            i += 1
            continue

        if line.startswith("new file mode "):
            current_file.is_new = True
            i += 1
            continue

        if line.startswith("deleted file mode "):
            current_file.is_deleted = True
            i += 1
            continue

        if line.startswith("similarity index ") or line.startswith("rename from "):
            current_file.is_rename = True
            i += 1
            continue

        if line.startswith("Binary files ") or "differ" in line:
            current_file.is_binary = True
            i += 1
            continue

        if line.startswith("--- "):
            raw_path = line[4:].strip()
            if raw_path == "/dev/null":
                current_file.is_new = True
                current_file.old_path = None
            else:
                current_file.old_path = raw_path[2:] if raw_path.startswith("a/") else raw_path
            i += 1
            continue

        if line.startswith("+++ "):
            raw_path = line[4:].strip()
            if raw_path == "/dev/null":
                current_file.is_deleted = True
                current_file.new_path = None
            else:
                current_file.new_path = raw_path[2:] if raw_path.startswith("b/") else raw_path
            i += 1
            continue

        # Hunk boundary: @@ -old_start,old_lines +new_start,new_lines @@
        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            if current_hunk:
                current_file.hunks.append(current_hunk)

            old_start = int(hunk_match.group(1))
            old_lines = int(hunk_match.group(2)) if hunk_match.group(2) else 1
            new_start = int(hunk_match.group(3))
            new_lines = int(hunk_match.group(4)) if hunk_match.group(4) else 1
            header = hunk_match.group(5).strip()

            current_hunk = DiffHunk(
                old_start=old_start,
                old_lines=old_lines,
                new_start=new_start,
                new_lines=new_lines,
                header=header,
                lines=[],
            )
            old_lineno = old_start
            new_lineno = new_start
            i += 1
            continue

        # Inside hunk
        if current_hunk is not None:
            if line.startswith("+"):
                diff_line = DiffLine(
                    line_type=DiffLineType.ADD,
                    content=line[1:],
                    old_lineno=None,
                    new_lineno=new_lineno,
                )
                new_lineno += 1
                current_hunk.lines.append(diff_line)
            elif line.startswith("-"):
                diff_line = DiffLine(
                    line_type=DiffLineType.DELETE,
                    content=line[1:],
                    old_lineno=old_lineno,
                    new_lineno=None,
                )
                old_lineno += 1
                current_hunk.lines.append(diff_line)
            elif line.startswith(" ") or line == "":
                # Context line
                content = line[1:] if line.startswith(" ") else line
                diff_line = DiffLine(
                    line_type=DiffLineType.CONTEXT,
                    content=content,
                    old_lineno=old_lineno,
                    new_lineno=new_lineno,
                )
                old_lineno += 1
                new_lineno += 1
                current_hunk.lines.append(diff_line)
            elif line.startswith("\\ No newline at end of file"):
                pass
            else:
                # Unexpected line outside hunk
                pass

        i += 1

    if current_hunk and current_file:
        current_file.hunks.append(current_hunk)
    if current_file:
        files.append(current_file)

    return GitDiff(files=files, raw_diff=raw_diff)
