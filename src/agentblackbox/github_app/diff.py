"""Diff Parsing, File Filtering, and Position Mapping for Pull Request Reviews."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

from agentblackbox.context.diff_parser import parse_unified_diff
from agentblackbox.github_app.config import PathSettings
from agentblackbox.models.diff import DiffLineType, FileDiff, GitDiff

# Standard files to ignore during AI / AST code review
DEFAULT_IGNORED_PATTERNS: Set[str] = {
    # Lockfiles
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    # Minified / Generated
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.pb.go",
    "*_pb2.py",
    "*.generated.*",
    "*.d.ts",
    # Binary / Assets
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.svg",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*.pdf",
    "*.zip",
    "*.tar.gz",
    "*.wasm",
    # Vendor / Cache
    "node_modules/*",
    "vendor/*",
    "third_party/*",
    ".git/*",
    "__pycache__/*",
    "*.pyc",
    "dist/*",
    "build/*",
    ".agentblackbox/*",
}


@dataclass
class DiffPosition:
    """Represents a validated GitHub inline comment target location."""
    path: str
    line: int
    side: str = "RIGHT"  # "RIGHT" for added/modified, "LEFT" for deleted


class DiffMapper:
    """Parses Git diffs, enforces file ignore rules, and maps line numbers to valid diff positions."""

    def __init__(
        self,
        raw_diff: str,
        path_settings: Optional[PathSettings] = None,
    ) -> None:
        self.raw_diff = raw_diff
        self.path_settings = path_settings or PathSettings()
        self.git_diff: GitDiff = parse_unified_diff(raw_diff) if raw_diff else GitDiff()

    def should_review_file(self, file_path: str) -> bool:
        """Check if file should be included in review based on default and custom rules."""
        norm = file_path.replace("\\", "/").lstrip("/")

        # Check explicit inclusions if specified
        if self.path_settings.include:
            matched = any(fnmatch.fnmatch(norm, pat) for pat in self.path_settings.include)
            if not matched:
                return False

        # Check custom exclusions
        for pat in self.path_settings.exclude:
            if fnmatch.fnmatch(norm, pat):
                return False

        # Check default noise patterns
        for pat in DEFAULT_IGNORED_PATTERNS:
            if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(norm.split("/")[-1], pat):
                return False

        return True

    def get_reviewable_files(self) -> List[FileDiff]:
        """Return list of modified or added files that pass filtering."""
        reviewable: List[FileDiff] = []
        for f in self.git_diff.files:
            if f.is_deleted:
                continue
            target = f.target_path
            if target and target != "/dev/null" and self.should_review_file(target):
                reviewable.append(f)
        return reviewable

    def get_comment_position(self, file_path: str, line_number: int) -> Optional[DiffPosition]:
        """Verify if a line falls within an active diff hunk to prevent GitHub 422 errors.

        GitHub requires inline review comments to be placed on a line that exists
        within the patch hunk of the diff.

        Returns:
            DiffPosition if line is valid in diff, or None if out of hunk.
        """
        if not file_path or line_number <= 0:
            return None

        norm = file_path.replace("\\", "/").lstrip("/")
        fdiff = self.git_diff.get_file(norm)
        if not fdiff or fdiff.is_deleted or fdiff.is_binary:
            return None

        # Check each hunk
        for hunk in fdiff.hunks:
            if hunk.contains_line(line_number):
                # Verify the line exists on the new side (RIGHT)
                for line in hunk.lines:
                    if line.new_lineno == line_number and line.line_type in (
                        DiffLineType.ADD,
                        DiffLineType.CONTEXT,
                    ):
                        return DiffPosition(path=fdiff.target_path, line=line_number, side="RIGHT")

        return None

    def chunk_diff_by_token_budget(self, max_chars: int = 120000) -> str:
        """Truncate or filter diff if it exceeds LLM token budget."""
        if len(self.raw_diff) <= max_chars:
            return self.raw_diff

        # Build prioritized diff from reviewable files only
        chunks: List[str] = []
        current_len = 0

        for f in self.get_reviewable_files():
            # Estimate file diff length
            hunk_texts = []
            for h in f.hunks:
                hunk_texts.append(h.header)
                for l in h.lines:
                    hunk_texts.append(f"{l.line_type.value}{l.content}")
            f_diff_text = f"diff --git a/{f.target_path} b/{f.target_path}\n" + "\n".join(hunk_texts) + "\n"

            if current_len + len(f_diff_text) > max_chars:
                chunks.append(f"\n# ... Diff truncated: remaining files exceeded token limit ({max_chars} chars) ...\n")
                break

            chunks.append(f_diff_text)
            current_len += len(f_diff_text)

        return "".join(chunks)
