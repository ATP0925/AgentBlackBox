"""Configuration settings for code review and repository analysis."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from agentblackbox.models.finding import Severity


DEFAULT_IGNORE_PATTERNS = [
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    "*.egg-info",
    ".agentblackbox",
]


@dataclass
class ReviewConfig:
    """Configurable options for code review and static analysis runs."""

    min_severity: Severity = Severity.LOW
    enable_ai: bool = False
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    max_context_tokens: int = 8000
    include_untracked: bool = False
    rule_filters: List[str] = field(default_factory=list)
    ignore_paths: List[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATTERNS))
    fail_on_severity: Optional[Severity] = Severity.HIGH  # Return non-zero exit code if this or higher exists
