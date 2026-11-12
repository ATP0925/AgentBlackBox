"""Configuration management for AgentBlackBox."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import json
import os


# Default ignore patterns — files/dirs we never watch
DEFAULT_IGNORE_PATTERNS: List[str] = [
    ".agentblackbox",
    "__pycache__",
    "*.pyc",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    "*.egg-info",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "dist",
    "build",
    "*.swp",
    "*.swo",
    "*~",
]


@dataclass
class BlackBoxConfig:
    """Central configuration for AgentBlackBox.

    Attributes:
        workspace_path: Root directory to monitor.
        db_path: Path to SQLite database file.
        ignore_patterns: File/dir patterns to skip.
        max_file_size_bytes: Skip files larger than this (default 1MB).
        debounce_ms: Milliseconds to debounce rapid file changes.
        dashboard_port: Port for the web dashboard.
        log_level: Logging level.
    """

    workspace_path: Path = field(default_factory=Path.cwd)
    db_path: Optional[Path] = None
    blobs_dir: Optional[Path] = None
    ignore_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATTERNS))
    max_file_size_bytes: int = 1_048_576  # 1 MB
    debounce_ms: int = 500
    dashboard_port: int = 7700
    log_level: str = "INFO"
    api_token: Optional[str] = None

    def __post_init__(self) -> None:
        """Set derived defaults after init."""
        if self.db_path is None:
            self.db_path = self.workspace_path / ".agentblackbox" / "blackbox.db"
        if self.blobs_dir is None:
            self.blobs_dir = self.workspace_path / ".agentblackbox" / "blobs"
        if self.api_token is None:
            self.api_token = os.environ.get("ABB_API_TOKEN")

    @classmethod
    def from_file(cls, path: Path) -> "BlackBoxConfig":
        """Load config from a JSON file.

        Args:
            path: Path to config JSON file.

        Returns:
            Populated BlackBoxConfig instance.
        """
        with open(path, "r") as f:
            data = json.load(f)
        if "workspace_path" in data:
            data["workspace_path"] = Path(data["workspace_path"])
        if "db_path" in data:
            data["db_path"] = Path(data["db_path"])
        return cls(**data)

    def to_dict(self) -> dict:
        """Serialize config to a dictionary.

        Returns:
            Dictionary representation of config.
        """
        return {
            "workspace_path": str(self.workspace_path),
            "db_path": str(self.db_path),
            "ignore_patterns": self.ignore_patterns,
            "max_file_size_bytes": self.max_file_size_bytes,
            "debounce_ms": self.debounce_ms,
            "dashboard_port": self.dashboard_port,
            "log_level": self.log_level,
        }

