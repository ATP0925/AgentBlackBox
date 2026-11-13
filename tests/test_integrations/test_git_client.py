"""Unit tests for GitClient read-only operations."""

from pathlib import Path
from agentblackbox.integrations.git_client import GitClient


def test_git_client_repo_detection(tmp_path: Path) -> None:
    # Not a git repo
    non_repo = GitClient(tmp_path)
    assert non_repo.is_git_repo() is False

    # Actual repo root
    client = GitClient()
    assert client.is_git_repo() is True
    # Can query without throwing
    diff = client.get_full_diff()
    assert isinstance(diff, str)
