"""Safe, read-only Git client for diff and repository inspection."""

from pathlib import Path
from typing import Optional
import subprocess


class GitClient:
    """Safe, read-only interface for querying Git diffs and repository states."""

    def __init__(self, repo_path: Optional[Path] = None) -> None:
        self.repo_path = repo_path.resolve() if repo_path else Path.cwd().resolve()

    def is_git_repo(self) -> bool:
        """Check if target path is inside a valid Git repository."""
        dot_git = self.repo_path / ".git"
        if dot_git.exists():
            return True
        res = self._run_git(["rev-parse", "--is-inside-work-tree"])
        return res is not None and res.strip() == "true"

    def is_git_repository(self) -> bool:
        """Alias for is_git_repo."""
        return self.is_git_repo()

    def get_working_tree_diff(self, cached: bool = False, staged: bool = False, untracked: bool = False) -> str:
        """Get diff of unstaged changes (or staged if cached/staged is True)."""
        args = ["diff", "--no-color"]
        if cached or staged:
            args.append("--cached")
        output = self._run_git(args)
        return output or ""

    def get_full_diff(self) -> str:
        """Get combined diff of all unstaged and staged changes against HEAD."""
        # Check against HEAD
        output = self._run_git(["diff", "HEAD", "--no-color"])
        if output and output.strip():
            return output
        # Fallback to unstaged diff if repo has no commits yet
        return self.get_working_tree_diff()

    def get_branch_diff(self, base: str = "main", head: str = "HEAD", base_branch: Optional[str] = None) -> str:
        """Get diff between head (default HEAD) and base branch."""
        base_ref = base_branch or base
        # Try three-dot diff first
        output = self._run_git(["diff", f"{base_ref}...{head}", "--no-color"])
        if output is not None and output.strip():
            return output

        # Try origin/base_ref
        output_remote = self._run_git(["diff", f"origin/{base_ref}...{head}", "--no-color"])
        if output_remote is not None and output_remote.strip():
            return output_remote

        # Fallback to direct two-dot diff
        fallback = self._run_git(["diff", f"{base_ref}..{head}" if head != "HEAD" else base_ref, "--no-color"])
        return fallback or ""

    def get_commit_diff(self, commit_sha: str) -> str:
        """Get diff introduced by a specific commit."""
        output = self._run_git(["show", "--format=", "--no-color", commit_sha])
        return output or ""

    def get_file_content(self, file_path: str, ref: str = "HEAD") -> Optional[str]:
        """Read content of a file at a specific Git reference without writing to disk."""
        norm_path = file_path.replace("\\", "/")
        return self._run_git(["show", f"{ref}:{norm_path}"])

    def _run_git(self, args: list[str]) -> Optional[str]:
        """Execute a read-only git command safely."""
        try:
            res = subprocess.run(
                ["git", "-C", str(self.repo_path)] + args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15.0,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except (subprocess.SubprocessError, OSError):
            return None
