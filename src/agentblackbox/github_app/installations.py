"""GitHub App Installation & Repository Registry.

Tracks installed accounts, added/removed repositories, and installation lifecycle states.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class InstallationRecord:
    """Represents a GitHub App installation on an account or organization."""
    installation_id: int
    account_login: str
    account_id: int
    account_type: str = "User"  # "User" or "Organization"
    repositories: Set[str] = field(default_factory=set)  # set of "owner/repo"
    installed_at: float = field(default_factory=time.time)
    suspended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["repositories"] = list(self.repositories)
        return d


class InstallationStore:
    """Thread-safe store for GitHub App installations and registered repositories."""

    def __init__(self, persistence_path: Optional[Path] = None) -> None:
        self.persistence_path = persistence_path
        # {installation_id: InstallationRecord}
        self._installations: Dict[int, InstallationRecord] = {}
        self._load()

    def _load(self) -> None:
        if self.persistence_path and self.persistence_path.is_file():
            try:
                data = json.loads(self.persistence_path.read_text(encoding="utf-8"))
                for item in data:
                    rec = InstallationRecord(
                        installation_id=item["installation_id"],
                        account_login=item["account_login"],
                        account_id=item["account_id"],
                        account_type=item.get("account_type", "User"),
                        repositories=set(item.get("repositories", [])),
                        installed_at=item.get("installed_at", time.time()),
                        suspended=item.get("suspended", False),
                    )
                    self._installations[rec.installation_id] = rec
            except Exception as exc:
                logger.warning("installation_store_load_failed", error=str(exc))

    def _save(self) -> None:
        if self.persistence_path:
            try:
                self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
                serialized = [rec.to_dict() for rec in self._installations.values()]
                self.persistence_path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
            except Exception as exc:
                logger.error("installation_store_save_failed", error=str(exc))

    def record_installation(
        self,
        installation_id: int,
        account_login: str,
        account_id: int,
        account_type: str = "User",
        repositories: Optional[List[str]] = None,
    ) -> InstallationRecord:
        """Create or update an installation record."""
        repos_set = set(repositories or [])
        rec = InstallationRecord(
            installation_id=installation_id,
            account_login=account_login,
            account_id=account_id,
            account_type=account_type,
            repositories=repos_set,
        )
        self._installations[installation_id] = rec
        self._save()
        logger.info("recorded_github_app_installation", installation_id=installation_id, account=account_login)
        return rec

    def remove_installation(self, installation_id: int) -> bool:
        """Remove an uninstalled app record."""
        if installation_id in self._installations:
            self._installations.pop(installation_id, None)
            self._save()
            logger.info("removed_github_app_installation", installation_id=installation_id)
            return True
        return False

    def update_repositories(
        self,
        installation_id: int,
        added: Optional[List[str]] = None,
        removed: Optional[List[str]] = None,
    ) -> None:
        """Handle repository additions or removals."""
        rec = self._installations.get(installation_id)
        if not rec:
            return
        if added:
            rec.repositories.update(added)
        if removed:
            rec.repositories.difference_update(removed)
        self._save()
        logger.info("updated_installation_repositories", installation_id=installation_id, total=len(rec.repositories))

    def get_installation(self, installation_id: int) -> Optional[InstallationRecord]:
        return self._installations.get(installation_id)

    def is_repo_installed(self, repo_full_name: str) -> bool:
        norm = repo_full_name.lower().strip()
        for rec in self._installations.values():
            if any(r.lower().strip() == norm for r in rec.repositories):
                return True
        return False
