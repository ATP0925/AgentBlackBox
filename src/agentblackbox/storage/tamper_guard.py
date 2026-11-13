# Module: Tamper protection, out-of-tree shadow mirroring, and remote checkpoint replication.
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def get_default_shadow_root() -> Path:
    # Return an out-of-workspace shadow backup directory under user appdata/share.
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    root = base / "agentblackbox" / "shadow_mirrors"
    root.mkdir(parents=True, exist_ok=True)
    return root


class TamperGuard:
    # Protects .agentblackbox state via shadow checkpoints and optional remote replication.

    def __init__(
        self,
        workspace_abb_dir: Path,
        session_id: str,
        shadow_root: Path | None = None,
        webhook_url: str | None = None,
    ) -> None:
        self.workspace_abb_dir = workspace_abb_dir
        self.session_id = session_id
        self.shadow_dir = (shadow_root or get_default_shadow_root()) / session_id
        self.shadow_dir.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url or os.environ.get("ABB_CHECKPOINT_WEBHOOK_URL")

    def replicate_tip_checkpoint(self, tip_data: dict[str, Any]) -> Path:
        # Write signed .tip checkpoint to both workspace and out-of-workspace shadow store.
        serialized = json.dumps(tip_data, sort_keys=True, indent=2).encode("utf-8")
        ws_tip = self.workspace_abb_dir / f"{self.session_id}.tip"
        ws_tip.parent.mkdir(parents=True, exist_ok=True)
        ws_tip.write_bytes(serialized)

        shadow_tip = self.shadow_dir / f"{self.session_id}.tip"
        shadow_tip.write_bytes(serialized)

        if self.webhook_url:
            self._ship_remote_checkpoint(serialized)
        return shadow_tip

    def verify_workspace_integrity(self) -> tuple[bool, str]:
        # Compare workspace .tip against out-of-tree shadow .tip to detect deletion/rollback.
        ws_tip = self.workspace_abb_dir / f"{self.session_id}.tip"
        shadow_tip = self.shadow_dir / f"{self.session_id}.tip"

        if not shadow_tip.exists():
            return True, "No shadow baseline recorded yet."
        if not ws_tip.exists():
            return False, f"TAMPER ALERT: Workspace checkpoint {ws_tip.name} was deleted!"

        ws_payload = json.loads(ws_tip.read_text(encoding="utf-8"))
        sh_payload = json.loads(shadow_tip.read_text(encoding="utf-8"))

        if ws_payload.get("seq", 0) < sh_payload.get("seq", 0):
            return False, "TAMPER ALERT: Workspace checkpoint sequence rolled back!"
        if (
            ws_payload.get("seq") == sh_payload.get("seq")
            and ws_payload.get("mac") != sh_payload.get("mac")
        ):
            return False, "TAMPER ALERT: Workspace checkpoint MAC mismatch against shadow copy!"
        return True, "Workspace checkpoint matches out-of-tree shadow record."

    def restore_from_shadow(self) -> bool:
        # Restore deleted workspace .tip file from shadow directory.
        shadow_tip = self.shadow_dir / f"{self.session_id}.tip"
        ws_tip = self.workspace_abb_dir / f"{self.session_id}.tip"
        if shadow_tip.exists():
            ws_tip.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(shadow_tip, ws_tip)
            return True
        return False

    def apply_os_readonly_guard(self, target_file: Path) -> bool:
        # Apply best-effort read-only attribute on completed session archives.
        try:
            target_file.chmod(0o444)
            return True
        except OSError as exc:
            logger.debug("Could not apply chmod 0444 on %s: %s", target_file, exc)
            return False

    def _ship_remote_checkpoint(self, payload: bytes) -> None:
        # Best-effort POST of signed checkpoint JSON to remote audit webhook.
        if not self.webhook_url or not self.webhook_url.startswith(("https://", "http://")):
            return
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "AgentBlackBox-Guard/0.3"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0):
                pass
        except Exception as exc:
            logger.warning("Remote checkpoint webhook replication failed: %s", exc)

