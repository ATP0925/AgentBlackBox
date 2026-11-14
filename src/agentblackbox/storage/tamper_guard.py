"""Out-of-workspace shadow checkpoint mirroring and tamper detection."""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import urllib.request
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def get_default_shadow_root() -> Path:
    env_override = os.environ.get("ABB_SHADOW_DIR")
    if env_override:
        root = Path(env_override)
    elif platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        root = base / "agentblackbox" / "shadow_mirrors"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        root = base / "agentblackbox" / "shadow_mirrors"
    root.mkdir(parents=True, exist_ok=True)
    return root


class TamperGuard:
    """Mirrors signed .tip checkpoints outside the workspace and detects rollback or deletion."""

    def __init__(
        self,
        workspace_abb_dir: Path,
        session_id: str,
        shadow_root: Optional[Path] = None,
        webhook_url: Optional[str] = None,
    ) -> None:
        self.workspace_abb_dir = workspace_abb_dir
        self.session_id = session_id
        self.shadow_dir = (shadow_root or get_default_shadow_root()) / session_id
        self.shadow_dir.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url or os.environ.get("ABB_CHECKPOINT_WEBHOOK_URL")

    @property
    def workspace_tip_path(self) -> Path:
        cp_dir = self.workspace_abb_dir / "checkpoints"
        if cp_dir.exists():
            return cp_dir / f"{self.session_id}.tip"
        return self.workspace_abb_dir / f"{self.session_id}.tip"

    @property
    def shadow_tip_path(self) -> Path:
        return self.shadow_dir / f"{self.session_id}.tip"

    def replicate_tip_checkpoint(
        self, tip_data: dict[str, Any], target_path: Optional[Path] = None
    ) -> Path:
        normalized = dict(tip_data)
        seq_val = normalized.get("last_seq", normalized.get("seq", 0))
        hash_val = normalized.get("head_hash", normalized.get("tip_hash", ""))
        sig_val = normalized.get("signature", normalized.get("mac", ""))
        normalized["last_seq"] = seq_val
        normalized["seq"] = seq_val
        normalized["head_hash"] = hash_val
        normalized["tip_hash"] = hash_val
        normalized["signature"] = sig_val
        normalized["mac"] = sig_val

        serialized = json.dumps(normalized, sort_keys=True, indent=2).encode("utf-8")
        ws_tip = target_path or self.workspace_tip_path
        ws_tip.parent.mkdir(parents=True, exist_ok=True)
        ws_tip.write_bytes(serialized)
        try:
            ws_tip.chmod(0o600)
        except (OSError, NotImplementedError):
            pass

        self.shadow_tip_path.write_bytes(serialized)
        try:
            self.shadow_tip_path.chmod(0o600)
        except (OSError, NotImplementedError):
            pass

        if self.webhook_url:
            self._ship_remote_checkpoint(serialized)
        return self.shadow_tip_path

    def verify_workspace_integrity(
        self, explicit_ws_tip: Optional[Path] = None
    ) -> tuple[bool, str]:
        ws_tip = explicit_ws_tip or self.workspace_tip_path
        if not self.shadow_tip_path.exists():
            return True, "No out-of-tree shadow baseline recorded yet."
        if not ws_tip.exists():
            return False, f"TAMPER ALERT: Workspace checkpoint {ws_tip.name} was deleted!"

        try:
            ws_payload = json.loads(ws_tip.read_text(encoding="utf-8"))
            sh_payload = json.loads(self.shadow_tip_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return False, f"TAMPER ALERT: Corrupted checkpoint JSON ({exc})"

        ws_seq = int(ws_payload.get("last_seq", ws_payload.get("seq", 0)))
        sh_seq = int(sh_payload.get("last_seq", sh_payload.get("seq", 0)))

        if ws_seq < sh_seq:
            return (
                False,
                f"TAMPER ALERT: Checkpoint sequence rolled back (workspace={ws_seq} < shadow={sh_seq})!",
            )
        ws_sig = ws_payload.get("signature") or ws_payload.get("mac") or ""
        sh_sig = sh_payload.get("signature") or sh_payload.get("mac") or ""
        if ws_seq == sh_seq and ws_sig != sh_sig:
            return False, "TAMPER ALERT: Workspace checkpoint signature mismatch against shadow mirror!"
        return True, "Workspace checkpoint verified against out-of-tree shadow mirror."

    def restore_from_shadow(self, target_ws_tip: Optional[Path] = None) -> bool:
        ws_tip = target_ws_tip or self.workspace_tip_path
        if self.shadow_tip_path.exists():
            ws_tip.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.shadow_tip_path, ws_tip)
            return True
        return False

    def apply_os_readonly_guard(self, target_file: Path) -> bool:
        try:
            target_file.chmod(0o444)
            return True
        except OSError as exc:
            logger.debug("Could not apply chmod 0444 on %s: %s", target_file, exc)
            return False

    def _ship_remote_checkpoint(self, payload: bytes) -> None:
        if not self.webhook_url or not self.webhook_url.startswith(("https://", "http://")):
            return
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "AgentBlackBox-Guard/0.3"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2.5):
                pass
        except Exception as exc:
            logger.debug("Remote checkpoint webhook skipped: %s", exc)
