"""Agent attribution hooks (Claude Code / Cursor / generic CLI hook ingestion)."""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from agentblackbox.analysis.pattern_matcher import classify_event
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType


def install_claude_hook(workspace: Path) -> Path:
    """Install ``PreToolUse`` hook into ``.claude/settings.local.json``.

    Safely merges into existing settings without overwriting unrelated keys.

    Args:
        workspace: Project workspace root.

    Returns:
        Path to the updated ``.claude/settings.local.json``.
    """
    claude_dir = workspace / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_path = claude_dir / "settings.local.json"

    data: Dict[str, Any] = {}
    if settings_path.exists():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}

    hooks = data.setdefault("hooks", {})
    pre_tool = hooks.setdefault("PreToolUse", [])

    py_exe = Path(sys.executable).as_posix()
    ws_str = workspace.resolve().as_posix()
    cmd_str = f'"{py_exe}" -m agentblackbox.watchers.agent_hooks --agent claude-code --workspace "{ws_str}"'

    already_present = any(
        isinstance(entry, dict)
        and any(
            isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", "")
            for h in entry.get("hooks", [])
        )
        for entry in pre_tool
    )
    if not already_present:
        pre_tool.append({
            "matcher": "Bash|Write|Edit|MultiEdit",
            "hooks": [{"type": "command", "command": cmd_str}],
        })

    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return settings_path


def ingest_hook_payload(
    workspace: Path,
    payload: Dict[str, Any],
    agent_id: str = "claude-code",
    session_id: Optional[str] = None,
) -> Optional[Event]:
    """Convert an AI agent hook payload into an attributed AgentBlackBox Event.

    Args:
        workspace: Workspace root path.
        payload: Parsed hook JSON payload (e.g. ``tool_name``, ``tool_input``).
        agent_id: Identifier of the calling agent.
        session_id: Target session ID (defaults to active recording session).

    Returns:
        Persisted Event if a target session exists, None otherwise.
    """
    config = BlackBoxConfig(workspace_path=workspace)
    store = EventStore(config.db_path)

    target_sid = session_id or os.environ.get("ABB_SESSION_ID")
    if not target_sid:
        sessions = store.list_sessions(limit=1)
        if sessions and sessions[0].status == "recording":
            target_sid = sessions[0].id
    if not target_sid:
        return None

    tool_name = str(payload.get("tool_name", "")).lower()
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"raw": str(tool_input)}

    if tool_name in ("bash", "shell", "terminal", "execute"):
        ev_type = EventType.CMD_EXECUTE
        src_path = str(workspace)
        ev_payload = {"command": str(tool_input.get("command", "")), "tool": tool_name}
    elif tool_name in ("write", "create_file"):
        ev_type = EventType.FILE_CREATE
        src_path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        ev_payload = {"tool": tool_name}
    elif tool_name in ("edit", "multiedit", "replace_file_content"):
        ev_type = EventType.FILE_MODIFY
        src_path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        ev_payload = {"tool": tool_name}
    else:
        ev_type = EventType.PROCESS_SPAWN
        src_path = str(workspace)
        ev_payload = {"tool": tool_name, "input": tool_input}

    env_parent = os.environ.get("ABB_PARENT_EVENT_ID")
    parent_id = int(env_parent) if env_parent and env_parent.isdigit() else None

    event = Event(
        session_id=target_sid,
        event_type=ev_type,
        source_path=src_path or None,
        agent_id=agent_id,
        pid=os.getppid(),
        parent_event_id=parent_id,
        payload=ev_payload,
        tags=["agent_hook", agent_id],
    )
    classify_event(event)
    score_event(event)
    return store.insert_event(event)


def _main() -> None:
    """CLI entrypoint called by agent hook commands reading JSON from stdin."""
    import argparse

    parser = argparse.ArgumentParser(description="AgentBlackBox hook ingestor")
    parser.add_argument("--agent", default="claude-code")
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()

    raw = sys.stdin.read().strip()
    if not raw:
        return
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return
    if isinstance(data, dict):
        ingest_hook_payload(Path(args.workspace), data, agent_id=args.agent)


if __name__ == "__main__":
    _main()

