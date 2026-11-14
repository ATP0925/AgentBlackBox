"""Agent attribution hooks (Claude Code / Cursor / Codex / Gemini hook ingestion)."""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentblackbox.analysis.alerting import maybe_create_alert
from agentblackbox.analysis.pattern_matcher import classify_event
from agentblackbox.analysis.risk_scorer import score_event
from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session, Severity


def _read_json_with_backup(file_path: Path) -> Dict[str, Any]:
    """Read a JSON configuration file, or create a backup and raise ValueError if invalid."""
    if not file_path.exists():
        return {}
    content = file_path.read_text(encoding="utf-8")
    if not content.strip():
        return {}
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
        return {}
    except Exception as exc:
        bak_path = file_path.with_name(file_path.name + ".bak")
        try:
            shutil.copy2(file_path, bak_path)
        except OSError:
            pass
        raise ValueError(
            f"Corrupt JSON in {file_path}: {exc}. Backed up to {bak_path}"
        ) from exc


def install_claude_hook(workspace: Path, is_global: bool = False) -> Path:
    """Install ``PreToolUse`` hook into ``.claude/settings.local.json`` or ``~/.claude/settings.json``.

    Safely merges into existing settings without overwriting unrelated keys.
    If an existing AgentBlackBox entry is found, updates its matcher and command string.
    """
    if is_global:
        target_dir = Path.home() / ".claude"
        settings_path = target_dir / "settings.json"
        ws_str = "auto"
    else:
        target_dir = workspace / ".claude"
        settings_path = target_dir / "settings.local.json"
        ws_str = workspace.resolve().as_posix()

    target_dir.mkdir(parents=True, exist_ok=True)
    data = _read_json_with_backup(settings_path)

    hooks = data.setdefault("hooks", {})
    pre_tool = hooks.setdefault("PreToolUse", [])

    py_exe = Path(sys.executable).as_posix()
    cmd_str = f'"{py_exe}" -m agentblackbox.watchers.agent_hooks --agent claude-code --workspace "{ws_str}"'
    matcher = "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|Read|mcp__.*"

    updated = False
    for entry in pre_tool:
        if isinstance(entry, dict):
            entry_hooks = entry.get("hooks", [])
            for h in entry_hooks:
                if isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", ""):
                    entry["matcher"] = matcher
                    h["command"] = cmd_str
                    updated = True
                    break
            if updated:
                break

    if not updated:
        pre_tool.append({
            "matcher": matcher,
            "hooks": [{"type": "command", "command": cmd_str}],
        })

    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return settings_path


def install_codex_hook(workspace: Path, is_global: bool = False) -> Path:
    """Install PreToolUse hook into Codex hooks.json (<repo>/.codex/hooks.json or ~/.codex/hooks.json)."""
    if is_global:
        codex_dir = Path.home() / ".codex"
        hook_file = codex_dir / "hooks.json"
        ws_str = "auto"
    else:
        codex_dir = workspace / ".codex"
        hook_file = codex_dir / "hooks.json"
        ws_str = workspace.resolve().as_posix()

    codex_dir.mkdir(parents=True, exist_ok=True)
    data = _read_json_with_backup(hook_file)

    py_exe = Path(sys.executable).as_posix()
    cmd_str = f'"{py_exe}" -m agentblackbox.watchers.agent_hooks --agent codex --workspace "{ws_str}"'

    hooks = data.setdefault("hooks", {})
    pre_tool = hooks.setdefault("PreToolUse", [])

    updated = False
    for entry in pre_tool:
        if isinstance(entry, dict):
            entry_hooks = entry.get("hooks", [])
            for h in entry_hooks:
                if isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", ""):
                    h["command"] = cmd_str
                    h["timeout"] = 10
                    h["type"] = "command"
                    updated = True
                    break
            if updated:
                break

    if not updated:
        pre_tool.append({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": cmd_str, "timeout": 10}],
        })

    hook_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("NOTE for Codex: Run /hooks inside Codex and trust the hook, and fully restart Codex.")
    return hook_file


def install_cursor_hook(workspace: Path, is_global: bool = False) -> Path:
    """Install Cursor IDE hooks into .cursor/hooks.json or ~/.cursor/hooks.json."""
    if is_global:
        cursor_dir = Path.home() / ".cursor"
        hook_file = cursor_dir / "hooks.json"
        ws_str = "auto"
    else:
        cursor_dir = workspace / ".cursor"
        hook_file = cursor_dir / "hooks.json"
        ws_str = workspace.resolve().as_posix()
        # Maintain rules/agentblackbox.mdc for compatibility with existing tests
        rules_dir = cursor_dir / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        rule_file = rules_dir / "agentblackbox.mdc"
        if not rule_file.exists():
            rule_file.write_text(
                "---\n"
                "description: AgentBlackBox Flight Recorder and Safety Rules for Cursor\n"
                "globs: *\n"
                "---\n\n"
                "# AgentBlackBox Autonomous Agent Safety\n"
                "- Run destructive or high-impact commands via `abb run --agent cursor \"<cmd>\"`.\n"
                "- Verify workspace before final pull request with `abb review`.\n"
                "- Secret scanning and risk telemetry are automatically recorded.\n",
                encoding="utf-8",
            )

    cursor_dir.mkdir(parents=True, exist_ok=True)
    data = _read_json_with_backup(hook_file)
    data.setdefault("version", 1)
    hooks = data.setdefault("hooks", {})

    py_exe = Path(sys.executable).as_posix()
    cmd_str = f'"{py_exe}" -m agentblackbox.watchers.agent_hooks --agent cursor --workspace "{ws_str}"'

    for event_name in ("beforeShellExecution", "afterFileEdit", "beforeMCPExecution"):
        event_list = hooks.setdefault(event_name, [])
        updated = False
        for entry in event_list:
            if isinstance(entry, dict) and "agentblackbox.watchers.agent_hooks" in entry.get("command", ""):
                entry["command"] = cmd_str
                entry["timeout"] = 30
                updated = True
                break
        if not updated:
            event_list.append({"command": cmd_str, "timeout": 30})

    hook_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return hook_file


def install_gemini_hook(workspace: Path, is_global: bool = False) -> Path:
    """Install Gemini BeforeTool hook into .gemini/settings.json or ~/.gemini/settings.json."""
    if is_global:
        gemini_dir = Path.home() / ".gemini"
        settings_file = gemini_dir / "settings.json"
        ws_str = "auto"
    else:
        gemini_dir = workspace / ".gemini"
        settings_file = gemini_dir / "settings.json"
        ws_str = workspace.resolve().as_posix()
        # Maintain rules/agentblackbox.md for compatibility with existing tests
        rules_dir = gemini_dir / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        rule_file = rules_dir / "agentblackbox.md"
        if not rule_file.exists():
            rule_file.write_text(
                "# AgentBlackBox Guidelines for Google Antigravity\n\n"
                "- Tracked under AgentBlackBox flight recorder (agent: `antigravity`).\n"
                "- Always run `abb review` or `abb analyze` to ensure 0 critical findings.\n",
                encoding="utf-8",
            )

    gemini_dir.mkdir(parents=True, exist_ok=True)
    data = _read_json_with_backup(settings_file)

    hooks = data.setdefault("hooks", {})
    before_tool = hooks.setdefault("BeforeTool", [])

    py_exe = Path(sys.executable).as_posix()
    cmd_str = f'"{py_exe}" -m agentblackbox.watchers.agent_hooks --agent gemini --workspace "{ws_str}"'
    matcher = "run_shell_command|write_file|replace|read_file"

    updated = False
    for entry in before_tool:
        if isinstance(entry, dict):
            entry_hooks = entry.get("hooks", [])
            for h in entry_hooks:
                if isinstance(h, dict) and (
                    h.get("name") == "agentblackbox"
                    or "agentblackbox.watchers.agent_hooks" in h.get("command", "")
                ):
                    entry["matcher"] = matcher
                    h["name"] = "agentblackbox"
                    h["type"] = "command"
                    h["command"] = cmd_str
                    h["timeout"] = 5000
                    updated = True
                    break
            if updated:
                break

    if not updated:
        before_tool.append({
            "matcher": matcher,
            "hooks": [
                {
                    "name": "agentblackbox",
                    "type": "command",
                    "command": cmd_str,
                    "timeout": 5000,
                }
            ],
        })

    settings_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("NOTE for Gemini: Gemini hooks are experimental and need hooks enabled in settings.json.")
    return settings_file


def install_antigravity_hook(workspace: Path, is_global: bool = False) -> Path:
    """Install Google Antigravity attribution & safety rules into .gemini/settings.json."""
    return install_gemini_hook(workspace, is_global=is_global)


def install_git_hook(workspace: Path) -> Path:
    """Install pre-commit hook into .git/hooks/pre-commit to review code automatically."""
    git_dir = workspace / ".git" / "hooks"
    git_dir.mkdir(parents=True, exist_ok=True)
    hook_file = git_dir / "pre-commit"
    py_exe = Path(sys.executable).as_posix()
    hook_content = (
        "#!/bin/sh\n"
        "# AgentBlackBox automated pre-commit review\n"
        f'"{py_exe}" -m agentblackbox.cli.main review --exit-zero\n'
    )
    hook_file.write_text(hook_content, encoding="utf-8")
    return hook_file


def install_agent_hook(workspace: Path, agent: str = "claude-code", is_global: bool = False) -> Dict[str, Path]:
    """Unified installer for Claude Code, OpenAI Codex, Cursor, Gemini, and Git hooks."""
    target = agent.lower().strip()
    installed: Dict[str, Path] = {}

    if target in ("all", "claude", "claude-code"):
        installed["claude-code"] = install_claude_hook(workspace, is_global=is_global)

    if target in ("all", "codex", "openai"):
        installed["codex"] = install_codex_hook(workspace, is_global=is_global)

    if target in ("all", "cursor"):
        installed["cursor"] = install_cursor_hook(workspace, is_global=is_global)

    if target in ("all", "antigravity", "gemini"):
        installed["gemini"] = install_gemini_hook(workspace, is_global=is_global)
        installed["antigravity"] = installed["gemini"]

    if target in ("all", "git", "pre-commit") and not is_global:
        if (workspace / ".git").exists():
            installed["git"] = install_git_hook(workspace)

    if not installed:
        raise ValueError(f"Unknown agent '{agent}'. Supported: claude, codex, cursor, gemini, git, all")

    return installed


def verify_agent_hooks(workspace: Path, is_global: bool = False) -> Dict[str, Dict[str, Any]]:
    """Verify that installed agent hooks still exist in configuration files."""
    results: Dict[str, Dict[str, Any]] = {}

    # 1. Claude
    claude_file = (Path.home() / ".claude" / "settings.json") if is_global else (workspace / ".claude" / "settings.local.json")
    claude_ok = False
    if claude_file.exists():
        try:
            d = json.loads(claude_file.read_text(encoding="utf-8"))
            hooks = d.get("hooks", {}).get("PreToolUse", [])
            claude_ok = any(
                isinstance(entry, dict)
                and any(
                    isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", "")
                    for h in entry.get("hooks", [])
                )
                for entry in hooks
            )
        except Exception:
            claude_ok = False
    results["claude"] = {"path": claude_file, "status": "OK" if claude_ok else "MISSING"}

    # 2. Codex
    codex_file = (Path.home() / ".codex" / "hooks.json") if is_global else (workspace / ".codex" / "hooks.json")
    codex_ok = False
    if codex_file.exists():
        try:
            d = json.loads(codex_file.read_text(encoding="utf-8"))
            hooks = d.get("hooks", {}).get("PreToolUse", [])
            codex_ok = any(
                isinstance(entry, dict)
                and any(
                    isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", "")
                    for h in entry.get("hooks", [])
                )
                for entry in hooks
            )
        except Exception:
            codex_ok = False
    results["codex"] = {"path": codex_file, "status": "OK" if codex_ok else "MISSING"}

    # 3. Cursor
    cursor_file = (Path.home() / ".cursor" / "hooks.json") if is_global else (workspace / ".cursor" / "hooks.json")
    cursor_ok = False
    if cursor_file.exists():
        try:
            d = json.loads(cursor_file.read_text(encoding="utf-8"))
            hooks = d.get("hooks", {})
            cursor_ok = any(
                isinstance(hooks.get(ev), list)
                and any(
                    isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", "")
                    for h in hooks[ev]
                )
                for ev in ("beforeShellExecution", "afterFileEdit", "beforeMCPExecution")
            )
        except Exception:
            cursor_ok = False
    results["cursor"] = {"path": cursor_file, "status": "OK" if cursor_ok else "MISSING"}

    # 4. Gemini
    gemini_file = (Path.home() / ".gemini" / "settings.json") if is_global else (workspace / ".gemini" / "settings.json")
    gemini_ok = False
    if gemini_file.exists():
        try:
            d = json.loads(gemini_file.read_text(encoding="utf-8"))
            hooks = d.get("hooks", {}).get("BeforeTool", [])
            gemini_ok = any(
                isinstance(entry, dict)
                and any(
                    isinstance(h, dict) and "agentblackbox.watchers.agent_hooks" in h.get("command", "")
                    for h in entry.get("hooks", [])
                )
                for entry in hooks
            )
        except Exception:
            gemini_ok = False
    results["gemini"] = {"path": gemini_file, "status": "OK" if gemini_ok else "MISSING"}

    return results


def normalize_hook_payload(agent: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize agent hook payloads across Claude Code, Codex, Cursor, and Gemini CLI.

    Returns:
        Dict with keys:
            kind: 'shell' | 'file_write' | 'file_edit' | 'file_read' | 'web' | 'mcp' | 'other'
            command: str | None
            path: str | None
            tool: str
            cwd: str | None
    """
    if not isinstance(payload, dict):
        return {
            "kind": "other",
            "command": None,
            "path": None,
            "tool": "unknown",
            "cwd": None,
        }

    # Extract cwd
    cwd: Optional[str] = None
    if payload.get("cwd"):
        cwd = str(payload.get("cwd"))
    elif payload.get("workspace_roots") and isinstance(payload.get("workspace_roots"), list) and payload["workspace_roots"]:
        cwd = str(payload["workspace_roots"][0])

    agent_normalized = (agent or "").lower().strip()
    hook_event = str(payload.get("hook_event_name") or "")

    # 1. Cursor shape
    # hook_event_name: beforeShellExecution (command TOP-LEVEL), afterFileEdit (file_path), beforeReadFile (file_path), beforeMCPExecution
    if hook_event.startswith("before") or hook_event.startswith("after") or "cursor" in agent_normalized:
        if hook_event == "beforeShellExecution":
            cmd = payload.get("command")
            if not cmd and isinstance(payload.get("tool_input"), dict):
                cmd = payload["tool_input"].get("command")
            return {
                "kind": "shell",
                "command": str(cmd) if cmd is not None else None,
                "path": None,
                "tool": hook_event,
                "cwd": cwd,
            }
        if hook_event == "afterFileEdit":
            p = payload.get("file_path") or payload.get("path")
            if not p and isinstance(payload.get("tool_input"), dict):
                p = payload["tool_input"].get("file_path") or payload["tool_input"].get("path")
            return {
                "kind": "file_edit",
                "command": None,
                "path": str(p) if p is not None else None,
                "tool": hook_event,
                "cwd": cwd,
            }
        if hook_event == "beforeReadFile":
            p = payload.get("file_path") or payload.get("path")
            if not p and isinstance(payload.get("tool_input"), dict):
                p = payload["tool_input"].get("file_path") or payload["tool_input"].get("path")
            return {
                "kind": "file_read",
                "command": None,
                "path": str(p) if p is not None else None,
                "tool": hook_event,
                "cwd": cwd,
            }
        if hook_event == "beforeMCPExecution":
            return {
                "kind": "mcp",
                "command": None,
                "path": None,
                "tool": hook_event,
                "cwd": cwd,
            }

    # 2. Gemini CLI shape
    # hook_event_name: BeforeTool, tool_name: run_shell_command (tool_input.command), write_file, replace, read_file, web_fetch; cwd field
    if hook_event == "BeforeTool" or "gemini" in agent_normalized:
        tool_name = str(payload.get("tool_name") or payload.get("name") or "gemini_tool")
        tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
        t_low = tool_name.lower()

        if t_low in ("run_shell_command", "bash", "shell"):
            cmd = tool_input.get("command")
            return {
                "kind": "shell",
                "command": str(cmd) if cmd is not None else None,
                "path": None,
                "tool": tool_name,
                "cwd": cwd,
            }
        if t_low in ("write_file", "write"):
            p = tool_input.get("file_path") or tool_input.get("path")
            return {
                "kind": "file_write",
                "command": None,
                "path": str(p) if p is not None else None,
                "tool": tool_name,
                "cwd": cwd,
            }
        if t_low in ("replace", "edit", "replace_file_content"):
            p = tool_input.get("file_path") or tool_input.get("path")
            return {
                "kind": "file_edit",
                "command": None,
                "path": str(p) if p is not None else None,
                "tool": tool_name,
                "cwd": cwd,
            }
        if t_low in ("read_file", "read"):
            p = tool_input.get("file_path") or tool_input.get("path")
            return {
                "kind": "file_read",
                "command": None,
                "path": str(p) if p is not None else None,
                "tool": tool_name,
                "cwd": cwd,
            }
        if t_low in ("web_fetch", "search_web", "web"):
            p = tool_input.get("url") or tool_input.get("path")
            return {
                "kind": "web",
                "command": None,
                "path": str(p) if p is not None else None,
                "tool": tool_name,
                "cwd": cwd,
            }
        if t_low.startswith("mcp"):
            return {
                "kind": "mcp",
                "command": None,
                "path": None,
                "tool": tool_name,
                "cwd": cwd,
            }
        return {
            "kind": "other",
            "command": None,
            "path": None,
            "tool": tool_name,
            "cwd": cwd,
        }

    # 3. Claude Code & Codex CLI shape
    tool_name = str(payload.get("tool_name") or payload.get("name") or payload.get("tool") or "unknown_tool")
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    if not tool_input and isinstance(payload.get("parameters"), dict):
        tool_input = payload["parameters"]
    if not tool_input and isinstance(payload.get("arguments"), dict):
        tool_input = payload["arguments"]

    t_low = tool_name.lower()
    if t_low in ("bash", "shell", "terminal", "execute", "exec_command", "run_shell_command"):
        cmd = tool_input.get("command") or payload.get("command")
        return {
            "kind": "shell",
            "command": str(cmd) if cmd is not None else None,
            "path": None,
            "tool": tool_name,
            "cwd": cwd,
        }
    if t_low in ("write", "create_file", "write_file"):
        p = tool_input.get("file_path") or tool_input.get("path") or payload.get("file_path")
        return {
            "kind": "file_write",
            "command": None,
            "path": str(p) if p is not None else None,
            "tool": tool_name,
            "cwd": cwd,
        }
    if t_low in ("edit", "multiedit", "notebookedit", "replace_file_content", "replace"):
        p = tool_input.get("file_path") or tool_input.get("path") or payload.get("file_path")
        return {
            "kind": "file_edit",
            "command": None,
            "path": str(p) if p is not None else None,
            "tool": tool_name,
            "cwd": cwd,
        }
    if t_low in ("read", "read_file"):
        p = tool_input.get("file_path") or tool_input.get("path") or payload.get("file_path")
        return {
            "kind": "file_read",
            "command": None,
            "path": str(p) if p is not None else None,
            "tool": tool_name,
            "cwd": cwd,
        }
    if t_low in ("webfetch", "web_fetch", "web"):
        p = tool_input.get("url") or tool_input.get("path")
        return {
            "kind": "web",
            "command": None,
            "path": str(p) if p is not None else None,
            "tool": tool_name,
            "cwd": cwd,
        }
    if t_low.startswith("mcp__") or t_low.startswith("mcp_") or t_low == "mcp":
        return {
            "kind": "mcp",
            "command": None,
            "path": None,
            "tool": tool_name,
            "cwd": cwd,
        }

    return {
        "kind": "other",
        "command": None,
        "path": None,
        "tool": tool_name,
        "cwd": cwd,
    }


def _is_sensitive_path(path_str: Optional[str]) -> bool:
    """Check if file path references sensitive credentials or keys."""
    if not path_str:
        return False
    norm = Path(path_str).as_posix().lower()
    markers = [".env", ".pem", "id_rsa", ".ssh/", "credentials", ".aws/"]
    return any(m in norm for m in markers)


def ingest_hook_payload(
    workspace: Optional[Path],
    payload: Dict[str, Any],
    agent_id: str = "claude-code",
    session_id: Optional[str] = None,
) -> Optional[Event]:
    """Convert an AI agent hook payload into an attributed AgentBlackBox Event.

    Args:
        workspace: Workspace root path (or None/'auto' to auto-resolve from payload).
        payload: Parsed hook JSON payload.
        agent_id: Identifier of the calling agent.
        session_id: Target session ID (defaults to active recording session).

    Returns:
        Persisted Event if target session exists/created and event was not skipped, None otherwise.
    """
    norm = normalize_hook_payload(agent_id, payload)

    # Auto-resolve workspace if not provided or 'auto'
    ws = workspace
    if ws is None or str(ws).lower() == "auto":
        ws_hint = norm.get("cwd")
        ws = Path(ws_hint) if ws_hint else Path.cwd()

    config = BlackBoxConfig(workspace_path=ws)
    store = EventStore(config.db_path)

    target_sid = session_id or os.environ.get("ABB_SESSION_ID")
    if not target_sid:
        sessions = store.list_sessions(limit=1)
        if sessions and sessions[0].status == "recording":
            target_sid = sessions[0].id
        else:
            new_sess = store.create_session(
                Session(
                    workspace_path=str(ws),
                    name="agent-hooks",
                    agent_hint=agent_id,
                )
            )
            target_sid = new_sess.id

    kind = norm["kind"]
    tool = norm["tool"]
    cmd = norm["command"]
    p = norm["path"]

    if kind == "file_read":
        if not _is_sensitive_path(p):
            return None
        ev_type = EventType.FILE_READ
        src_path = str(p or "")
        ev_payload = {"tool": tool, "path": src_path}

    elif kind == "shell":
        ev_type = EventType.CMD_EXECUTE
        src_path = str(norm.get("cwd") or ws)
        ev_payload = {"command": str(cmd or ""), "tool": tool}

    elif kind == "file_write":
        target_obj = Path(p) if p else None
        if target_obj and not target_obj.is_absolute():
            target_obj = ws / target_obj
        if target_obj and target_obj.exists():
            ev_type = EventType.FILE_MODIFY
        else:
            ev_type = EventType.FILE_CREATE
        src_path = str(p or "")
        ev_payload = {"tool": tool, "path": src_path}

    elif kind == "file_edit":
        ev_type = EventType.FILE_MODIFY
        src_path = str(p or "")
        ev_payload = {"tool": tool, "path": src_path}

    else:
        ev_type = EventType.PROCESS_SPAWN
        src_path = str(p or norm.get("cwd") or ws)
        ev_payload = {"tool": tool, "kind": kind, "input": payload.get("tool_input") or payload}

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
    stored = store.insert_event(event)
    maybe_create_alert(store, stored)
    return stored


def _main() -> None:
    """CLI entrypoint called by agent hook commands reading JSON from stdin.

    Must never break the caller agent, always exit code 0, silent on stdout.
    """
    import argparse

    parser = argparse.ArgumentParser(description="AgentBlackBox hook ingestor")
    parser.add_argument("--agent", default="claude-code")
    parser.add_argument("--workspace", default="auto")

    ws_for_log = Path.cwd()
    try:
        args = parser.parse_args()
        ws_arg = args.workspace
        if ws_arg and ws_arg != "auto":
            ws_for_log = Path(ws_arg)
        raw = sys.stdin.read().strip()
        if not raw:
            sys.exit(0)
        data = json.loads(raw)
        if isinstance(data, dict):
            if ws_arg and ws_arg != "auto":
                target_ws = Path(ws_arg)
            else:
                ws_hint = data.get("cwd")
                if data.get("workspace_roots") and isinstance(data["workspace_roots"], list) and data["workspace_roots"]:
                    ws_hint = data["workspace_roots"][0]
                target_ws = Path(ws_hint) if ws_hint else Path.cwd()
            ws_for_log = target_ws
            ingest_hook_payload(target_ws, data, agent_id=args.agent)
    except Exception as exc:
        try:
            err_log_dir = ws_for_log / ".agentblackbox"
            err_log_dir.mkdir(parents=True, exist_ok=True)
            err_log = err_log_dir / "hook_errors.log"
            ts = datetime.now(timezone.utc).isoformat()
            with err_log.open("a", encoding="utf-8") as f:
                f.write(f"[{ts}] {type(exc).__name__}: {exc}\n")
        except Exception:
            pass
        sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    _main()


# --- v0.3.0 Universal IDE Collector (Claude Code, Cursor, Cline, Antigravity) ---

@dataclass(frozen=True)
class NormalizedAgentEvent:
    agent_source: str
    event_type: str
    tool_name: str
    target_resource: str
    raw_arguments: dict[str, Any]

    def to_storage_event(self, session_id: str) -> Event:
        return Event(
            session_id=session_id,
            event_type=self.event_type,
            severity=Severity.INFO,
            source_path=self.target_resource if self.target_resource != "workspace" else None,
            agent_id=self.agent_source,
            payload={
                "agent_source": self.agent_source,
                "tool_name": self.tool_name,
                "target": self.target_resource,
                "arguments": self.raw_arguments,
            },
            tags=[f"ide:{self.agent_source}", f"tool:{self.tool_name}"],
        )


class UniversalIDECollector:
    """Normalizes hook payloads from Claude Code, Cursor, Cline, and Google Antigravity IDE."""

    @staticmethod
    def ingest_ide_log_file(log_file: Path, source_hint: str = "auto") -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if not log_file.exists():
            return results
        text = log_file.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return results
        if text.startswith("["):
            try:
                data = json.loads(text)
                for item in data:
                    if isinstance(item, dict):
                        ev = UniversalIDECollector.parse_hook_payload(item, source_hint=source_hint)
                        results.append(asdict(ev))
                return results
            except Exception:
                pass
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        ev = UniversalIDECollector.parse_hook_payload(item, source_hint=source_hint)
                        results.append(asdict(ev))
                except Exception:
                    continue
        return results

    @staticmethod
    def parse_hook_payload(
        payload: dict[str, Any], source_hint: str = "auto"
    ) -> NormalizedAgentEvent:
        if source_hint == "claude_code" or "tool_input" in payload or "hook_event_name" in payload:
            tool_name = str(payload.get("tool_name") or payload.get("name") or "unknown_tool")
            tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
            target = str(
                tool_input.get("file_path")
                or tool_input.get("command")
                or tool_input.get("path")
                or "workspace"
            )
            ev_type = (
                EventType.CMD_EXECUTE
                if tool_name.lower() in ("bash", "run_command", "execute_command")
                else EventType.FILE_MODIFY
            )
            return NormalizedAgentEvent(
                agent_source="claude_code",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=tool_input,
            )

        if source_hint == "cline" or "cline_task_id" in payload or "say" in payload or "ask" in payload:
            tool_name = str(payload.get("tool") or payload.get("ask") or "cline_action")
            target = str(payload.get("path") or payload.get("command") or "workspace")
            ev_type = EventType.CMD_EXECUTE if "command" in payload else EventType.FILE_MODIFY
            return NormalizedAgentEvent(
                agent_source="cline",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=payload,
            )

        if source_hint == "cursor" or "composerId" in payload or "mcpServer" in payload:
            tool_name = str(payload.get("toolName") or payload.get("action") or "cursor_composer")
            params = payload.get("parameters") if isinstance(payload.get("parameters"), dict) else payload
            target = str(params.get("relativeWorkspacePath") or params.get("command") or "workspace")
            if payload.get("action") == "mcp_call" or tool_name.lower() in ("mcp_call", "mcp") or tool_name.lower().startswith("mcp_"):
                ev_type = EventType.PROCESS_SPAWN
            elif "command" in params:
                ev_type = EventType.CMD_EXECUTE
            else:
                ev_type = EventType.FILE_MODIFY
            return NormalizedAgentEvent(
                agent_source="cursor",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=params,
            )

        if (
            source_hint in ("codex", "openai")
            or "codex" in str(payload.get("agent", "")).lower()
            or "tool_call_id" in payload
            or "codex_action" in payload
            or ("function" in payload and isinstance(payload.get("function"), dict))
        ):
            fn = payload.get("function") if isinstance(payload.get("function"), dict) else payload
            tool_name = str(fn.get("name") or payload.get("tool") or "codex_tool")
            args = fn.get("arguments") or payload.get("args") or payload.get("parameters") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"raw": args}
            target = str(args.get("file_path") or args.get("command") or args.get("path") or args.get("target") or "workspace")
            ev_type = (
                EventType.CMD_EXECUTE
                if tool_name.lower() in ("bash", "shell", "exec_command", "run_command", "execute")
                else EventType.FILE_MODIFY
            )
            return NormalizedAgentEvent(
                agent_source="codex",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=args,
            )

        tool_name = str(payload.get("tool") or payload.get("function") or "agent_step")
        args = payload.get("args") if isinstance(payload.get("args"), dict) else payload
        target = str(args.get("TargetFile") or args.get("command") or args.get("path") or "workspace")
        ev_type = (
            EventType.CMD_EXECUTE
            if tool_name.lower() in ("execute_bash", "run_command") or "command" in args
            else EventType.FILE_MODIFY
        )
        return NormalizedAgentEvent(
            agent_source=source_hint if source_hint != "auto" else "antigravity",
            event_type=ev_type,
            tool_name=tool_name,
            target_resource=target,
            raw_arguments=args,
        )
