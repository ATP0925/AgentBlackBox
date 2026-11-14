# Module: Universal IDE event normalization for Claude Code, Cursor, Cline, and Antigravity IDE.
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class NormalizedAgentEvent:
    # Canonical flight-recorder event structure across all supported AI coding agents.
    agent_source: str  # 'claude_code' | 'cursor' | 'cline' | 'antigravity'
    event_type: str  # 'tool_call' | 'terminal_cmd' | 'file_edit' | 'mcp_call'
    tool_name: str
    target_resource: str
    raw_arguments: dict[str, Any]
    timestamp: float


class UniversalIDECollector:
    # Parses payloads from Claude PreToolUse, Cursor MCP/composer, Cline tasks, and Antigravity.

    @staticmethod
    def parse_hook_payload(
        payload: dict[str, Any], source_hint: str = "auto"
    ) -> NormalizedAgentEvent:
        # Normalize heterogeneous IDE hook JSON into a canonical NormalizedAgentEvent.
        now = float(payload.get("timestamp") or time.time())

        # 1. Claude Code PreToolUse / PostToolUse format
        if (
            source_hint == "claude_code"
            or "tool_input" in payload
            or "hook_event_name" in payload
        ):
            tool_name = str(
                payload.get("tool_name") or payload.get("name") or "unknown_tool"
            )
            tool_input = (
                payload.get("tool_input")
                if isinstance(payload.get("tool_input"), dict)
                else {}
            )
            target = str(
                tool_input.get("file_path")
                or tool_input.get("command")
                or tool_input.get("path")
                or "workspace"
            )
            ev_type = (
                "terminal_cmd"
                if tool_name.lower() in ("bash", "run_command")
                else "tool_call"
            )
            return NormalizedAgentEvent(
                agent_source="claude_code",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=tool_input,
                timestamp=now,
            )

        # 2. Cline (VS Code extension) task/api_conversation_history format
        if (
            source_hint == "cline"
            or "cline_task_id" in payload
            or "say" in payload
            or "ask" in payload
        ):
            tool_name = str(
                payload.get("tool") or payload.get("ask") or "cline_action"
            )
            target = str(
                payload.get("path")
                or payload.get("command")
                or payload.get("regex")
                or "workspace"
            )
            ev_type = "terminal_cmd" if "command" in payload else "tool_call"
            return NormalizedAgentEvent(
                agent_source="cline",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=payload,
                timestamp=now,
            )

        # 3. Cursor IDE Composer / MCP tool execution format
        if (
            source_hint == "cursor"
            or "composerId" in payload
            or "mcpServer" in payload
        ):
            tool_name = str(
                payload.get("toolName") or payload.get("action") or "cursor_composer"
            )
            params = (
                payload.get("parameters")
                if isinstance(payload.get("parameters"), dict)
                else payload
            )
            target = str(
                params.get("relativeWorkspacePath")
                or params.get("command")
                or "workspace"
            )
            ev_type = "mcp_call" if "mcpServer" in payload else "file_edit"
            return NormalizedAgentEvent(
                agent_source="cursor",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=params,
                timestamp=now,
            )

        # 4. OpenAI Codex / OpenAI Agent format
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
                "terminal_cmd"
                if tool_name.lower() in ("bash", "shell", "exec_command", "run_command", "execute")
                else "file_edit" if tool_name.lower() in ("apply_patch", "write_file", "edit_file", "replace_file_content")
                else "tool_call"
            )
            return NormalizedAgentEvent(
                agent_source="codex",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=args,
                timestamp=now,
            )

        # 5. Google Antigravity IDE / Generic MCP Agent format
        tool_name = str(
            payload.get("tool") or payload.get("function") or "agent_step"
        )
        args = (
            payload.get("args") if isinstance(payload.get("args"), dict) else payload
        )
        target = str(
            args.get("TargetFile")
            or args.get("command")
            or args.get("path")
            or "workspace"
        )
        return NormalizedAgentEvent(
            agent_source=source_hint if source_hint != "auto" else "antigravity",
            event_type="tool_call",
            tool_name=tool_name,
            target_resource=target,
            raw_arguments=args,
            timestamp=now,
        )

    @classmethod
    def ingest_ide_log_file(
        cls, log_path: Path, source_hint: str = "auto"
    ) -> list[dict[str, Any]]:
        # Read a JSON or JSONL IDE log file and return normalized event dicts.
        if not log_path.exists():
            return []
        raw_text = log_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw_text:
            return []
        events: list[dict[str, Any]] = []
        if raw_text.startswith("["):
            items = json.loads(raw_text)
            for item in items:
                if isinstance(item, dict):
                    events.append(
                        asdict(
                            cls.parse_hook_payload(item, source_hint=source_hint)
                        )
                    )
        else:
            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(
                            asdict(
                                cls.parse_hook_payload(obj, source_hint=source_hint)
                            )
                        )
                except json.JSONDecodeError:
                    continue
        return events

