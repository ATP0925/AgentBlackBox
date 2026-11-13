"""Risk scoring for events — assigns 0-10 risk score based on event characteristics."""

import re
import shlex
from agentblackbox.storage.models import Event, EventType, Severity

_SHELL_OPERATORS = {";", "|", "||", "&&", "&"}
_BENIGN_PRINT_VERBS = {"echo", "printf", "grep", "rg", "cat", "head", "tail"}


def _split_shell_pipeline(command_str: str) -> tuple[list[list[str]], bool]:
    # Tokenize shell command respecting quotes while separating pipeline operators.
    lexer = shlex.shlex(command_str, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    subcommands: list[list[str]] = []
    current: list[str] = []
    has_pipe = False
    try:
        for tok in lexer:
            if tok in _SHELL_OPERATORS:
                if "|" in tok:
                    has_pipe = True
                if current:
                    subcommands.append(current)
                    current = []
            else:
                current.append(tok)
    except ValueError:
        # Unclosed quote fallback: treat entire string as single literal command
        return [command_str.split()], ("|" in command_str)
    if current:
        subcommands.append(current)
    return subcommands, has_pipe


def score_command_tokens(command_str: str) -> tuple[float, list[str]]:
    if not command_str or not command_str.strip():
        return 0.0, []

    reasons: list[str] = []
    max_score = 1.0
    subcommands, has_pipe = _split_shell_pipeline(command_str.strip())

    saw_network_fetch = False
    for tokens in subcommands:
        idx = 0
        while idx < len(tokens) and ("=" in tokens[idx] or tokens[idx] == "sudo"):
            if tokens[idx] == "sudo":
                max_score = max(max_score, 6.0)
                if "privilege_escalation:sudo" not in reasons:
                    reasons.append("privilege_escalation:sudo")
            idx += 1
        if idx >= len(tokens):
            continue

        verb = tokens[idx].rsplit("/", 1)[-1]
        args = tokens[idx + 1 :]
        flags = {a for a in args if a.startswith("-")}

        if verb in _BENIGN_PRINT_VERBS:
            continue

        if verb in ("curl", "wget"):
            saw_network_fetch = True
        elif saw_network_fetch and has_pipe and verb in ("sh", "bash", "zsh", "python", "python3"):
            max_score = max(max_score, 9.5)
            reasons.append("remote_code_execution:pipe_to_shell")

        if verb == "rm":
            has_rec = any(f in flags for f in ("-r", "-R", "--recursive", "-rf", "-fr"))
            has_force = any(f in flags for f in ("-f", "--force", "-rf", "-fr"))
            targets_root = any(a in ("/", "/*", "~", "~/*") for a in args)
            if targets_root or (has_rec and has_force):
                max_score = max(max_score, 9.5 if targets_root else 8.0)
                reasons.append("destructive_delete:rm_rf")
        elif verb == "git" and args:
            if args[0] == "push" and any(f in flags for f in ("-f", "--force", "--force-with-lease")):
                max_score = max(max_score, 8.5)
                reasons.append("destructive_git:force_push")
            elif args[0] == "reset" and "--hard" in flags:
                max_score = max(max_score, 7.0)
                reasons.append("destructive_git:reset_hard")
        elif verb == "chmod" and any("777" in a for a in args):
            max_score = max(max_score, 7.5)
            reasons.append("insecure_permissions:chmod_777")

    return min(10.0, round(max_score, 2)), reasons


# Risk score rules — deterministic, no ambiguity
_BASE_RISK: dict[str, float] = {
    EventType.FILE_CREATE: 0.5,
    EventType.FILE_MODIFY: 1.0,
    EventType.FILE_DELETE: 3.0,
    EventType.FILE_RENAME: 1.0,
    EventType.CMD_EXECUTE: 2.0,
    EventType.CMD_OUTPUT: 0.5,
    EventType.GIT_ADD: 1.0,
    EventType.GIT_COMMIT: 1.5,
    EventType.GIT_PUSH: 2.0,
    EventType.GIT_FORCE_PUSH: 9.0,
    EventType.GIT_RESET: 5.0,
    EventType.PROCESS_SPAWN: 1.5,
    EventType.PROCESS_EXIT: 0.5,
    EventType.SECRET_DETECTED: 8.0,
}

# Patterns that increase risk score
_DANGEROUS_COMMANDS = [
    ("rm -rf", 4.0),
    ("rm -r", 3.0),
    ("git push --force", 5.0),
    ("git push -f", 5.0),
    ("git reset --hard", 4.0),
    ("chmod 777", 3.0),
    ("curl | bash", 5.0),
    ("curl | sh", 5.0),
    ("wget | bash", 5.0),
    ("eval(", 3.0),
    ("exec(", 3.0),
    ("> /dev/null", 1.0),  # output suppression
    ("DROP TABLE", 5.0),
    ("DELETE FROM", 3.0),
    ("TRUNCATE", 4.0),
]

_SENSITIVE_PATHS = [
    (".env", 3.0),
    (".pem", 4.0),
    (".key", 4.0),
    ("id_rsa", 5.0),
    ("credentials", 3.0),
    ("secret", 2.0),
    (".git/config", 2.0),
]


def score_event(event: Event) -> Event:
    """Calculate and assign risk score to an event.

    Modifies the event in-place: sets risk_score and severity.
    Scoring is additive:
      base_risk + command_bonus + path_bonus + tag_bonus

    Args:
        event: Event to score.

    Returns:
        The same event with risk_score and severity updated.
    """
    risk = _BASE_RISK.get(event.event_type, 1.0)

    cmd_str = None
    if isinstance(event.payload, dict) and "command" in event.payload:
        cmd_str = str(event.payload["command"])
    elif event.event_type in (EventType.CMD_EXECUTE, EventType.CMD_OUTPUT) and isinstance(event.payload, str):
        cmd_str = str(event.payload)

    if cmd_str:
        cmd_risk, cmd_reasons = score_command_tokens(cmd_str)
        if cmd_risk > 1.0:
            risk = max(risk, cmd_risk)
        for r in cmd_reasons:
            if r not in event.tags:
                event.tags = list(event.tags) + [r]
    else:
        # Check payload for dangerous commands
        payload_str = str(event.payload).lower()
        for pattern, bonus in _DANGEROUS_COMMANDS:
            if pattern.lower() in payload_str:
                risk += bonus

    # Check source path for sensitive files
    if event.source_path:
        path_lower = event.source_path.lower()
        for pattern, bonus in _SENSITIVE_PATHS:
            if pattern in path_lower:
                risk += bonus

    # Check tags
    if "secret" in event.tags or "sensitive_file" in event.tags:
        risk += 2.0

    # Clamp to 0-10
    risk = min(max(risk, 0.0), 10.0)
    event.risk_score = round(risk, 1)

    # Set severity based on risk score
    if risk >= 8.0:
        event.severity = Severity.CRITICAL
    elif risk >= 5.0:
        event.severity = Severity.DANGER
    elif risk >= 3.0:
        event.severity = Severity.WARNING
    else:
        event.severity = Severity.INFO

    return event

