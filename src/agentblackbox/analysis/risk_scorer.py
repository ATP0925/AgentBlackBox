"""Risk scoring for events — assigns 0-10 risk score based on event characteristics."""

from agentblackbox.storage.models import Event, EventType, Severity


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

