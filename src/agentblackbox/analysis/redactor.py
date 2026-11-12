"""Secret redaction — redact secrets BEFORE persisting payloads or blobs to disk."""

import re
from typing import Any, List, Tuple

from agentblackbox.analysis.secret_detector import (
    SecretMatch,
    _SECRET_PATTERNS,
    _is_false_positive,
    _shannon_entropy,
)

_ASSIGN_ENTROPY_PATTERN = re.compile(
    r'((?:key|secret|token|password|credential|auth)\s*[:=]\s*["\'])([^"\']{16,})(["\'])',
    re.IGNORECASE,
)


def redact_text(text: str, source: str = "payload") -> Tuple[str, List[SecretMatch]]:
    """Redact detected secrets from a string before storage.

    Replaces matched secrets with ``[REDACTED:<secret_type>]``.
    Runs known regex patterns first, then high-entropy secret assignments.

    Args:
        text: Input string to sanitize.
        source: Origin label for SecretMatch records.

    Returns:
        Tuple of ``(redacted_text, matches_found)``.
    """
    if not text:
        return text, []

    redacted = text
    matches: List[SecretMatch] = []

    for pattern, secret_type in _SECRET_PATTERNS:
        def _replace_match(m: re.Match[str], stype: str = secret_type) -> str:
            raw = m.group(0)
            if "[REDACTED:" in raw or _is_false_positive(raw):
                return raw
            preview = raw[:8] + "..." + raw[-4:] if len(raw) > 16 else raw
            matches.append(SecretMatch(
                secret_type=stype,
                matched_text=preview,
                confidence=0.9,
                source=source,
            ))
            return f"[REDACTED:{stype}]"

        redacted = pattern.sub(_replace_match, redacted)

    def _replace_entropy(m: re.Match[str]) -> str:
        prefix, value, suffix = m.group(1), m.group(2), m.group(3)
        if "[REDACTED:" in value or _is_false_positive(value):
            return m.group(0)
        entropy = _shannon_entropy(value)
        if entropy > 4.0:
            matches.append(SecretMatch(
                secret_type="high_entropy_secret",
                matched_text=value[:8] + "...",
                confidence=min(0.5 + (entropy - 4.0) * 0.2, 0.95),
                source=source,
            ))
            return f"{prefix}[REDACTED:high_entropy_secret]{suffix}"
        return m.group(0)

    redacted = _ASSIGN_ENTROPY_PATTERN.sub(_replace_entropy, redacted)
    return redacted, matches


def redact_payload(obj: Any, source: str = "payload") -> Tuple[Any, List[SecretMatch]]:
    """Recursively redact secrets inside a dict/list/string payload.

    Does not mutate the caller's object.

    Args:
        obj: Payload object (dict, list, tuple, or scalar).
        source: Origin label for SecretMatch records.

    Returns:
        Tuple of ``(sanitized_copy, all_matches)``.
    """
    all_matches: List[SecretMatch] = []

    if isinstance(obj, str):
        return redact_text(obj, source=source)

    if isinstance(obj, dict):
        clean_dict = {}
        for k, v in obj.items():
            clean_v, m = redact_payload(v, source=source)
            all_matches.extend(m)
            clean_dict[k] = clean_v
        return clean_dict, all_matches

    if isinstance(obj, list):
        clean_list = []
        for item in obj:
            clean_item, m = redact_payload(item, source=source)
            all_matches.extend(m)
            clean_list.append(clean_item)
        return clean_list, all_matches

    return obj, all_matches


def redact_bytes(data: bytes, source: str = "file_content") -> Tuple[bytes, List[SecretMatch]]:
    """Redact secrets from UTF-8 text bytes; leave binary bytes untouched.

    Args:
        data: Raw file bytes.
        source: Origin label for SecretMatch records.

    Returns:
        Tuple of ``(sanitized_bytes, matches)``.
    """
    if b"\x00" in data:
        return data, []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, []

    redacted, matches = redact_text(text, source=source)
    if not matches:
        return data, []
    return redacted.encode("utf-8"), matches
