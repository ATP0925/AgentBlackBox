"""Secret redaction — redact secrets BEFORE persisting payloads or blobs to disk."""

import re
from typing import Any, List, Optional, Tuple

from agentblackbox.analysis.secret_detector import (
    SecretMatch,
    _SECRET_PATTERNS,
    _is_false_positive,
    _secret_fingerprint,
    _shannon_entropy,
)

_SENSITIVE_KEY_PATTERN = re.compile(
    r"^(?:(?:api[_-]?|access[_-]?|auth[_-]?|bearer[_-]?|client[_-]?|refresh[_-]?|secret[_-]?|private[_-]?)?(?:password|passwd|passphrase|secret|api[_-]?key|private[_-]?key|authorization|credentials?)|(?:api[_-]?|access[_-]?|auth[_-]?|bearer[_-]?|refresh[_-]?|session[_-]?)?token)$",
    re.IGNORECASE,
)

_ASSIGN_PATTERN = re.compile(
    r'((?:key|secret|token|password|credential|auth|bearer)\s*[:=]\s*(?:["\']?))([^\s"\'`]{8,})((?:["\']?))',
    re.IGNORECASE,
)


def _is_high_entropy_secret(value: str) -> Tuple[bool, float]:
    """Check entropy considering charset (hex vs base64/ascii)."""
    if len(value) < 12:
        return False, 0.0
    entropy = _shannon_entropy(value)
    # Hex strings (0-9, a-f) have theoretical max entropy of 4.0; threshold is 2.8
    if bool(re.fullmatch(r"[0-9a-fA-F]+", value)) and len(value) >= 16:
        return entropy >= 2.8, entropy
    return entropy >= 4.0, entropy


def redact_text(text: str, source: str = "payload") -> Tuple[str, List[SecretMatch]]:
    """Redact detected secrets from a string before storage.

    Replaces matched secrets with ``[REDACTED:<secret_type>]``.
    Runs known regex patterns first, then entropy-based assignments.

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
            matches.append(SecretMatch(
                secret_type=stype,
                matched_text=f"[REDACTED:{stype}]",
                confidence=0.9,
                source=source,
                length=len(raw),
                offset=m.start(),
                fingerprint=_secret_fingerprint(raw),
            ))
            return f"[REDACTED:{stype}]"

        redacted = pattern.sub(_replace_match, redacted)

    def _replace_entropy(m: re.Match[str]) -> str:
        prefix, value, suffix = m.group(1), m.group(2), m.group(3)
        if "[REDACTED:" in value or _is_false_positive(value):
            return m.group(0)
        is_secret, entropy = _is_high_entropy_secret(value)
        if is_secret:
            matches.append(SecretMatch(
                secret_type="high_entropy_secret",
                matched_text="[REDACTED:high_entropy_secret]",
                confidence=min(0.5 + (entropy - 2.8) * 0.2, 0.95),
                source=source,
                length=len(value),
                offset=m.start(2),
                fingerprint=_secret_fingerprint(value),
            ))
            return f"{prefix}[REDACTED:high_entropy_secret]{suffix}"
        return m.group(0)

    redacted = _ASSIGN_PATTERN.sub(_replace_entropy, redacted)
    return redacted, matches


def redact_payload(obj: Any, source: str = "payload") -> Tuple[Any, List[SecretMatch]]:
    """Recursively redact secrets inside a dict/list/string payload.

    Redacts known dictionary keys (e.g. password, secret, api_key) immediately,
    as well as string values matching regex or entropy signatures.
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
            if isinstance(v, str) and _SENSITIVE_KEY_PATTERN.match(str(k)):
                if not v.startswith("[REDACTED:"):
                    clean_dict[k] = f"[REDACTED:{k.lower()}]"
                    all_matches.append(SecretMatch(
                        secret_type=f"sensitive_key_{k.lower()}",
                        matched_text=f"[REDACTED:{k.lower()}]",
                        confidence=1.0,
                        source=source,
                        length=len(v),
                        fingerprint=_secret_fingerprint(v),
                    ))
                    continue
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
    """Redact secrets from UTF-8 or UTF-16 text bytes; leave binary bytes untouched.

    Handles Windows PowerShell UTF-16 output encoding gracefully.

    Args:
        data: Raw file bytes.
        source: Origin label for SecretMatch records.

    Returns:
        Tuple of ``(sanitized_bytes, matches)``.
    """
    encoding: Optional[str] = None
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        encoding = "utf-16"
    elif len(data) >= 4 and (data[1] == 0 or data[0] == 0):
        try:
            data.decode("utf-16")
            encoding = "utf-16"
        except UnicodeDecodeError:
            pass

    if encoding is None:
        if b"\x00" in data:
            return data, []
        encoding = "utf-8"

    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        return data, []

    redacted, matches = redact_text(text, source=source)
    if not matches:
        return data, []
    return redacted.encode(encoding), matches
