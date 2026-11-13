# Module: Redact-first secret scanner with Base64/Hex/URL decoding and split-token reassembly.
from __future__ import annotations

import base64
import binascii
import math
import re
import urllib.parse
from typing import NamedTuple


class SecretMatch(NamedTuple):
    secret_type: str
    raw_value: str


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}")),
    (
        "GITHUB_PAT",
        re.compile(
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{22,255}"
        ),
    ),
    ("STRIPE_KEY", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}")),
    (
        "JWT_TOKEN",
        re.compile(
            r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
        ),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
]

# Detects adjacent concatenated quotes in Python/JS/Shell: 'sk-ant-' + 'api03-xxxx'
_SPLIT_CONCAT_RE = re.compile(
    r"(['\"])([A-Za-z0-9_\-/+=]{3,})\1\s*(?:\+|\.)?\s*(['\"])([A-Za-z0-9_\-/+=]{6,})\3"
)
# Candidate Base64 blobs (length >= 16, with optional = padding)
_BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}(?=[^A-Za-z0-9+/=]|$)")
# Candidate Hex blobs (length >= 40, even length)
_HEX_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F]{40,}\b")


def shannon_entropy(data: str) -> float:
    # Calculate Shannon entropy in bits per character.
    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def reassemble_split_tokens(text: str) -> str:
    # Collapse concatenated string literals so split secrets can be matched.
    prev = None
    curr = text
    for _ in range(4):
        if curr == prev:
            break
        prev = curr
        curr = _SPLIT_CONCAT_RE.sub(lambda m: f'"{m.group(2)}{m.group(4)}"', curr)
    return curr


def _match_known_patterns(candidate: str) -> str | None:
    # Return secret_type if candidate matches any known pattern.
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(candidate):
            return name
    return None


def redact_secrets(text: str) -> tuple[str, list[str]]:
    # Scan and redact direct, split, URL-encoded, Base64-encoded, and Hex-encoded secrets.
    if not text:
        return text, []
    detected_types: list[str] = []

    # Step 1: Reassemble split tokens in a working copy to check if split secrets exist
    reassembled = reassemble_split_tokens(text)
    if reassembled != text:
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(reassembled) and not pattern.search(text):
                detected_types.append(f"SPLIT_{name}")
        text = reassembled

    # Step 2: URL-decode pass
    if "%" in text:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            matched_type = _match_known_patterns(unquoted)
            if matched_type:
                detected_types.append(f"URLENC_{matched_type}")
            text = unquoted

    # Step 3: Inspect Base64 candidates and redact if decoded payload holds a secret
    def _b64_replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            return token
        secret_kind = _match_known_patterns(decoded)
        if secret_kind:
            detected_types.append(f"BASE64_{secret_kind}")
            return f"[REDACTED:BASE64_{secret_kind}]"
        return token

    text = _BASE64_CANDIDATE_RE.sub(_b64_replacer, text)

    # Step 4: Inspect Hex candidates and redact if decoded payload holds a secret
    def _hex_replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) % 2 != 0:
            return token
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except ValueError:
            return token
        secret_kind = _match_known_patterns(decoded)
        if secret_kind:
            detected_types.append(f"HEX_{secret_kind}")
            return f"[REDACTED:HEX_{secret_kind}]"
        return token

    text = _HEX_CANDIDATE_RE.sub(_hex_replacer, text)

    # Step 5: Direct regex replacement on normalized text
    for name, pattern in SECRET_PATTERNS:

        def _direct_repl(m: re.Match[str], label: str = name) -> str:
            detected_types.append(label)
            return f"[REDACTED:{label}]"

        text = pattern.sub(_direct_repl, text)

    return text, sorted(set(detected_types))
