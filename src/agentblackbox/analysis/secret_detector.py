"""Multi-pass secret detector catching direct, split, URL, Base64, and Hex secrets."""
from __future__ import annotations

import base64
import binascii
from collections import Counter
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any, List, Optional, Tuple
import urllib.parse

# Split-token concatenation regex
_SPLIT_CONCAT_RE = re.compile(
    r"""(['"])([A-Za-z0-9_\-/+=]{3,})\1\s*(?:\+|\.)?\s*(['"])([A-Za-z0-9_\-/+=]{6,})\3"""
)
_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CANDIDATE_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40,}(?![0-9a-fA-F])")

# Match plausible high-entropy secret tokens (20 to 256 non-whitespace token chars)
_CANDIDATE_TOKEN_RE = re.compile(
    r"(?<![/\w.-])([A-Za-z0-9_\-+=/]{20,256})(?![/\w.-])"
)

PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}")),
    ("github_token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}")),
    ("openai_api_key", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}")),
    ("anthropic_api_key", re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{20,}")),
    ("stripe_live_key", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("stripe_test_key", re.compile(r"(?:sk|rk)_test_[A-Za-z0-9]{16,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{20,})")),
    ("database_url", re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@[^\s'\"]+")),
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]")),
    ("password", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
]

# Legacy tuple format (regex, name)
_SECRET_PATTERNS = [(pattern, name) for name, pattern in PATTERNS]

_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"sk-[xX]{16,}"),
    re.compile(r"your[_-]?api[_-]?key", re.IGNORECASE),
    re.compile(r"<[A-Z_]+>"),
    re.compile(r"\$\{[A-Z_]+\}"),
    re.compile(r"process\.env\.\w+"),
    re.compile(r"os\.environ"),
    re.compile(r"REPLACE_ME|TODO|FIXME|CHANGEME|INSERT_HERE", re.IGNORECASE),
]

_CACHED_SALT: Optional[str] = None


def _get_or_create_secret_salt(salt_override: Optional[str] = None) -> bytes:
    """Return salt for HMAC secret fingerprinting without hardcoded public fallbacks."""
    global _CACHED_SALT
    if salt_override:
        return salt_override.encode("utf-8")

    env_salt = os.environ.get("ABB_SECRET_SALT")
    if env_salt:
        return env_salt.encode("utf-8")

    if _CACHED_SALT:
        return _CACHED_SALT.encode("utf-8")

    salt_path = Path.home() / ".agentblackbox" / ".secret_salt"
    try:
        if salt_path.exists():
            content = salt_path.read_text(encoding="utf-8").strip()
            if content:
                _CACHED_SALT = content
                return content.encode("utf-8")
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        new_salt = secrets.token_hex(32)
        salt_path.write_text(new_salt, encoding="utf-8")
        if sys.platform == "win32":
            try:
                import subprocess
                user = os.environ.get("USERNAME")
                if user:
                    subprocess.run(
                        ["icacls", str(salt_path), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                        capture_output=True,
                        check=False,
                        timeout=2,
                    )
            except Exception:
                pass
        else:
            try:
                salt_path.chmod(0o600)
            except (OSError, NotImplementedError):
                pass
        _CACHED_SALT = new_salt
        return new_salt.encode("utf-8")
    except Exception:
        if not _CACHED_SALT:
            _CACHED_SALT = secrets.token_hex(32)
        return _CACHED_SALT.encode("utf-8")


def _secret_fingerprint(raw: str, salt: Optional[str] = None) -> str:
    """Deterministic 8-char HMAC-SHA256 fingerprint of secret without leaking content."""
    key = _get_or_create_secret_salt(salt)
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:8]


@dataclass
class SecretMatch:
    """A detected secret match supporting both pattern_name and secret_type."""
    pattern_name: str = ""
    matched_text: str = ""
    entropy: float = 0.0
    line_number: Optional[int] = None
    secret_type: str = ""
    confidence: float = 0.9
    source: str = "payload"
    length: int = 0
    offset: Optional[int] = None
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.pattern_name and self.secret_type:
            self.pattern_name = self.secret_type
        elif not self.secret_type and self.pattern_name:
            self.secret_type = self.pattern_name
        if not self.length and self.matched_text:
            self.length = len(self.matched_text)


def reassemble_split_tokens(text: str) -> str:
    """Reassemble strings split across quotes/concatenation into candidate tokens."""
    prev = None
    curr = text
    for _ in range(4):
        if curr == prev:
            break
        prev = curr
        curr = _SPLIT_CONCAT_RE.sub(lambda m: f'"{m.group(2)}{m.group(4)}"', curr)
    return curr


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per character) using C-optimized Counter."""
    length = len(text)
    if length == 0:
        return 0.0
    counts = Counter(text)
    inv_len = 1.0 / length
    return -sum((count * inv_len) * math.log2(count * inv_len) for count in counts.values())


def find_high_entropy_tokens(
    payload: str,
    entropy_threshold: float = 4.35,
    max_scan_bytes: int = 262_144,
) -> list[tuple[str, float]]:
    """Extract only candidate secret tokens and compute entropy in O(k) time."""
    if not payload:
        return []
    sample = payload[:max_scan_bytes]
    findings: list[tuple[str, float]] = []
    for match in _CANDIDATE_TOKEN_RE.finditer(sample):
        token = match.group(1)
        if len(token) == 40 and all(c in "0123456789abcdef" for c in token):
            continue
        if token.isalpha() or token.isdigit():
            continue
        ent = _shannon_entropy(token)
        if ent >= entropy_threshold:
            findings.append((token, round(ent, 3)))
    return findings


def _is_false_positive(text: str) -> bool:
    """Check if matched text is a known false positive."""
    pwd_m = re.match(r"^(?:pwd)\s*[:=]\s*['\"]?(\S+?)['\"]?$", text, re.IGNORECASE)
    if pwd_m:
        val = pwd_m.group(1).strip("'\"")
        if (
            val.startswith(("/", "\\", "~"))
            or bool(re.match(r"^[A-Za-z]:[/\\]", val))
            or (("/" in val or "\\" in val) and "://" not in val)
        ):
            return True

    for pattern in _FALSE_POSITIVE_PATTERNS:
        if pattern.search(text):
            return True
    return False


class SecretDetector:
    """Multi-pass secret detector for plain, split, URL, Base64, and Hex secret payloads."""

    def __init__(self, min_entropy: float = 4.5) -> None:
        self.min_entropy = min_entropy

    def _calculate_entropy(self, text: str) -> float:
        return _shannon_entropy(text)

    def _match_first_pattern(self, candidate: str) -> Optional[Tuple[str, str]]:
        for name, pattern in PATTERNS:
            m = pattern.search(candidate)
            if m:
                matched = m.group(1) if m.lastindex else m.group(0)
                return name, matched
        return None

    def scan_text(self, text: str) -> List[SecretMatch]:
        if not text:
            return []
        matches: List[SecretMatch] = []
        seen: set[Tuple[str, str]] = set()

        for line_idx, raw_line in enumerate(text.splitlines(), start=1):
            reassembled = reassemble_split_tokens(raw_line)
            for target_line, prefix in ((raw_line, ""), (reassembled, "split_")):
                for name, pattern in PATTERNS:
                    for m in pattern.finditer(target_line):
                        val = m.group(1) if m.lastindex else m.group(0)
                        if _is_false_positive(val):
                            continue
                        if (name, val) not in seen:
                            seen.add((name, val))
                            label = f"{prefix}{name}" if prefix and val not in raw_line else name
                            matches.append(
                                SecretMatch(
                                    pattern_name=label,
                                    secret_type=label,
                                    matched_text=val,
                                    entropy=round(self._calculate_entropy(val), 3),
                                    line_number=line_idx,
                                    confidence=0.9,
                                    fingerprint=_secret_fingerprint(val),
                                )
                            )

            if "%" in raw_line:
                unquoted = urllib.parse.unquote(raw_line)
                if unquoted != raw_line:
                    hit = self._match_first_pattern(unquoted)
                    if hit and not _is_false_positive(hit[1]):
                        if (hit[0], hit[1]) not in seen:
                            seen.add((hit[0], hit[1]))
                            label = f"urlenc_{hit[0]}"
                            matches.append(
                                SecretMatch(
                                    pattern_name=label,
                                    secret_type=label,
                                    matched_text=hit[1],
                                    entropy=round(self._calculate_entropy(hit[1]), 3),
                                    line_number=line_idx,
                                    confidence=0.9,
                                    fingerprint=_secret_fingerprint(hit[1]),
                                )
                            )

            for b64_m in _BASE64_CANDIDATE_RE.finditer(raw_line):
                token = b64_m.group(0)
                if len(token) % 4 != 0:
                    continue
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
                except (binascii.Error, ValueError):
                    continue
                hit = self._match_first_pattern(decoded)
                if hit and not _is_false_positive(hit[1]):
                    label = f"base64_{hit[0]}"
                    if (label, token) not in seen:
                        seen.add((label, token))
                        matches.append(
                            SecretMatch(
                                pattern_name=label,
                                secret_type=label,
                                matched_text=token,
                                entropy=round(self._calculate_entropy(decoded), 3),
                                line_number=line_idx,
                                confidence=0.9,
                                fingerprint=_secret_fingerprint(token),
                            )
                        )

            for hex_m in _HEX_CANDIDATE_RE.finditer(raw_line):
                token = hex_m.group(0)
                if len(token) % 2 != 0:
                    continue
                try:
                    decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
                except ValueError:
                    continue
                hit = self._match_first_pattern(decoded)
                if hit and not _is_false_positive(hit[1]):
                    label = f"hex_{hit[0]}"
                    if (label, token) not in seen:
                        seen.add((label, token))
                        matches.append(
                            SecretMatch(
                                pattern_name=label,
                                secret_type=label,
                                matched_text=token,
                                entropy=round(self._calculate_entropy(decoded), 3),
                                line_number=line_idx,
                                confidence=0.9,
                                fingerprint=_secret_fingerprint(token),
                            )
                        )

        return matches

    def scan_event(self, event: Any) -> List[SecretMatch]:
        payload = getattr(event, "payload", {})
        serialized = json.dumps(payload, default=str)
        return self.scan_text(serialized)


def detect_secrets(text: str, source: str = "unknown") -> List[SecretMatch]:
    """Scan text for secrets using pattern matching and entropy analysis."""
    matches: List[SecretMatch] = []

    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            if _is_false_positive(raw):
                continue
            confidence = 0.9
            matches.append(SecretMatch(
                pattern_name=name,
                secret_type=name,
                matched_text=f"[REDACTED:{name}]",
                confidence=confidence,
                source=source,
                length=len(raw),
                offset=match.start(),
                fingerprint=_secret_fingerprint(raw),
            ))

    assign_pattern = re.compile(
        r'(?:key|secret|token|password|credential|auth)\s*[:=]\s*["\']([^"\']{16,})["\']',
        re.IGNORECASE,
    )
    for match in assign_pattern.finditer(text):
        value = match.group(1)
        if _is_false_positive(value):
            continue
        entropy = _shannon_entropy(value)
        if entropy > 4.0:
            fp = _secret_fingerprint(value)
            already_found = any(m.fingerprint == fp for m in matches)
            if not already_found:
                matches.append(SecretMatch(
                    pattern_name="high_entropy_secret",
                    secret_type="high_entropy_secret",
                    matched_text="[REDACTED:high_entropy_secret]",
                    confidence=min(0.5 + (entropy - 4.0) * 0.2, 0.95),
                    source=source,
                    length=len(value),
                    offset=match.start(1),
                    fingerprint=fp,
                ))

    return matches
