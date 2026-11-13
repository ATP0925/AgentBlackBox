"""Detect secrets (API keys, tokens, passwords) in event payloads and file content."""

from collections import Counter
import hashlib
import hmac
import math
import os
import re
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# Match plausible high-entropy secret tokens (20 to 256 non-whitespace token chars)
# while ignoring plain filesystem paths (/usr/local/...) and URLs without query keys
_CANDIDATE_TOKEN_RE = re.compile(
    r"(?<![/\w.-])([A-Za-z0-9_\-+=/]{20,256})(?![/\w.-])"
)

# Pre-compiled patterns for known secret formats
_SECRET_PATTERNS = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*\S{20,}"), "aws_secret_key"),
    # GitHub
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "github_token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "github_pat"),
    # OpenAI
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_api_key"),
    # Stripe
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "stripe_live_key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{20,}"), "stripe_test_key"),
    # Google
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
    # Slack
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "slack_token"),
    # Generic patterns
    (re.compile(r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?\S{16,}['\"]?", re.IGNORECASE), "generic_api_key"),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?\S{8,}['\"]?", re.IGNORECASE), "password"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "private_key"),
    (re.compile(r"(?:bearer|token)\s+[A-Za-z0-9\-._~+/]{20,}", re.IGNORECASE), "bearer_token"),
    # Database URLs
    (re.compile(r"(?:postgres|mysql|mongodb)://\S+:\S+@\S+"), "database_url"),
]

# Patterns that look like secrets but are actually placeholders
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"sk-[xX]{16,}"),  # sk-xxxxxxxx
    re.compile(r"your[_-]?api[_-]?key", re.IGNORECASE),
    re.compile(r"<[A-Z_]+>"),  # <API_KEY>
    re.compile(r"\$\{[A-Z_]+\}"),  # ${API_KEY}
    re.compile(r"process\.env\.\w+"),
    re.compile(r"os\.environ"),
    re.compile(r"REPLACE_ME|TODO|FIXME|CHANGEME|INSERT_HERE", re.IGNORECASE),
]


_CACHED_SALT: Optional[str] = None


def _get_or_create_secret_salt(salt_override: Optional[str] = None) -> bytes:
    """Return salt for HMAC secret fingerprinting without hardcoded public fallbacks.

    Priority:
    1. Explicit salt_override parameter
    2. ABB_SECRET_SALT environment variable
    3. Persistent random 32-byte salt stored at ~/.agentblackbox/.secret_salt (mode 0600)
    4. Ephemeral in-process random 32-byte salt if filesystem is read-only
    """
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
    """Deterministic 8-char HMAC-SHA256 fingerprint of secret without leaking content.

    Prevents offline rainbow table / brute-force dictionary attacks on short secrets.
    Uses configurable ABB_SECRET_SALT, explicit salt, or a persistent local random key (0600).
    Has zero hardcoded salt fallbacks.
    """
    key = _get_or_create_secret_salt(salt)
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:8]


@dataclass
class SecretMatch:
    """A detected secret match.

    Attributes:
        secret_type: Category of secret (e.g., 'aws_access_key').
        matched_text: Safe placeholder ([REDACTED:<type>]); never leaks raw secret.
        confidence: 0.0-1.0 confidence score.
        source: Where it was found ('payload', 'file_content', etc.).
        length: Character length of the matched secret.
        offset: Character index offset in the source text.
        fingerprint: Safe 8-char SHA-256 fingerprint for correlation without content leak.
    """

    secret_type: str
    matched_text: str
    confidence: float
    source: str
    length: int = 0
    offset: Optional[int] = None
    fingerprint: str = ""


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
        # Skip pure hex git commit SHAs (40 chars lowercase hex) or pure letters
        if len(token) == 40 and all(c in "0123456789abcdef" for c in token):
            continue
        if token.isalpha() or token.isdigit():
            continue
        ent = _shannon_entropy(token)
        if ent >= entropy_threshold:
            findings.append((token, round(ent, 3)))
    return findings


def _is_false_positive(text: str) -> bool:
    """Check if matched text is a known false positive.

    Args:
        text: The matched text to check.

    Returns:
        True if this is likely a placeholder, not a real secret.
    """
    # Exact pwd/PWD with a path-like value is working directory, not password
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


def detect_secrets(text: str, source: str = "unknown") -> List[SecretMatch]:
    """Scan text for secrets using pattern matching and entropy analysis.

    Args:
        text: Text content to scan.
        source: Label for where the text came from.

    Returns:
        List of SecretMatch objects found.
    """
    matches: List[SecretMatch] = []

    for pattern, secret_type in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            if _is_false_positive(raw):
                continue
            confidence = 0.9  # Pattern match = high confidence
            matches.append(SecretMatch(
                secret_type=secret_type,
                matched_text=f"[REDACTED:{secret_type}]",
                confidence=confidence,
                source=source,
                length=len(raw),
                offset=match.start(),
                fingerprint=_secret_fingerprint(raw),
            ))

    # Entropy-based detection for unmatched high-entropy strings
    # Look for assignments like KEY = "very-random-string"
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
            # Check it wasn't already caught by pattern matching
            already_found = any(m.fingerprint == fp for m in matches)
            if not already_found:
                matches.append(SecretMatch(
                    secret_type="high_entropy_secret",
                    matched_text="[REDACTED:high_entropy_secret]",
                    confidence=min(0.5 + (entropy - 4.0) * 0.2, 0.95),
                    source=source,
                    length=len(value),
                    offset=match.start(1),
                    fingerprint=fp,
                ))

    return matches

