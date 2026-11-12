"""Detect secrets (API keys, tokens, passwords) in event payloads and file content."""

import math
import re
from dataclasses import dataclass
from typing import List, Optional

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


@dataclass
class SecretMatch:
    """A detected secret match.

    Attributes:
        secret_type: Category of secret (e.g., 'aws_access_key').
        matched_text: The actual matched text (redacted in logs).
        confidence: 0.0-1.0 confidence score.
        source: Where it was found ('payload', 'file_content', etc.).
    """

    secret_type: str
    matched_text: str
    confidence: float
    source: str


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    High entropy (>4.5) suggests random/encrypted data like API keys.

    Args:
        text: String to analyze.

    Returns:
        Entropy value (bits per character).
    """
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_false_positive(text: str) -> bool:
    """Check if matched text is a known false positive.

    Args:
        text: The matched text to check.

    Returns:
        True if this is likely a placeholder, not a real secret.
    """
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
            matched_text = match.group(0)
            if _is_false_positive(matched_text):
                continue
            confidence = 0.9  # Pattern match = high confidence
            matches.append(SecretMatch(
                secret_type=secret_type,
                matched_text=matched_text[:8] + "..." + matched_text[-4:] if len(matched_text) > 16 else matched_text,
                confidence=confidence,
                source=source,
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
            # Check it wasn't already caught by pattern matching
            already_found = any(value[:8] in m.matched_text for m in matches)
            if not already_found:
                matches.append(SecretMatch(
                    secret_type="high_entropy_secret",
                    matched_text=value[:8] + "...",
                    confidence=min(0.5 + (entropy - 4.0) * 0.2, 0.95),
                    source=source,
                ))

    return matches

