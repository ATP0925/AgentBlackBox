#!/usr/bin/env python3
"""Automated v0.3.0 Upgrade & Verification Script for ATP0925/AgentBlackBox.

Usage (run from the root of your ATP0925/AgentBlackBox clone):
    python3 apply_agentblackbox_v030_upgrade.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
SRC_ABB = ROOT / "src" / "agentblackbox"


def ensure_repo_root() -> None:
    if not (ROOT / "pyproject.toml").exists() or not SRC_ABB.exists():
        sys.stderr.write(
            "Error: Run this script from the root of the ATP0925/AgentBlackBox repository "
            "(where pyproject.toml and src/agentblackbox/ are located).\n"
        )
        sys.exit(1)


def update_pyproject() -> None:
    pyproject_path = ROOT / "pyproject.toml"
    text = pyproject_path.read_text(encoding="utf-8")
    text = re.sub(r'version\s*=\s*"[^"]+"', 'version = "0.3.0"', text, count=1)
    if '"keyring' not in text and "'keyring" not in text:
        text = re.sub(
            r'(dependencies\s*=\s*\[\s*\n)',
            r'\1    "keyring>=25.0.0",\n',
            text,
            count=1,
        )
    pyproject_path.write_text(text, encoding="utf-8")
    print("[1/7] Updated pyproject.toml (version=0.3.0, added keyring>=25.0.0)")

KEY_PROVIDER_CODE = r'''"""OS Keychain integration, HKDF subkey derivation, and process env scrubbing."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from typing import Final, Optional, Union

import keyring
from keyring.errors import KeyringError, NoKeyringError

logger = logging.getLogger(__name__)

SERVICE_NAME: Final[str] = "agentblackbox"
KEY_NAME: Final[str] = "hmac_master_key"
ENV_HMAC_KEY: Final[str] = "ABB_HMAC_KEY"
ENV_TEST_KEY: Final[str] = "ABB_EPHEMERAL_TEST_KEY"

_ACTIVE_PROVIDER: Optional["KeyProvider"] = None


class KeyProviderError(RuntimeError):
    """Raised when OS Keychain is unavailable and ABB_EPHEMERAL_TEST_KEY is not enabled."""


def hkdf_sha256(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a domain-separated subkey using RFC 5869 HKDF-SHA256."""
    salt = b"agentblackbox-hkdf-v1-salt"
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


class KeyProvider:
    """Manages the master HMAC key in memory and OS Keychain (DPAPI / SecretService / macOS)."""

    def __init__(self, master_key: bytes) -> None:
        if not master_key:
            raise ValueError("Master key cannot be empty.")
        self._master_key = bytearray(master_key)

    @property
    def raw_key(self) -> bytes:
        return bytes(self._master_key)

    @classmethod
    def initialize(cls, force_reload: bool = False) -> "KeyProvider":
        global _ACTIVE_PROVIDER
        if _ACTIVE_PROVIDER is not None and not force_reload:
            os.environ.pop(ENV_HMAC_KEY, None)
            return _ACTIVE_PROVIDER

        legacy_env = os.environ.pop(ENV_HMAC_KEY, None)

        if os.environ.get(ENV_TEST_KEY) == "1":
            seed = legacy_env.encode("utf-8") if legacy_env else secrets.token_bytes(32)
            _ACTIVE_PROVIDER = cls(seed)
            return _ACTIVE_PROVIDER

        try:
            stored = keyring.get_password(SERVICE_NAME, KEY_NAME)
            if stored:
                try:
                    raw = bytes.fromhex(stored.strip())
                except ValueError:
                    raw = stored.encode("utf-8")
                _ACTIVE_PROVIDER = cls(raw)
                return _ACTIVE_PROVIDER

            raw_key = legacy_env.encode("utf-8") if legacy_env else secrets.token_bytes(32)
            keyring.set_password(SERVICE_NAME, KEY_NAME, raw_key.hex())
            logger.info("Stored master HMAC key in OS Keychain (%s).", SERVICE_NAME)
            _ACTIVE_PROVIDER = cls(raw_key)
            return _ACTIVE_PROVIDER
        except (NoKeyringError, KeyringError) as exc:
            if legacy_env:
                _ACTIVE_PROVIDER = cls(legacy_env.encode("utf-8"))
                return _ACTIVE_PROVIDER
            raise KeyProviderError(
                "OS Keychain backend unavailable. Configure system keyring or set "
                "ABB_EPHEMERAL_TEST_KEY=1 in isolated CI/pytest environments."
            ) from exc

    @classmethod
    def get_active_key_optional(cls) -> Optional[bytes]:
        global _ACTIVE_PROVIDER
        if _ACTIVE_PROVIDER is not None:
            return _ACTIVE_PROVIDER.raw_key
        legacy_env = os.environ.get(ENV_HMAC_KEY)
        if legacy_env:
            return legacy_env.encode("utf-8")
        return None

    def derive_subkey(self, domain: Union[bytes, str]) -> bytes:
        d = domain.encode("utf-8") if isinstance(domain, str) else domain
        return hmac.new(self.raw_key, d, hashlib.sha256).digest()

    def sign_payload(self, purpose: Union[str, bytes], payload: bytes) -> str:
        subkey = self.derive_subkey(purpose)
        return hmac.new(subkey, payload, hashlib.sha256).hexdigest()

    def verify_payload(
        self, purpose: Union[str, bytes], payload: bytes, signature_hex: str
    ) -> bool:
        expected = self.sign_payload(purpose, payload)
        return hmac.compare_digest(expected, signature_hex)

    def zeroize(self) -> None:
        global _ACTIVE_PROVIDER
        for i in range(len(self._master_key)):
            self._master_key[i] = 0
        _ACTIVE_PROVIDER = None
'''

TAMPER_GUARD_CODE = r'''"""Out-of-workspace shadow checkpoint mirroring and tamper detection."""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import urllib.request
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def get_default_shadow_root() -> Path:
    env_override = os.environ.get("ABB_SHADOW_DIR")
    if env_override:
        root = Path(env_override)
    elif platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        root = base / "agentblackbox" / "shadow_mirrors"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        root = base / "agentblackbox" / "shadow_mirrors"
    root.mkdir(parents=True, exist_ok=True)
    return root


class TamperGuard:
    """Mirrors signed .tip checkpoints outside the workspace and detects rollback or deletion."""

    def __init__(
        self,
        workspace_abb_dir: Path,
        session_id: str,
        shadow_root: Optional[Path] = None,
        webhook_url: Optional[str] = None,
    ) -> None:
        self.workspace_abb_dir = workspace_abb_dir
        self.session_id = session_id
        self.shadow_dir = (shadow_root or get_default_shadow_root()) / session_id
        self.shadow_dir.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url or os.environ.get("ABB_CHECKPOINT_WEBHOOK_URL")

    @property
    def workspace_tip_path(self) -> Path:
        cp_dir = self.workspace_abb_dir / "checkpoints"
        if cp_dir.exists():
            return cp_dir / f"{self.session_id}.tip"
        return self.workspace_abb_dir / f"{self.session_id}.tip"

    @property
    def shadow_tip_path(self) -> Path:
        return self.shadow_dir / f"{self.session_id}.tip"

    def replicate_tip_checkpoint(
        self, tip_data: dict[str, Any], target_path: Optional[Path] = None
    ) -> Path:
        normalized = dict(tip_data)
        seq_val = normalized.get("last_seq", normalized.get("seq", 0))
        hash_val = normalized.get("head_hash", normalized.get("tip_hash", ""))
        sig_val = normalized.get("signature", normalized.get("mac", ""))
        normalized["last_seq"] = seq_val
        normalized["seq"] = seq_val
        normalized["head_hash"] = hash_val
        normalized["tip_hash"] = hash_val
        normalized["signature"] = sig_val
        normalized["mac"] = sig_val

        serialized = json.dumps(normalized, sort_keys=True, indent=2).encode("utf-8")
        ws_tip = target_path or self.workspace_tip_path
        ws_tip.parent.mkdir(parents=True, exist_ok=True)
        ws_tip.write_bytes(serialized)
        try:
            ws_tip.chmod(0o600)
        except (OSError, NotImplementedError):
            pass

        self.shadow_tip_path.write_bytes(serialized)
        try:
            self.shadow_tip_path.chmod(0o600)
        except (OSError, NotImplementedError):
            pass

        if self.webhook_url:
            self._ship_remote_checkpoint(serialized)
        return self.shadow_tip_path

    def verify_workspace_integrity(
        self, explicit_ws_tip: Optional[Path] = None
    ) -> tuple[bool, str]:
        ws_tip = explicit_ws_tip or self.workspace_tip_path
        if not self.shadow_tip_path.exists():
            return True, "No out-of-tree shadow baseline recorded yet."
        if not ws_tip.exists():
            return False, f"TAMPER ALERT: Workspace checkpoint {ws_tip.name} was deleted!"

        try:
            ws_payload = json.loads(ws_tip.read_text(encoding="utf-8"))
            sh_payload = json.loads(self.shadow_tip_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return False, f"TAMPER ALERT: Corrupted checkpoint JSON ({exc})"

        ws_seq = int(ws_payload.get("last_seq", ws_payload.get("seq", 0)))
        sh_seq = int(sh_payload.get("last_seq", sh_payload.get("seq", 0)))

        if ws_seq < sh_seq:
            return (
                False,
                f"TAMPER ALERT: Checkpoint sequence rolled back (workspace={ws_seq} < shadow={sh_seq})!",
            )
        ws_sig = ws_payload.get("signature") or ws_payload.get("mac") or ""
        sh_sig = sh_payload.get("signature") or sh_payload.get("mac") or ""
        if ws_seq == sh_seq and ws_sig != sh_sig:
            return False, "TAMPER ALERT: Workspace checkpoint signature mismatch against shadow mirror!"
        return True, "Workspace checkpoint verified against out-of-tree shadow mirror."

    def restore_from_shadow(self, target_ws_tip: Optional[Path] = None) -> bool:
        ws_tip = target_ws_tip or self.workspace_tip_path
        if self.shadow_tip_path.exists():
            ws_tip.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.shadow_tip_path, ws_tip)
            return True
        return False

    def apply_os_readonly_guard(self, target_file: Path) -> bool:
        try:
            target_file.chmod(0o444)
            return True
        except OSError as exc:
            logger.debug("Could not apply chmod 0444 on %s: %s", target_file, exc)
            return False

    def _ship_remote_checkpoint(self, payload: bytes) -> None:
        if not self.webhook_url or not self.webhook_url.startswith(("https://", "http://")):
            return
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "AgentBlackBox-Guard/0.3"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2.5):
                pass
        except Exception as exc:
            logger.debug("Remote checkpoint webhook skipped: %s", exc)
'''

SECRET_DETECTOR_CODE = r'''"""Multi-pass secret detector catching direct, split, URL, Base64, and Hex secrets."""
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
'''

IDE_COLLECTOR_APPEND_CODE = r'''
# --- v0.3.0 Universal IDE Collector (Claude Code, Cursor, Cline, Antigravity) ---
from dataclasses import dataclass
from typing import Any
from agentblackbox.storage.models import Event, EventType, Severity


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
            ev_type = EventType.CMD_EXECUTE if "command" in params else EventType.FILE_MODIFY
            return NormalizedAgentEvent(
                agent_source="cursor",
                event_type=ev_type,
                tool_name=tool_name,
                target_resource=target,
                raw_arguments=params,
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
'''

TEST_SUITE_CODE = r'''"""Unit tests verifying all 4 v0.3.0 architectural security upgrades for AgentBlackBox."""
from __future__ import annotations

import base64
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from keyring.errors import NoKeyringError

from agentblackbox.analysis.key_provider import (
    ENV_HMAC_KEY,
    ENV_TEST_KEY,
    KeyProvider,
    KeyProviderError,
)
from agentblackbox.analysis.redactor import redact_secrets
from agentblackbox.analysis.secret_detector import SecretDetector
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Session
from agentblackbox.storage.tamper_guard import TamperGuard
from agentblackbox.watchers.agent_hooks import UniversalIDECollector


def test_gap1_key_provider_scrubs_env_and_integrates_with_event_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV_TEST_KEY, raising=False)
    monkeypatch.setenv(ENV_HMAC_KEY, "ab" * 32)
    mock_ring: dict[tuple[str, str], str] = {}

    with patch("keyring.get_password", side_effect=lambda s, u: mock_ring.get((s, u))), patch(
        "keyring.set_password", side_effect=lambda s, u, p: mock_ring.__setitem__((s, u), p)
    ):
        provider = KeyProvider.initialize(force_reload=True)
        assert ENV_HMAC_KEY not in os.environ

        db_path = tmp_path / ".agentblackbox" / "events.db"
        store = EventStore(db_path=db_path)
        sess = store.create_session(Session(id="s_keytest", workspace_path=str(tmp_path)))
        store.insert_event(
            Event(session_id=sess.id, event_type=EventType.CMD_EXECUTE, payload={"cmd": "echo ok"})
        )
        res = store.verify_chain(sess.id)
        assert res.valid is True
        provider.zeroize()


def test_gap1_key_provider_fails_closed_without_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_TEST_KEY, raising=False)
    monkeypatch.delenv(ENV_HMAC_KEY, raising=False)
    with patch("keyring.get_password", side_effect=NoKeyringError("No D-Bus")):
        with pytest.raises(KeyProviderError):
            KeyProvider.initialize(force_reload=True)


def test_gap2_tamper_guard_detects_checkpoint_deletion_and_rollback(tmp_path: Path) -> None:
    ws_abb = tmp_path / ".agentblackbox"
    shadow_root = tmp_path / "shadow_mirrors"
    guard = TamperGuard(ws_abb, session_id="sess_tamper", shadow_root=shadow_root)

    guard.replicate_tip_checkpoint({"last_seq": 8, "head_hash": "hash8", "signature": "sig8"})
    ok, _ = guard.verify_workspace_integrity()
    assert ok is True

    guard.workspace_tip_path.write_text(
        '{"last_seq": 3, "head_hash": "hash3", "signature": "sig3"}', encoding="utf-8"
    )
    ok_rb, msg_rb = guard.verify_workspace_integrity()
    assert ok_rb is False
    assert "rolled back" in msg_rb

    guard.workspace_tip_path.unlink()
    assert guard.verify_workspace_integrity()[0] is False
    assert guard.restore_from_shadow() is True
    assert guard.verify_workspace_integrity()[0] is True


def test_gap3_secret_detector_and_redactor_catch_base64_hex_and_split_tokens() -> None:
    detector = SecretDetector()
    raw_openai = "sk-" + "proj-1234567890abcdefghijklmnop"
    b64_openai = base64.b64encode(raw_openai.encode("utf-8")).decode("ascii")

    matches_b64 = detector.scan_text(f"export TOKEN={b64_openai}")
    assert any("base64_openai_api_key" in m.pattern_name for m in matches_b64)

    redacted_b64 = redact_secrets(f"export TOKEN={b64_openai}")
    assert b64_openai not in redacted_b64
    assert "[REDACTED:" in redacted_b64

    split_line = 'api_key = "sk-ant-api03-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"'
    redacted_split = redact_secrets(split_line)
    assert "sk-ant-api03-" not in redacted_split
    assert "[REDACTED:" in redacted_split


def test_gap4_universal_ide_collector_maps_to_valid_storage_events() -> None:
    cursor_norm = UniversalIDECollector.parse_hook_payload(
        {
            "composerId": "c1",
            "mcpServer": "fs",
            "toolName": "edit_file",
            "parameters": {"relativeWorkspacePath": "src/main.py"},
        }
    )
    ev_cursor = cursor_norm.to_storage_event(session_id="sess_ide")
    assert ev_cursor.agent_id == "cursor"
    assert ev_cursor.event_type == EventType.FILE_MODIFY
    assert ev_cursor.source_path == "src/main.py"

    ag_norm = UniversalIDECollector.parse_hook_payload(
        {"tool": "execute_bash", "args": {"command": "pytest -q"}}
    )
    ev_ag = ag_norm.to_storage_event(session_id="sess_ide")
    assert ev_ag.agent_id == "antigravity"
    assert ev_ag.event_type == EventType.CMD_EXECUTE
'''


def write_new_modules() -> None:
    kp_path = SRC_ABB / "analysis" / "key_provider.py"
    kp_path.write_text(KEY_PROVIDER_CODE, encoding="utf-8")
    print(f"[2/7] Wrote {kp_path.relative_to(ROOT)}")

    tg_path = SRC_ABB / "storage" / "tamper_guard.py"
    tg_path.write_text(TAMPER_GUARD_CODE, encoding="utf-8")
    print(f"[3/7] Wrote {tg_path.relative_to(ROOT)}")

    sd_path = SRC_ABB / "analysis" / "secret_detector.py"
    sd_path.write_text(SECRET_DETECTOR_CODE, encoding="utf-8")
    print(f"[4/7] Upgraded {sd_path.relative_to(ROOT)} (Base64/Hex/URL/Split-token scanner)")


def patch_redactor_and_hooks() -> None:
    redactor_path = SRC_ABB / "analysis" / "redactor.py"
    if redactor_path.exists():
        r_text = redactor_path.read_text(encoding="utf-8")
        if "reassemble_split_tokens" not in r_text:
            r_text = (
                "from agentblackbox.analysis.secret_detector import (\n"
                "    PATTERNS,\n"
                "    SecretDetector,\n"
                "    reassemble_split_tokens,\n"
                ")\n"
                + r_text
            )
        if "def redact_secrets" not in r_text:
            r_text += '''

def redact_secrets(text: str) -> str:
    """Convenience string redactor applying multi-pass detection, split token reassembly, and pattern masking."""
    if not text or not isinstance(text, str):
        return text
    reassembled = reassemble_split_tokens(text)
    working = reassembled if any(p.search(reassembled) for _, p in PATTERNS) else text
    detector = SecretDetector()
    matches = detector.scan_text(working)
    result = working
    for match in matches:
        if match.matched_text and match.matched_text in result:
            result = result.replace(match.matched_text, f"[REDACTED:{match.pattern_name}]")
    for name, pattern in PATTERNS:
        result = pattern.sub(f"[REDACTED:{name}]", result)
    return result
'''
        redactor_path.write_text(r_text, encoding="utf-8")
        print(f"[5/7] Patched {redactor_path.relative_to(ROOT)}")

    hooks_path = SRC_ABB / "watchers" / "agent_hooks.py"
    if hooks_path.exists():
        h_text = hooks_path.read_text(encoding="utf-8")
        if "UniversalIDECollector" not in h_text:
            hooks_path.write_text(h_text + IDE_COLLECTOR_APPEND_CODE, encoding="utf-8")
            print(f"[6/7] Appended UniversalIDECollector to {hooks_path.relative_to(ROOT)}")


def write_and_run_tests() -> None:
    test_path = ROOT / "tests" / "test_v030_upgrades.py"
    test_path.write_text(TEST_SUITE_CODE, encoding="utf-8")
    print(f"[7/7] Wrote {test_path.relative_to(ROOT)}")

    env = dict(os.environ)
    env["ABB_EPHEMERAL_TEST_KEY"] = "1"
    print("\nRunning pytest verification suite...")
    res = subprocess.run([sys.executable, "-m", "pytest", "-v"], env=env, check=False)
    if res.returncode != 0:
        sys.exit(res.returncode)


if __name__ == "__main__":
    ensure_repo_root()
    update_pyproject()
    write_new_modules()
    patch_redactor_and_hooks()
    write_and_run_tests()
