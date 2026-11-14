"""OS Keychain integration, HKDF subkey derivation, and process env scrubbing."""
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
