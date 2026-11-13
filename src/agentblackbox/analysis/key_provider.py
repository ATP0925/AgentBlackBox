# Module: OS Keychain integration, HKDF subkey derivation, and process env scrubbing.
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from typing import Final

import keyring
from keyring.errors import KeyringError, NoKeyringError

logger = logging.getLogger(__name__)

SERVICE_NAME: Final[str] = "agentblackbox"
KEY_NAME: Final[str] = "hmac_master_key"
ENV_HMAC_KEY: Final[str] = "ABB_HMAC_KEY"
ENV_TEST_KEY: Final[str] = "ABB_EPHEMERAL_TEST_KEY"


class KeyProviderError(RuntimeError):
    # Raised when the OS Keychain is unavailable and test mode is not enabled.
    pass


def hkdf_sha256(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    # Derive a domain-separated subkey using RFC 5869 HKDF-SHA256.
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
    # Manages master HMAC key lifecycle via OS Keychain and memory-only buffers.

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) < 32:
            raise ValueError("Master key must be at least 32 bytes.")
        self._master_key = bytearray(master_key)

    @classmethod
    def initialize(cls) -> "KeyProvider":
        # Load master key from OS Keychain, migrating and scrubbing env vars if present.
        legacy_env = os.environ.pop(ENV_HMAC_KEY, None)

        if os.environ.get(ENV_TEST_KEY) == "1":
            if legacy_env:
                if len(legacy_env) == 64:
                    try:
                        seed = bytes.fromhex(legacy_env)
                    except ValueError:
                        seed = legacy_env.encode("utf-8")
                else:
                    seed = legacy_env.encode("utf-8")
                if len(seed) < 32:
                    seed = hashlib.sha256(seed).digest()
            else:
                seed = secrets.token_bytes(32)
            return cls(seed)

        try:
            stored = keyring.get_password(SERVICE_NAME, KEY_NAME)
            if stored is not None:
                return cls(bytes.fromhex(stored.strip()))

            if legacy_env and len(legacy_env) == 64:
                try:
                    raw_key = bytes.fromhex(legacy_env)
                except ValueError:
                    raw_key = secrets.token_bytes(32)
            else:
                raw_key = secrets.token_bytes(32)

            keyring.set_password(SERVICE_NAME, KEY_NAME, raw_key.hex())
            logger.info("Provisioned 256-bit master key in OS Keychain (%s).", SERVICE_NAME)
            return cls(raw_key)
        except (NoKeyringError, KeyringError, ValueError) as exc:
            raise KeyProviderError(
                "OS Keychain backend unavailable. Configure system keyring (DPAPI/SecretService) "
                "or set ABB_EPHEMERAL_TEST_KEY=1 strictly in isolated CI/pytest environments."
            ) from exc

    def derive_subkey(self, purpose: str) -> bytes:
        # Return a 32-byte subkey for event_chain, tip_checkpoint, or session_meta_mac.
        return hkdf_sha256(bytes(self._master_key), purpose.encode("utf-8"), length=32)

    def sign_payload(self, purpose: str, payload: bytes) -> str:
        # Compute hex HMAC-SHA256 signature using the purpose-specific subkey.
        subkey = self.derive_subkey(purpose)
        return hmac.new(subkey, payload, hashlib.sha256).hexdigest()

    def verify_payload(self, purpose: str, payload: bytes, signature_hex: str) -> bool:
        # Constant-time verification of a hex HMAC-SHA256 signature.
        expected = self.sign_payload(purpose, payload)
        return hmac.compare_digest(expected, signature_hex)

    def zeroize(self) -> None:
        # Overwrite in-memory bytearray key buffer on daemon shutdown.
        for i in range(len(self._master_key)):
            self._master_key[i] = 0

