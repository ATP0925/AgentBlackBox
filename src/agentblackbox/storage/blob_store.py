"""Content-addressed blob store for file content snapshots."""

import hashlib
import re
from pathlib import Path
from typing import List, Optional, Tuple

from agentblackbox.analysis.redactor import redact_bytes
from agentblackbox.analysis.secret_detector import SecretMatch

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class BlobStore:
    """Stores deduplicated, secret-redacted file blobs keyed by SHA-256 hash.

    Args:
        blobs_dir: Directory where blobs are stored (auto-created).
    """

    def __init__(self, blobs_dir: Path) -> None:
        self.blobs_dir = blobs_dir
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, data: bytes, redact: bool = True) -> Tuple[str, int, List[SecretMatch]]:
        """Store bytes in the blob store, optionally redacting secrets first.

        The returned SHA-256 hash always corresponds to the stored (sanitized) bytes.

        Args:
            data: Raw content bytes.
            redact: If True, redact secrets from UTF-8 text before saving.

        Returns:
            Tuple of ``(sha256_hex, stored_size_bytes, secret_matches)``.
        """
        matches: List[SecretMatch] = []
        stored_data = data
        if redact:
            stored_data, matches = redact_bytes(data, source="blob_snapshot")

        digest = hashlib.sha256(stored_data).hexdigest()
        target = self.blobs_dir / digest
        if not target.exists():
            tmp_target = self.blobs_dir / f".{digest}.tmp"
            tmp_target.write_bytes(stored_data)
            tmp_target.replace(target)
        return digest, len(stored_data), matches

    def exists(self, blob_hash: str) -> bool:
        """Check whether a valid SHA-256 blob exists on disk.

        Args:
            blob_hash: 64-character lowercase hex SHA-256 digest.

        Returns:
            True if the blob exists.
        """
        if not _SHA256_RE.match(blob_hash):
            return False
        return (self.blobs_dir / blob_hash).is_file()

    def get_bytes(self, blob_hash: str) -> Optional[bytes]:
        """Retrieve raw bytes for a blob hash.

        Args:
            blob_hash: 64-character lowercase hex SHA-256 digest.

        Returns:
            Bytes if found and valid hash, None otherwise.
        """
        if not _SHA256_RE.match(blob_hash):
            return None
        path = self.blobs_dir / blob_hash
        if not path.is_file():
            return None
        return path.read_bytes()

    def get_text(self, blob_hash: str) -> Optional[str]:
        """Retrieve UTF-8 text for a blob hash.

        Args:
            blob_hash: 64-character lowercase hex SHA-256 digest.

        Returns:
            Decoded UTF-8 text, or None if missing/non-UTF-8.
        """
        raw = self.get_bytes(blob_hash)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

