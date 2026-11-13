"""Tests for secret redaction (redact-first-store-later)."""

from pathlib import Path
from agentblackbox.analysis.redactor import redact_bytes, redact_payload, redact_text


class TestRedactText:
    """Test text-level secret redaction."""

    def test_redacts_openai_and_aws_keys(self) -> None:
        raw = 'OPENAI="sk-abcdefghijklmnopqrstuvwxyz123456" AWS="AKIAIOSFODNN7EXAMPLE"'
        redacted, matches = redact_text(raw)
        assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED:openai_api_key]" in redacted
        assert "[REDACTED:aws_access_key]" in redacted
        assert len(matches) == 2

    def test_redacts_stripe_key(self) -> None:
        secret = "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz"
        redacted, matches = redact_text(f'key = "{secret}"')
        assert secret not in redacted
        assert "[REDACTED:stripe_live_key]" in redacted
        assert len(matches) == 1

    def test_preserves_placeholders(self) -> None:
        raw = 'API_KEY = "your-api-key-here" OTHER = "${MY_SECRET}"'
        redacted, matches = redact_text(raw)
        assert redacted == raw
        assert matches == []

    def test_redacts_high_entropy_assignment(self) -> None:
        secret_val = "xK9#mP2$vL8!qR4@zN7&wT5^"
        raw = f'service_token = "{secret_val}"'
        redacted, matches = redact_text(raw)
        assert secret_val not in redacted
        assert "[REDACTED:high_entropy_secret]" in redacted
        assert len(matches) >= 1


class TestRedactPayloadAndBytes:
    """Test nested payload and byte redaction."""

    def test_redact_nested_payload_does_not_mutate_input(self) -> None:
        gh_tok = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        original = {"cmd": f"export TOKEN={gh_tok}", "nested": [gh_tok, "safe"]}
        clean, matches = redact_payload(original)
        assert gh_tok in original["cmd"]
        assert gh_tok not in clean["cmd"]
        assert gh_tok not in clean["nested"][0]
        assert clean["nested"][1] == "safe"
        assert len(matches) == 2

    def test_redact_bytes_binary_untouched(self) -> None:
        binary = b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE\xff\xfe"
        out, matches = redact_bytes(binary)
        assert out == binary
        assert matches == []

    def test_redacts_sensitive_dict_keys_regardless_of_entropy(self) -> None:
        # Task C: author, max_tokens, token_count, credit must NOT be redacted
        # password, api_key, access_token, authorization MUST be redacted
        payload = {
            "author": "Pratik Atpadkar",
            "max_tokens": 4096,
            "token_count": 512,
            "credit": 100,
            "password": "simplepassword",
            "api_key": "custom_format_token_123",
            "access_token": "token_val_456",
            "authorization": "Bearer xyz_789",
        }
        clean, matches = redact_payload(payload)
        assert clean["author"] == "Pratik Atpadkar"
        assert clean["max_tokens"] == 4096
        assert clean["token_count"] == 512
        assert clean["credit"] == 100
        assert clean["password"] == "[REDACTED:password]"
        assert clean["api_key"] == "[REDACTED:api_key]"
        assert clean["access_token"] == "[REDACTED:access_token]"
        assert clean["authorization"] == "[REDACTED:authorization]"
        assert len(matches) == 4

    def test_no_substring_of_secret_in_any_secretmatch_field(self) -> None:
        # Task D: No substring of secret appears in any SecretMatch field
        secret = "9876543210zywvutsrqponmlkjihgfedcba"
        raw = f'my_token = "{secret}"'
        redacted, matches = redact_text(raw)
        assert len(matches) >= 1
        for m in matches:
            assert m.length == len(secret)
            assert len(m.fingerprint) == 8
            # Check 4-char and full substrings
            for start in range(len(secret) - 4):
                sub = secret[start:start+4]
                assert sub not in m.matched_text
                assert sub not in m.secret_type
                assert sub not in m.fingerprint
                assert sub not in m.source

    def test_redacts_hex_tokens_with_lower_entropy_threshold(self) -> None:
        # 32-char hex token has entropy ~3.5 (< 4.0), which failed old > 4.0 check
        hex_token = "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"
        raw = f'auth_token = "{hex_token}"'
        redacted, matches = redact_text(raw)
        assert hex_token not in redacted
        assert "[REDACTED:high_entropy_secret]" in redacted

    def test_matched_text_never_exposes_raw_short_secret(self) -> None:
        short_secret = "secret123"
        raw = f'password = "{short_secret}"'
        _, matches = redact_text(raw)
        for m in matches:
            assert m.matched_text != short_secret
            assert "[REDACTED" in m.matched_text

    def test_redact_bytes_handles_windows_utf16_powershell(self) -> None:
        utf16_text = 'API_TOKEN="AKIAIOSFODNN7EXAMPLE"'.encode("utf-16")
        sanitized_bytes, matches = redact_bytes(utf16_text)
        assert len(matches) == 1
        decoded = sanitized_bytes.decode("utf-16")
        assert "AKIAIOSFODNN7EXAMPLE" not in decoded
        assert "[REDACTED:aws_access_key]" in decoded

    def test_redacts_claude_reviewed_keys(self) -> None:
        """Verify db_password, github_token, client_secret, and camelCase variants are redacted."""
        payload = {
            "db_password": "mypassword1",
            "github_token": "ghp_mocktoken123",
            "client_secret": "secretval456",
            "dbPassword": "mypassword2",
            "githubToken": "ghp_mocktoken789",
            "clientSecret": "secretval012",
            "aws_credentials": "creds_val",
            "author": "Alice",
            "authorId": 101,
            "credit": 50,
            "token_count": 100,
            "max_tokens": 2048,
        }
        clean, matches = redact_payload(payload)
        assert clean["db_password"] == "[REDACTED:db_password]"
        assert clean["github_token"] == "[REDACTED:github_token]"
        assert clean["client_secret"] == "[REDACTED:client_secret]"
        assert clean["dbPassword"] == "[REDACTED:dbpassword]"
        assert clean["githubToken"] == "[REDACTED:githubtoken]"
        assert clean["clientSecret"] == "[REDACTED:clientsecret]"
        assert clean["aws_credentials"] == "[REDACTED:aws_credentials]"

        # Safe non-secret keys must NOT be redacted
        assert clean["author"] == "Alice"
        assert clean["authorId"] == 101
        assert clean["credit"] == 50
        assert clean["token_count"] == 100
        assert clean["max_tokens"] == 2048
        assert len(matches) == 7

    def test_claude_tokenized_edge_cases(self) -> None:
        """Verify run-together words, aws_secret_access_key, pwd, and suffix variants are all redacted."""
        payload = {
            "dbpassword": "pass1",
            "accesstoken": "token1",
            "authtoken": "token2",
            "refreshtoken": "token3",
            "aws_secret_access_key": "raw_secret_key_val",
            "password_hash": "hash_val_abc",
            "client_secret_value": "secret_xyz",
            "pwd": "simple_pwd_123",
            # Safe non-secrets
            "author": "Alice",
            "authors": ["Alice", "Bob"],
            "authority": "root",
            "credit": 100,
            "credits": 200,
            "token_count": 50,
            "token_usage": 1000,
            "max_tokens": 4096,
            "prompt_tokens": 256,
        }
        clean, matches = redact_payload(payload)
        assert clean["dbpassword"] == "[REDACTED:dbpassword]"
        assert clean["accesstoken"] == "[REDACTED:accesstoken]"
        assert clean["authtoken"] == "[REDACTED:authtoken]"
        assert clean["refreshtoken"] == "[REDACTED:refreshtoken]"
        assert clean["aws_secret_access_key"] == "[REDACTED:aws_secret_access_key]"
        assert clean["password_hash"] == "[REDACTED:password_hash]"
        assert clean["client_secret_value"] == "[REDACTED:client_secret_value]"
        assert clean["pwd"] == "[REDACTED:pwd]"

        assert clean["author"] == "Alice"
        assert clean["authors"] == ["Alice", "Bob"]
        assert clean["authority"] == "root"
        assert clean["credit"] == 100
        assert clean["credits"] == 200
        assert clean["token_count"] == 50
        assert clean["token_usage"] == 1000
        assert clean["max_tokens"] == 4096
        assert clean["prompt_tokens"] == 256
        assert len(matches) == 8

    def test_secret_fingerprint_uses_hmac_and_resists_rainbow_tables(self) -> None:
        from agentblackbox.analysis.secret_detector import _secret_fingerprint, _get_or_create_secret_salt
        import hashlib
        short_secret = "admin"
        unkeyed_sha256 = hashlib.sha256(short_secret.encode()).hexdigest()[:8]
        # Dynamic salt ensures HMAC fingerprint never matches unkeyed SHA256
        fp1 = _secret_fingerprint(short_secret)
        assert fp1 != unkeyed_sha256
        assert len(fp1) == 8
        # Explicit salt alters fingerprint
        fp2 = _secret_fingerprint(short_secret, salt="custom-salt-xyz")
        assert fp2 != fp1
        assert len(fp2) == 8
        # Salt generator returns non-empty random bytes without hardcoded constant
        salt_bytes = _get_or_create_secret_salt()
        assert len(salt_bytes) >= 16
        assert salt_bytes != b"agentblackbox-audit-salt-v1"

    def test_pwd_path_not_redacted_while_nonpath_pwd_is_redacted(self) -> None:
        """Terminal PWD environment variable paths must NOT be redacted."""
        payload = {
            "PWD": "/home/user/workspace/AgentBlackBox",
            "pwd": "C:\\Users\\alice\\AppData\\Local\\project",
            "working_pwd": "/var/log/app",
            "secret_pwd": "cleartextPassword99!",
            "pwd_secret": "plainPassword456!",
        }
        clean, matches = redact_payload(payload)
        # Working directories must remain untouched
        assert clean["PWD"] == "/home/user/workspace/AgentBlackBox"
        assert clean["pwd"] == "C:\\Users\\alice\\AppData\\Local\\project"
        assert clean["working_pwd"] == "/var/log/app"

        # Non-path credentials with pwd in name must be redacted
        assert clean["secret_pwd"] == "[REDACTED:secret_pwd]"
        assert clean["pwd_secret"] == "[REDACTED:pwd_secret]"

    def test_llm_token_keys_and_non_secret_terms_unredacted(self) -> None:
        """LLM usage statistics and non-secret terms must remain unredacted."""
        payload = {
            "input_tokens": 1500,
            "output_tokens": 350,
            "completion_tokens": 350,
            "total_tokens": 1850,
            "cache_read_input_tokens": 800,
            "cache_creation_input_tokens": 200,
            "tokenizer": "cl100k_base",
            "password_length": 16,
            "password_policy": "min_16_with_special",
            "secret_santa": "Charlie",
            # Real secrets alongside
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "db_password": "supersecretpassword1",
            "github_token": "ghp_123456789012345678901234567890123456",
        }
        clean, matches = redact_payload(payload)
        # LLM stats & safe terms unredacted
        assert clean["input_tokens"] == 1500
        assert clean["output_tokens"] == 350
        assert clean["completion_tokens"] == 350
        assert clean["total_tokens"] == 1850
        assert clean["cache_read_input_tokens"] == 800
        assert clean["cache_creation_input_tokens"] == 200
        assert clean["tokenizer"] == "cl100k_base"
        assert clean["password_length"] == 16
        assert clean["password_policy"] == "min_16_with_special"
        assert clean["secret_santa"] == "Charlie"

        # Actual secrets must be redacted
        assert clean["aws_secret_access_key"] == "[REDACTED:aws_secret_access_key]"
        assert clean["db_password"] == "[REDACTED:db_password]"
        assert clean["github_token"] == "[REDACTED:github_token]"

    def test_salt_file_isolation_in_tmp_path(self, tmp_path: Path, monkeypatch) -> None:
        """Salt file must be written to configured/isolated home, not developer real home."""
        import agentblackbox.analysis.secret_detector as sd
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        monkeypatch.setattr(sd, "_CACHED_SALT", None)
        monkeypatch.delenv("ABB_SECRET_SALT", raising=False)

        salt = sd._get_or_create_secret_salt()
        assert len(salt) == 64  # 32-byte token_hex is 64 hex chars
        salt_file = fake_home / ".agentblackbox" / ".secret_salt"
        assert salt_file.exists()
        assert salt_file.read_text(encoding="utf-8").strip() == salt.decode("utf-8")

    def test_no_hardcoded_default_salt_in_source(self) -> None:
        """Source tree must contain zero hardcoded salt fallback strings."""
        from pathlib import Path
        src_dir = Path(__file__).parent.parent.parent / "src" / "agentblackbox"
        assert src_dir.exists()
        for py_file in src_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            assert "agentblackbox-audit-salt" not in content, f"Hardcoded salt string found in {py_file}"

