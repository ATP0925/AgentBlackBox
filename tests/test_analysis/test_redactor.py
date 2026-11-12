"""Tests for secret redaction (redact-first-store-later)."""

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
        payload = {
            "password": "simplepassword",
            "api_key": "custom_format_token_123",
            "safe_key": "safe_value",
        }
        clean, matches = redact_payload(payload)
        assert clean["password"] == "[REDACTED:password]"
        assert clean["api_key"] == "[REDACTED:api_key]"
        assert clean["safe_key"] == "safe_value"
        assert len(matches) == 2

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
            assert "[REDACTED]" in m.matched_text

    def test_redact_bytes_handles_windows_utf16_powershell(self) -> None:
        utf16_text = 'API_TOKEN="AKIAIOSFODNN7EXAMPLE"'.encode("utf-16")
        sanitized_bytes, matches = redact_bytes(utf16_text)
        assert len(matches) == 1
        decoded = sanitized_bytes.decode("utf-16")
        assert "AKIAIOSFODNN7EXAMPLE" not in decoded
        assert "[REDACTED:aws_access_key]" in decoded

