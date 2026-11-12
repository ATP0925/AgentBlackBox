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
