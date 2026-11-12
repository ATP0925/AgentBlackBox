"""Tests for secret detection."""

import pytest
from agentblackbox.analysis.secret_detector import detect_secrets, _shannon_entropy


class TestSecretDetection:
    """Test pattern-based secret detection."""

    def test_detect_aws_key(self) -> None:
        text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "aws_access_key" for m in matches)

    def test_detect_github_token(self) -> None:
        text = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "github_token" for m in matches)

    def test_detect_openai_key(self) -> None:
        text = 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "openai_api_key" for m in matches)

    def test_detect_stripe_key(self) -> None:
        prefix = "sk_" + "live_"
        text = f'stripe.api_key = "{prefix}abcdefghijklmnopqrstuvwxyz"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "stripe_live_key" for m in matches)

    def test_detect_private_key(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "private_key" for m in matches)

    def test_no_false_positive_placeholder(self) -> None:
        text = 'API_KEY = "your-api-key-here"'
        matches = detect_secrets(text)
        # Should not flag "your-api-key-here" as a real secret
        secret_matches = [m for m in matches if m.confidence > 0.8]
        # Placeholder should not be high confidence
        assert all(
            "your" not in m.matched_text.lower() for m in secret_matches
        )

    def test_detect_database_url(self) -> None:
        text = 'DATABASE_URL = "postgres://user:pass123@db.example.com/mydb"'
        matches = detect_secrets(text)
        assert len(matches) >= 1
        assert any(m.secret_type == "database_url" for m in matches)


class TestEntropy:
    """Test Shannon entropy calculation."""

    def test_low_entropy(self) -> None:
        assert _shannon_entropy("aaaaaa") < 1.0

    def test_high_entropy(self) -> None:
        # Random-looking string
        assert _shannon_entropy("aB3$kL9!mZ2@xQ7&") > 3.5

    def test_empty_string(self) -> None:
        assert _shannon_entropy("") == 0.0

