"""Unit tests for GitHub App authentication and token management."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import httpx

from agentblackbox.github_app.auth import GitHubAppAuth


@pytest.fixture(scope="module")
def rsa_private_key_pem() -> str:
    """Generate a test RSA private key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def test_create_app_jwt(rsa_private_key_pem: str) -> None:
    auth = GitHubAppAuth(
        app_id="123456",
        private_key=rsa_private_key_pem,
        webhook_secret="test-secret",
    )

    token = auth.create_app_jwt(expiration_seconds=300)
    assert isinstance(token, str)

    # Decode and verify payload
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["iss"] == "123456"
    assert "exp" in decoded
    assert "iat" in decoded


@pytest.mark.asyncio
async def test_get_installation_token_caching(rsa_private_key_pem: str) -> None:
    auth = GitHubAppAuth(
        app_id="123456",
        private_key=rsa_private_key_pem,
        webhook_secret="test-secret",
    )

    call_count = 0

    def mock_transport(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            201,
            json={
                "token": "ghs_test_access_token_123456",
                "expires_at": "2030-01-01T00:00:00Z",
            },
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))

    # First call: hits API
    token1 = await auth.get_installation_token(1001, client=mock_client)
    assert token1 == "ghs_test_access_token_123456"
    assert call_count == 1

    # Second call: returns cached token without hitting API
    token2 = await auth.get_installation_token(1001, client=mock_client)
    assert token2 == "ghs_test_access_token_123456"
    assert call_count == 1
