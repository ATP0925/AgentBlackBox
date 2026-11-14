"""Integration tests for GitHub App webhook endpoints and end-to-end event flow."""

import hashlib
import hmac
import json
import pytest
from fastapi.testclient import TestClient
import httpx

from agentblackbox.api.main import app
from agentblackbox.github_app.client import GitHubClient
from agentblackbox.github_app.events import GitHubEventHandler
from agentblackbox.github_app.webhook import auth_manager

client = TestClient(app)
TEST_SECRET = "test-webhook-secret-xyz"


@pytest.fixture(autouse=True)
def configure_test_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_manager, "webhook_secret", TEST_SECRET)
    monkeypatch.setattr(auth_manager, "app_id", "99999")
    monkeypatch.setattr(auth_manager, "private_key", "dummy-key")


def sign_payload(payload_bytes: bytes, secret: str = TEST_SECRET) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def test_healthz_and_readyz() -> None:
    resp = client.get("/github/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    resp = client.get("/github/readyz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


def test_webhook_unauthorized_missing_signature() -> None:
    resp = client.post(
        "/github/webhook",
        content=b'{"action": "opened"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_webhook_unauthorized_invalid_signature() -> None:
    resp = client.post(
        "/github/webhook",
        content=b'{"action": "opened"}',
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad",
        },
    )
    assert resp.status_code == 401


def test_webhook_ping_event() -> None:
    payload = b'{"zen": "Practicality beats purity."}'
    sig = sign_payload(payload)

    resp = client.post(
        "/github/webhook",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "delivery-ping-1",
        },
    )
    assert resp.status_code == 200
    assert resp.text == "pong"


def test_webhook_idempotency_duplicate_delivery() -> None:
    payload = json.dumps({"action": "opened", "number": 1}).encode("utf-8")
    sig = sign_payload(payload)
    delivery_id = "delivery-unique-test-99"

    # First request -> 202
    resp1 = client.post(
        "/github/webhook",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery_id,
        },
    )
    assert resp1.status_code == 202

    # Second request with SAME delivery ID -> 202 "Duplicate delivery"
    resp2 = client.post(
        "/github/webhook",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery_id,
        },
    )
    assert resp2.status_code == 202
    assert "Duplicate" in resp2.text


@pytest.mark.asyncio
async def test_end_to_end_pr_event_handler() -> None:
    recorded_calls: list[str] = []

    def mock_transport(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        method = request.method
        recorded_calls.append(f"{method} {url_str}")

        # Check run creation / update
        if "check-runs" in url_str:
            return httpx.Response(201, json={"id": 12345, "status": "completed"})

        # PR diff
        if "pulls/42" in url_str and request.headers.get("Accept") == "application/vnd.github.v3.diff":
            diff_text = (
                "diff --git a/src/app.py b/src/app.py\n"
                "--- a/src/app.py\n"
                "+++ b/src/app.py\n"
                "@@ -1,3 +1,4 @@\n"
                " import os\n"
                "+API_KEY = 'sk-proj-test1234567890123456'\n"
            )
            return httpx.Response(200, text=diff_text)

        # PR reviews
        if "pulls/42/reviews" in url_str:
            return httpx.Response(200, json={"id": 999})

        # Issue comments
        if "issues/42/comments" in url_str:
            if method == "GET":
                return httpx.Response(200, json=[])
            return httpx.Response(201, json={"id": 777})

        # Review comments
        if "pulls/42/comments" in url_str:
            return httpx.Response(200, json=[])

        # Contents (.agentblackbox.yaml)
        if "contents" in url_str:
            return httpx.Response(404, json={"message": "Not found"})

        return httpx.Response(200, json={})

    mock_client = GitHubClient(
        token="test-token",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )
    handler = GitHubEventHandler(client=mock_client)

    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "title": "Add API Key",
            "head": {"sha": "c0ffee1234567890"},
            "base": {"ref": "main"},
            "draft": False,
        },
        "repository": {
            "name": "demo-repo",
            "owner": {"login": "acme-corp"},
        },
        "installation": {"id": 888},
    }

    await handler.handle_pull_request_event(payload)

    # Verify key API steps were executed
    assert any("check-runs" in call for call in recorded_calls)
    assert any("pulls/42" in call for call in recorded_calls)
    assert any("issues/42/comments" in call for call in recorded_calls)
