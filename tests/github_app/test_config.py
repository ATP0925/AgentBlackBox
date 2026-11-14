"""Unit tests for repository configuration parsing (.agentblackbox.yaml)."""

import pytest
import httpx

from agentblackbox.github_app.client import GitHubClient
from agentblackbox.github_app.config import load_repo_config, parse_config_yaml


def test_parse_valid_config_yaml() -> None:
    yaml_text = """
version: "1.0"
reviews:
  enabled: true
  draft_prs: true
  fail_on: "critical"
  min_confidence: 0.8
  max_comments: 15
  language: "en"
paths:
  include:
    - "src/**"
  exclude:
    - "tests/fixtures/**"
scanners:
  security: true
  bugs: true
  drift: false
  perf: true
custom_instructions: "Focus heavily on SQL injection."
"""
    cfg = parse_config_yaml(yaml_text)

    assert cfg.reviews.enabled is True
    assert cfg.reviews.draft_prs is True
    assert cfg.reviews.fail_on == "critical"
    assert cfg.reviews.min_confidence == 0.8
    assert cfg.reviews.max_comments == 15
    assert cfg.paths.include == ["src/**"]
    assert cfg.paths.exclude == ["tests/fixtures/**"]
    assert cfg.scanners.security is True
    assert cfg.scanners.drift is False
    assert cfg.custom_instructions == "Focus heavily on SQL injection."
    assert len(cfg.warnings) == 0


def test_parse_invalid_yaml_handles_gracefully() -> None:
    bad_yaml = "reviews: [unclosed list"
    cfg = parse_config_yaml(bad_yaml)

    assert cfg.reviews.enabled is True  # fallback default
    assert len(cfg.warnings) >= 1
    assert "Failed to parse" in cfg.warnings[0]


def test_parse_unknown_keys_records_warnings() -> None:
    yaml_with_unknowns = """
reviews:
  enabled: true
  unknown_sub_key: 123
unknown_root_key: "foobar"
"""
    cfg = parse_config_yaml(yaml_with_unknowns)

    assert cfg.reviews.enabled is True
    assert any("unknown_root_key" in w for w in cfg.warnings)
    assert any("unknown_sub_key" in w for w in cfg.warnings)


@pytest.mark.asyncio
async def test_load_repo_config_from_base_branch() -> None:
    def mock_transport(request: httpx.Request) -> httpx.Response:
        if "contents/.agentblackbox.yaml" in str(request.url):
            import base64
            content_bytes = b"reviews:\n  fail_on: medium\n"
            b64_content = base64.b64encode(content_bytes).decode("utf-8")
            return httpx.Response(200, json={"content": b64_content})
        return httpx.Response(404, json={"message": "Not Found"})

    client = GitHubClient(http_client=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)))
    cfg = await load_repo_config(client, "owner", "repo", "main")

    assert cfg.reviews.fail_on == "medium"
