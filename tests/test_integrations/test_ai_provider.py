"""Tests for AI provider interface, prompt generation, and mock provider."""

import json
import pytest

from agentblackbox.integrations.ai_provider import (
    OfflineMockAIProvider,
    get_ai_provider,
)
from agentblackbox.integrations.prompt_builder import (
    build_diff_review_prompt,
    build_file_review_prompt,
    build_system_prompt,
    parse_ai_findings,
)
from agentblackbox.models.finding import FindingCategory, Severity


def test_build_system_prompt() -> None:
    prompt = build_system_prompt()
    assert "AgentBlackBox" in prompt
    assert "SCHEMA" in prompt
    assert "CRITICAL" in prompt


def test_build_diff_prompt() -> None:
    diff_text = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new"
    prompt = build_diff_review_prompt(diff_text, context_summary="Module context: foo")
    assert "Module context: foo" in prompt
    assert "+new" in prompt


def test_build_file_prompt() -> None:
    prompt = build_file_review_prompt("src/main.py", "print('hello')", context_summary="ctx")
    assert "src/main.py" in prompt
    assert "print('hello')" in prompt


def test_parse_ai_findings_json_codeblock() -> None:
    raw_response = """
    Here is my analysis:
    ```json
    {
      "summary": "Found critical injection flaw.",
      "findings": [
        {
          "title": "SQL Injection",
          "severity": "CRITICAL",
          "file_path": "src/db.py",
          "line_start": 42,
          "line_end": 42,
          "category": "security",
          "message": "Direct user input interpolated into query.",
          "why_it_matters": "Database exfiltration risk.",
          "suggested_fix": "Use parameterized queries.",
          "rule_id": "AI-SEC-001",
          "cwe_id": "CWE-89"
        }
      ]
    }
    ```
    Please address these quickly.
    """
    summary, findings = parse_ai_findings(raw_response)
    assert summary == "Found critical injection flaw."
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "SQL Injection"
    assert f.severity == Severity.CRITICAL
    assert f.category == FindingCategory.SECURITY
    assert f.line_start == 42
    assert f.cwe_id == "CWE-89"


def test_offline_mock_provider() -> None:
    provider = get_ai_provider(provider_name="offline")
    assert isinstance(provider, OfflineMockAIProvider)

    # Clean code returns empty findings
    summary, findings = provider.generate_review(
        build_system_prompt(),
        "Reviewing simple clean code",
    )
    assert len(findings) == 0

    # Simulated trigger returns simulated finding
    summary, findings = provider.generate_review(
        build_system_prompt(),
        "Checking SIMULATED_CRITICAL_BUG in code",
        default_file="src/target.py",
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].file_path == "src/target.py"


def test_get_ai_provider_mappings(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentblackbox.integrations.ai_provider import AnthropicAIProvider, OpenAICompatibleProvider

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    p_claude = get_ai_provider(provider_name="claude")
    assert isinstance(p_claude, AnthropicAIProvider)
    assert p_claude.api_key == "test-anthropic-key"

    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    p_codex = get_ai_provider(provider_name="codex")
    assert isinstance(p_codex, OpenAICompatibleProvider)
    assert p_codex.model == "gpt-4o"

