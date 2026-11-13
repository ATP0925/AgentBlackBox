"""AI provider interface and implementations for automated code analysis."""

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from agentblackbox.integrations.prompt_builder import parse_ai_findings
from agentblackbox.models.finding import Finding


class AIProviderError(Exception):
    """Raised when an AI provider fails to generate a response."""
    pass


class BaseAIProvider(ABC):
    """Abstract base class for LLM code review providers."""

    @abstractmethod
    def generate_review(
        self,
        system_prompt: str,
        user_prompt: str,
        default_file: Optional[str] = None,
    ) -> Tuple[str, List[Finding]]:
        """Send prompt to LLM and return summary and parsed findings."""
        pass


class OfflineMockAIProvider(BaseAIProvider):
    """Deterministic mock provider for offline mode, testing, and CI without API keys."""

    def __init__(self, canned_response: Optional[str] = None):
        self.canned_response = canned_response

    def generate_review(
        self,
        system_prompt: str,
        user_prompt: str,
        default_file: Optional[str] = None,
    ) -> Tuple[str, List[Finding]]:
        if self.canned_response is not None:
            return parse_ai_findings(self.canned_response, default_file=default_file)

        # Check for simulated triggers in user_prompt for testing
        if "SIMULATED_CRITICAL_BUG" in user_prompt:
            fake_json = json.dumps({
                "summary": "Detected critical flaw in business logic.",
                "findings": [
                    {
                        "title": "Simulated Critical Flaw",
                        "severity": "CRITICAL",
                        "file_path": default_file or "src/app.py",
                        "line_start": 42,
                        "line_end": 45,
                        "category": "security",
                        "message": "Unvalidated user input causes arbitrary execution.",
                        "why_it_matters": "Remote attackers can compromise the host.",
                        "suggested_fix": "Validate input schema before execution.",
                        "rule_id": "AI-SEC-999",
                    }
                ],
            })
            return parse_ai_findings(fake_json, default_file=default_file)

        return (
            "Static and context analysis completed in offline mode (no external AI provider configured).",
            [],
        )


class GeminiAIProvider(BaseAIProvider):
    """Google Gemini AI provider via REST API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-2.5-flash",
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        self.timeout = timeout

        if not self.api_key:
            raise AIProviderError("GEMINI_API_KEY environment variable or argument is required.")

    def generate_review(
        self,
        system_prompt: str,
        user_prompt: str,
        default_file: Optional[str] = None,
    ) -> Tuple[str, List[Finding]]:
        import time

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.2,
            },
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        max_retries = 3
        last_error = None
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                    text = (
                        result.get("candidates", [{}])[0]
                        .get("content", {})
                        .get("parts", [{}])[0]
                        .get("text", "")
                    )
                    return parse_ai_findings(text, default_file=default_file)
            except urllib.error.HTTPError as e:
                last_error = e
                if e.code in (429, 500, 503) and attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise AIProviderError(f"Gemini API request failed: {e}") from e
            except urllib.error.URLError as e:
                raise AIProviderError(f"Gemini API request failed: {e}") from e

        raise AIProviderError(f"Gemini API request failed after {max_retries} attempts: {last_error}")


class OpenAICompatibleProvider(BaseAIProvider):
    """Provider for OpenAI, Groq, Ollama, DeepSeek, or any /v1/chat/completions API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.model = model
        self.timeout = timeout

        if not self.api_key and "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            raise AIProviderError("OPENAI_API_KEY is required for OpenAI-compatible provider.")

    def generate_review(
        self,
        system_prompt: str,
        user_prompt: str,
        default_file: Optional[str] = None,
    ) -> Tuple[str, List[Finding]]:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                content = (
                    result.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                return parse_ai_findings(content, default_file=default_file)
        except urllib.error.URLError as e:
            raise AIProviderError(f"OpenAI API request failed: {e}") from e


def get_ai_provider(
    provider_name: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
) -> BaseAIProvider:
    """Factory to obtain configured AI provider or fallback to offline mock."""
    name = (provider_name or os.environ.get("ABB_AI_PROVIDER", "")).lower()

    if name == "gemini" or (not name and os.environ.get("GEMINI_API_KEY")):
        try:
            return GeminiAIProvider(
                api_key=api_key,
                model=model or "gemini-2.5-flash",
            )
        except AIProviderError:
            return OfflineMockAIProvider()

    if name in ("openai", "groq", "ollama", "deepseek") or (not name and os.environ.get("OPENAI_API_KEY")):
        try:
            return OpenAICompatibleProvider(
                api_key=api_key,
                base_url=base_url,
                model=model or ("gpt-4o-mini" if name == "openai" else "llama3"),
            )
        except AIProviderError:
            return OfflineMockAIProvider()

    return OfflineMockAIProvider()

