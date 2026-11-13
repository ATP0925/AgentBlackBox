"""Prompt builder and response parser for AI-assisted code review."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from agentblackbox.models.finding import Finding, FindingCategory, Severity


SYSTEM_PROMPT = """You are AgentBlackBox Reviewer, an elite senior software engineer and security auditor.
Your job is to analyze code changes or source files for:
1. Logic bugs and edge case crashes (null pointer / None dereference, off-by-one, unhandled exceptions)
2. Security vulnerabilities (injection, insecure deserialization, privilege escalation, secret exposure)
3. Performance regressions (quadratic loops, excessive database/network roundtrips, unbuffered IO)
4. Structural architectural degradation and maintainability flaws

GUIDELINES:
- Focus on real, actionable defects. Avoid stylistic bikeshedding, trivial formatting, or subjective opinions.
- If the code is well-written and has no defects, return an empty findings list.
- Every finding must contain clear reasoning, why it matters in production, and an exact suggested fix.
- Output MUST be valid JSON adhering strictly to the schema below without any extra markdown wrapping or comments outside the JSON.

SCHEMA:
{
  "summary": "Executive summary of the review",
  "findings": [
    {
      "title": "Short descriptive title",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "file_path": "path/to/file.py",
      "line_start": 10,
      "line_end": 12,
      "category": "security" | "bug" | "quality" | "performance" | "duplication",
      "message": "Specific explanation of what is wrong",
      "why_it_matters": "Real-world consequence if left unfixed",
      "suggested_fix": "Code snippet or exact remediation steps",
      "rule_id": "AI-BUG-001",
      "cwe_id": "CWE-89" (optional)
    }
  ]
}
"""


def build_system_prompt() -> str:
    """Return the base system prompt for AI code review."""
    return SYSTEM_PROMPT.strip()


def build_diff_review_prompt(
    diff_text: str,
    context_summary: str = "",
    scanner_findings: Optional[List[Finding]] = None,
) -> str:
    """Build user prompt for analyzing a git diff with code context."""
    sections = [
        "Please review the following git diff for bugs, security risks, and regressions.",
    ]

    if context_summary:
        sections.append(f"### PROJECT & DEPENDENCY CONTEXT:\n{context_summary}")

    if scanner_findings:
        findings_summary = "\n".join(
            f"- [{f.severity.value}] {f.file_path}:{f.line_start}: {f.title} ({f.rule_id})"
            for f in scanner_findings
        )
        sections.append(f"### PRE-COMPUTED DETERMINISTIC SCANNER FINDINGS:\n{findings_summary}\n(Validate or extend these, do not blindly duplicate)")

    sections.append(f"### GIT DIFF TO REVIEW:\n```diff\n{diff_text}\n```")
    sections.append("Respond strictly with the specified JSON schema.")
    return "\n\n".join(sections)


def build_file_review_prompt(
    file_path: str,
    source_code: str,
    context_summary: str = "",
    scanner_findings: Optional[List[Finding]] = None,
) -> str:
    """Build user prompt for analyzing a single source file."""
    sections = [
        f"Please analyze the file '{file_path}' for bugs, security issues, performance, and code quality.",
    ]

    if context_summary:
        sections.append(f"### PROJECT & DEPENDENCY CONTEXT:\n{context_summary}")

    if scanner_findings:
        findings_summary = "\n".join(
            f"- [{f.severity.value}] {f.file_path}:{f.line_start}: {f.title} ({f.rule_id})"
            for f in scanner_findings
        )
        sections.append(f"### PRE-COMPUTED SCANNER FINDINGS:\n{findings_summary}")

    sections.append(f"### FILE CONTENT ({file_path}):\n```python\n{source_code}\n```")
    sections.append("Respond strictly with the specified JSON schema.")
    return "\n\n".join(sections)


def parse_ai_findings(
    response_text: str,
    default_file: Optional[str] = None,
) -> Tuple[str, List[Finding]]:
    """Parse raw LLM response text into summary and structured Finding instances."""
    if not response_text or not response_text.strip():
        return "No response from AI provider.", []

    # Strip code block fences if present
    cleaned = response_text.strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(1)
    else:
        # Try finding outermost braces
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            cleaned = cleaned[start : end + 1]

    try:
        data: Dict[str, Any] = json.loads(cleaned)
    except Exception:
        # Fallback: if not valid JSON, treat as raw summary
        return response_text.strip(), []

    summary = data.get("summary", "AI review completed.")
    raw_findings = data.get("findings", [])
    findings: List[Finding] = []

    for item in raw_findings:
        if not isinstance(item, dict):
            continue

        title = item.get("title", "Review Finding")
        severity_str = item.get("severity", "MEDIUM")
        file_path = item.get("file_path") or default_file or "unknown"
        line_start = item.get("line_start", 1)
        line_end = item.get("line_end", line_start)
        category = item.get("category", FindingCategory.BUG)
        message = item.get("message", "")
        why_it_matters = item.get("why_it_matters", "")
        suggested_fix = item.get("suggested_fix", "")
        rule_id = item.get("rule_id", "AI-001")
        cwe_id = item.get("cwe_id")

        try:
            severity = Severity.from_str(severity_str)
        except Exception:
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                title=title,
                severity=severity,
                file_path=file_path,
                line_start=int(line_start),
                line_end=int(line_end),
                category=category,
                message=message,
                why_it_matters=why_it_matters,
                suggested_fix=suggested_fix,
                rule_id=rule_id,
                cwe_id=cwe_id,
            )
        )

    return summary, findings
