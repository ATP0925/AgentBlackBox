"""Context-Aware Compliance Tracking.

Binds AI agent actions (events, prompts, tool outputs, terminal executions, file diffs)
to verifiable compliance frameworks: SOC2-CC6.1, OWASP-LLM06, GDPR-PII, and MIT-LICENSE-GUARD.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from agentblackbox.analysis.secret_detector import SecretDetector
from agentblackbox.storage.models import Event, Severity

_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CORS_WILDCARD = re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|Access-Control-Allow-Origin['\"\s]*:[\"'\s]*\*")
_VERIFY_FALSE_RE = re.compile(r"\bverify\s*=\s*False\b")
_SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
_RESTRICTIVE_LICENSES = {"gpl", "agpl", "gpl-3.0", "agpl-3.0", "lgpl"}


@dataclass
class ComplianceFinding:
    """A single compliance finding mapped to an industry framework."""

    rule_id: str
    framework: str
    severity: str
    remediation_hint: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    agent_event_id: Optional[str] = None
    chain_hash_proof: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ComplianceTracker:
    """Audits agent actions and file edits against enterprise compliance controls."""

    def __init__(self, secret_detector: Optional[SecretDetector] = None) -> None:
        self.secret_detector = secret_detector or SecretDetector()

    def check_content(
        self,
        content: str,
        file_path: str = "",
        event_id: Optional[str] = None,
        chain_hash: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        """Audit raw source code or prompt text for compliance violations."""
        findings: List[ComplianceFinding] = []

        # 1. Secret / Credential detection (SOC2-CC6.1)
        secret_matches = self.secret_detector.scan_text(content)
        for sm in secret_matches:
            findings.append(
                ComplianceFinding(
                    rule_id="SOC2-CC6.1",
                    framework="SOC2",
                    severity=Severity.CRITICAL if sm.confidence > 0.8 else Severity.HIGH,
                    file_path=file_path or None,
                    line_number=sm.line_number,
                    agent_event_id=event_id,
                    chain_hash_proof=chain_hash,
                    description=f"Unredacted credential or secret detected: {sm.pattern_name}",
                    remediation_hint="Remove hardcoded secrets and inject via OS Keychain or secure environment variables.",
                )
            )

        # 2. PII Exposure (GDPR-PII)
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if _SSN_PATTERN.search(line):
                findings.append(
                    ComplianceFinding(
                        rule_id="GDPR-PII-01",
                        framework="GDPR",
                        severity=Severity.HIGH,
                        file_path=file_path or None,
                        line_number=idx,
                        agent_event_id=event_id,
                        chain_hash_proof=chain_hash,
                        description="Unredacted Social Security Number (SSN) detected in source code or agent context.",
                        remediation_hint="Anonymize or mask sensitive identifiers before passing into model context.",
                    )
                )

        # 3. Dependency & License Drift (MIT-LICENSE-GUARD)
        if any(file_path.endswith(f) for f in ("pyproject.toml", "requirements.txt", "package.json")):
            findings.extend(self._check_dependency_drift(content, file_path, event_id, chain_hash))

        # 4. AST-based or Regex-based Security Checks (OWASP-LLM06 / SOC2-CC6.1)
        if file_path.endswith(".py"):
            findings.extend(self._check_python_ast(content, file_path, event_id, chain_hash))
        else:
            findings.extend(self._check_generic_patterns(content, file_path, event_id, chain_hash))

        return findings

    def check_event(
        self,
        event: Event,
        chain_hash: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        """Audit a recorded event object and bind compliance findings to it."""
        proof = chain_hash or event.event_hash or None
        event_id = str(event.id) if event.id is not None else None
        text_to_scan = ""

        if isinstance(event.payload, dict):
            parts = []
            for k in ("command", "output", "content", "prompt", "tool_input", "diff"):
                if k in event.payload:
                    parts.append(str(event.payload[k]))
            text_to_scan = "\n".join(parts)
        elif isinstance(event.payload, str):
            text_to_scan = event.payload

        findings = self.check_content(
            content=text_to_scan,
            file_path=event.source_path or "",
            event_id=event_id,
            chain_hash=proof,
        )

        return findings

    def _check_python_ast(
        self,
        content: str,
        file_path: str,
        event_id: Optional[str],
        chain_hash: Optional[str],
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return self._check_generic_patterns(content, file_path, event_id, chain_hash)

        for node in ast.walk(tree):
            # verify=False & shell=True
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value == False:
                        findings.append(
                            ComplianceFinding(
                                rule_id="SEC-NO-VERIFY",
                                framework="OWASP-LLM06",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=node.lineno,
                                agent_event_id=event_id,
                                chain_hash_proof=chain_hash,
                                description="TLS certificate validation disabled (verify=False).",
                                remediation_hint="Enable SSL/TLS certificate verification or provide a valid CA bundle.",
                            )
                        )
                    elif kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value == True:
                        findings.append(
                            ComplianceFinding(
                                rule_id="SEC-SHELL-TRUE",
                                framework="OWASP-LLM06",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=node.lineno,
                                agent_event_id=event_id,
                                chain_hash_proof=chain_hash,
                                description="Command execution with shell=True invites command injection vulnerability.",
                                remediation_hint="Pass arguments as a list without shell=True to prevent shell escaping exploits.",
                            )
                        )

                # eval() or exec()
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("eval", "exec") and node.args:
                    first_arg = node.args[0]
                    if not isinstance(first_arg, ast.Constant):
                        findings.append(
                            ComplianceFinding(
                                rule_id="SEC-DYN-EXEC",
                                framework="OWASP-LLM06",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=node.lineno,
                                agent_event_id=event_id,
                                chain_hash_proof=chain_hash,
                                description=f"Dynamic code execution via {func_name}() on variable expression.",
                                remediation_hint=f"Avoid {func_name}() on dynamic expressions; use safe serialization or dispatch maps.",
                            )
                        )

                # SQL execute with f-string or string concatenation
                if func_name in ("execute", "executemany") and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.JoinedStr) or (isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Add)):
                        findings.append(
                            ComplianceFinding(
                                rule_id="SEC-SQL-INJECT",
                                framework="SOC2-CC6.1",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=node.lineno,
                                agent_event_id=event_id,
                                chain_hash_proof=chain_hash,
                                description="SQL query constructed using string concatenation or f-string interpolation.",
                                remediation_hint="Use parameterized SQL queries with bind variables (? or :param) to prevent SQL injection.",
                            )
                        )

            # Wildcard CORS in FastAPI/Starlette CORSMiddleware
            if isinstance(node, ast.keyword) and node.arg == "allow_origins":
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            findings.append(
                                ComplianceFinding(
                                    rule_id="SEC-CORS-WILDCARD",
                                    framework="SOC2-CC6.1",
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line_number=node.value.lineno,
                                    agent_event_id=event_id,
                                    chain_hash_proof=chain_hash,
                                    description="Wildcard CORS allow_origins=['*'] exposes APIs to unauthorized cross-origin requests.",
                                    remediation_hint="Specify explicit authorized domain origins instead of wildcard '*'.",
                                )
                            )

        return findings

    def _check_generic_patterns(
        self,
        content: str,
        file_path: str,
        event_id: Optional[str],
        chain_hash: Optional[str],
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if _VERIFY_FALSE_RE.search(line):
                findings.append(
                    ComplianceFinding(
                        rule_id="SEC-NO-VERIFY",
                        framework="OWASP-LLM06",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        agent_event_id=event_id,
                        chain_hash_proof=chain_hash,
                        description="TLS certificate validation disabled (verify=False).",
                        remediation_hint="Enable SSL/TLS certificate verification or provide a valid CA bundle.",
                    )
                )
            if _SHELL_TRUE_RE.search(line):
                findings.append(
                    ComplianceFinding(
                        rule_id="SEC-SHELL-TRUE",
                        framework="OWASP-LLM06",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=idx,
                        agent_event_id=event_id,
                        chain_hash_proof=chain_hash,
                        description="Command execution with shell=True invites command injection vulnerability.",
                        remediation_hint="Pass arguments as a list without shell=True to prevent shell escaping exploits.",
                    )
                )
            if _CORS_WILDCARD.search(line):
                findings.append(
                    ComplianceFinding(
                        rule_id="SEC-CORS-WILDCARD",
                        framework="SOC2-CC6.1",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=idx,
                        agent_event_id=event_id,
                        chain_hash_proof=chain_hash,
                        description="Wildcard CORS policy detected.",
                        remediation_hint="Specify explicit authorized origins.",
                    )
                )
        return findings

    def _check_dependency_drift(
        self,
        content: str,
        file_path: str,
        event_id: Optional[str],
        chain_hash: Optional[str],
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []
        lower_content = content.lower()
        for lic in _RESTRICTIVE_LICENSES:
            if f'license = "{lic}"' in lower_content or f"license: {lic}" in lower_content or f'"{lic}"' in lower_content:
                findings.append(
                    ComplianceFinding(
                        rule_id="MIT-LICENSE-GUARD",
                        framework="LICENSING",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=1,
                        agent_event_id=event_id,
                        chain_hash_proof=chain_hash,
                        description=f"Restrictive viral license ({lic.upper()}) detected in package manifest.",
                        remediation_hint="Verify corporate licensing compatibility before introducing copyleft licenses.",
                    )
                )
                break
        return findings
