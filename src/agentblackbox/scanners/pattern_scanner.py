"""Fast pattern- and token-based static scanner for security and configuration defects."""

import re
from typing import List, Optional

from agentblackbox.analysis.secret_detector import detect_secrets
from agentblackbox.models.context import FileContext
from agentblackbox.models.finding import Finding
from agentblackbox.scanners.base import BaseScanner
from agentblackbox.scanners.rules import BUILTIN_RULES

_CHMOD_777_RE = re.compile(r"\b(?:chmod\s+777|0o?777)\b", re.IGNORECASE)
_MKTEMP_RE = re.compile(r"\btempfile\.mktemp\b")
_WEAK_CRYPTO_RE = re.compile(r"\b(?:hashlib\.md5|hashlib\.sha1)\b")


class PatternScanner(BaseScanner):
    """Token and regex-driven static analyzer for security and secrets."""

    @property
    def name(self) -> str:
        return "pattern_scanner"

    def scan_file(
        self,
        file_path: str,
        content: str,
        file_ctx: Optional[FileContext] = None,
    ) -> List[Finding]:
        if not content.strip():
            return []

        findings: List[Finding] = []
        lines = content.splitlines()

        # 1. Secret & Key Scanning using the existing hardened secret detector
        # Ignore test files and migration scripts from reporting fake secrets
        norm_file = file_path.replace("\\", "/")
        is_test_file = any(part in norm_file for part in ("tests/", "test_", "_test.py", "apply_agentblackbox"))
        if not is_test_file:
            secret_matches = detect_secrets(content, source=file_path)
            sec_rule = BUILTIN_RULES["SEC-004"]
            for sm in secret_matches:
                # Find line number from character offset
                lineno = 1
                if sm.offset is not None:
                    lineno = content[: sm.offset].count("\n") + 1

                findings.append(
                    Finding(
                        title=f"{sec_rule.title} ({sm.secret_type})",
                        severity=sec_rule.severity,
                        file_path=file_path,
                        line_start=lineno,
                        line_end=lineno,
                        category=sec_rule.category.value,
                        message=f"Hardcoded secret candidate detected: {sm.secret_type}.",
                        why_it_matters=sec_rule.why_it_matters,
                        suggested_fix=sec_rule.suggested_fix,
                        rule_id=sec_rule.rule_id,
                        cwe_id=sec_rule.cwe_id,
                        confidence=sm.confidence,
                    )
                )

        # 2. Insecure Permissions (chmod 777) & 3. Insecure mktemp
        if not is_test_file:
            for idx, line in enumerate(lines, 1):
                code_line = line.split("#", 1)[0].strip()
                if not code_line:
                    continue

                if any(k in line for k in ("re.compile", "_RE", "title=", "message=", "description=", "rule_id", "BUILTIN_RULES", "_DANGEROUS_COMMANDS")):
                    continue

                if _CHMOD_777_RE.search(code_line):
                    findings.append(
                        Finding(
                            title="Insecure File Permissions (chmod 777)",
                            severity=BUILTIN_RULES["SEC-002"].severity,
                            file_path=file_path,
                            line_start=idx,
                            line_end=idx,
                            category="security",
                            message="File created or modified with world-writable permissions (777).",
                            why_it_matters="Allows any local user or malicious process to read and overwrite sensitive files.",
                            suggested_fix="Restrict file permissions to owner read/write (e.g. 0o600 or 0o700).",
                            rule_id="SEC-005",
                            cwe_id="CWE-732",
                        )
                    )

                if _MKTEMP_RE.search(code_line):
                    findings.append(
                        Finding(
                            title="Insecure Temporary File Creation",
                            severity=BUILTIN_RULES["SEC-002"].severity,
                            file_path=file_path,
                            line_start=idx,
                            line_end=idx,
                            category="security",
                            message="`tempfile.mktemp()` is deprecated and vulnerable to symlink race conditions.",
                            why_it_matters="An attacker can create a symlink at the chosen path before file creation, leading to file overwrite.",
                            suggested_fix="Use `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()` instead.",
                            rule_id="SEC-006",
                            cwe_id="CWE-377",
                        )
                    )

        return findings
