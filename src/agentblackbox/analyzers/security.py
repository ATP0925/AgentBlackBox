"""Static security vulnerability analyzer mapping findings to CWE categories."""

from typing import List, Optional

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding
from agentblackbox.scanners.ast_scanner import ASTScanner
from agentblackbox.scanners.pattern_scanner import PatternScanner


class SecurityAnalyzer(BaseAnalyzer):
    """Detects security vulnerabilities, injection flaws, and sensitive credential exposure."""

    def __init__(self) -> None:
        self._ast_scanner = ASTScanner()
        self._pattern_scanner = PatternScanner()

    @property
    def name(self) -> str:
        return "security_analyzer"

    def analyze(
        self,
        code_context: CodeContext,
        target_diff: Optional[GitDiff] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        files_to_check = code_context.target_files or list(code_context.files.keys())

        for file_path in files_to_check:
            ctx = code_context.files.get(file_path)
            if not ctx or not ctx.raw_source:
                continue

            # Run AST scanner security checks
            ast_findings = self._ast_scanner.scan_file(file_path, ctx.raw_source, ctx)
            for f in ast_findings:
                if f.category == "security":
                    if target_diff:
                        fdiff = target_diff.get_file(file_path)
                        if fdiff and not fdiff.touches_line(f.line_start):
                            continue
                    findings.append(f)

            # Run Pattern scanner checks
            pattern_findings = self._pattern_scanner.scan_file(file_path, ctx.raw_source, ctx)
            for f in pattern_findings:
                if f.category == "security":
                    if target_diff:
                        fdiff = target_diff.get_file(file_path)
                        if fdiff and not fdiff.touches_line(f.line_start):
                            continue
                    findings.append(f)

        return findings

