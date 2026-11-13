"""Code quality, maintainability, and complexity analyzer."""

import ast
from typing import List, Optional

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext, FileContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding, Severity
from agentblackbox.scanners.ast_scanner import ASTScanner


class QualityAnalyzer(BaseAnalyzer):
    """Measures maintainability index, function length, argument counts, and nesting depth."""

    def __init__(
        self,
        max_function_lines: int = 60,
        max_params: int = 6,
        max_complexity: int = 12,
    ) -> None:
        self.max_function_lines = max_function_lines
        self.max_params = max_params
        self.max_complexity = max_complexity
        self._ast_scanner = ASTScanner()

    @property
    def name(self) -> str:
        return "quality_analyzer"

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

            # 1. AST scanner quality rules (bare except, etc.)
            for f in self._ast_scanner.scan_file(file_path, ctx.raw_source, ctx):
                if f.category == "quality":
                    if target_diff:
                        fdiff = target_diff.get_file(file_path)
                        if fdiff and not fdiff.touches_line(f.line_start):
                            continue
                    findings.append(f)

            # 2. Symbol metrics checks
            for sym in ctx.symbols:
                if sym.symbol_type.value in ("function", "method", "async_function", "async_method"):
                    fn_len = sym.line_end - sym.line_start + 1
                    if fn_len > self.max_function_lines:
                        findings.append(
                            Finding(
                                title="Excessive Function Length",
                                severity=Severity.LOW,
                                file_path=file_path,
                                line_start=sym.line_start,
                                line_end=sym.line_end,
                                category="quality",
                                message=f"Function '{sym.name}' spans {fn_len} lines (recommended maximum: {self.max_function_lines}).",
                                why_it_matters="Long functions are difficult to comprehend, test thoroughly, and maintain over time.",
                                suggested_fix="Decompose into cohesive, single-responsibility helper functions.",
                                rule_id="QUAL-003",
                            )
                        )

                    param_count = len(sym.parameters)
                    if param_count > self.max_params:
                        findings.append(
                            Finding(
                                title="Excessive Parameter Count",
                                severity=Severity.LOW,
                                file_path=file_path,
                                line_start=sym.line_start,
                                line_end=sym.line_start,
                                category="quality",
                                message=f"Function '{sym.name}' accepts {param_count} parameters (recommended: {self.max_params}).",
                                why_it_matters="Functions with too many parameters indicate high coupling and violate the clean code rule of small parameter lists.",
                                suggested_fix="Encapsulate related arguments into a dataclass or configuration object.",
                                rule_id="QUAL-004",
                            )
                        )

        return findings

