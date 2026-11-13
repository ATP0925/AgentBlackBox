"""Performance, quadratic loop, and async efficiency analyzer."""

import ast
from typing import List, Optional

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding, Severity
from agentblackbox.scanners.ast_scanner import ASTScanner


class _PerformanceVisitor(ast.NodeVisitor):
    """Detects quadratic loops and inefficient string concatenations."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: List[Finding] = []
        self._loop_depth = 0

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Check for string += string inside loops which incurs O(N^2) memory reallocation."""
        if self._loop_depth > 0 and isinstance(node.op, ast.Add):
            # Check if target is string variable or identifier
            if isinstance(node.target, ast.Name):
                self.findings.append(
                    Finding(
                        title="Quadratic String Concatenation in Loop",
                        severity=Severity.LOW,
                        file_path=self.file_path,
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                        category="performance",
                        message=f"Repeated string concatenation `+=` on `{node.target.id}` inside loop.",
                        why_it_matters="Strings are immutable in Python; repeated concatenation in a loop reallocates memory quadratically O(N^2).",
                        suggested_fix="Append chunks to a list and combine with `''.join(chunks)` after the loop.",
                        rule_id="PERF-002",
                    )
                )
        self.generic_visit(node)


class PerformanceAnalyzer(BaseAnalyzer):
    """Detects anti-patterns that degrade CPU, memory, and async throughput."""

    def __init__(self) -> None:
        self._ast_scanner = ASTScanner()

    @property
    def name(self) -> str:
        return "performance_analyzer"

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

            # Run AST scanner performance rules (e.g. blocking sleep in async)
            for f in self._ast_scanner.scan_file(file_path, ctx.raw_source, ctx):
                if f.category == "performance":
                    if target_diff:
                        fdiff = target_diff.get_file(file_path)
                        if fdiff and not fdiff.touches_line(f.line_start):
                            continue
                    findings.append(f)

            # Run AST loop checks
            try:
                tree = ast.parse(ctx.raw_source, filename=file_path)
                visitor = _PerformanceVisitor(file_path=file_path)
                visitor.visit(tree)
                for f in visitor.findings:
                    if target_diff:
                        fdiff = target_diff.get_file(file_path)
                        if fdiff and not fdiff.touches_line(f.line_start):
                            continue
                    findings.append(f)
            except (SyntaxError, ValueError):
                continue

        return findings

