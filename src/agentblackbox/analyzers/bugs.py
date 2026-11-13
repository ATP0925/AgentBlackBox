"""Logic bug, null safety, and dead code analyzer."""

import ast
from typing import List, Optional

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding, Severity
from agentblackbox.scanners.ast_scanner import ASTScanner


class _BugVisitor(ast.NodeVisitor):
    """Detects logic errors, dead statements, and potential crash bugs."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_unreachable_statements(node.body)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_unreachable_statements(node.body)
        self.generic_visit(node)

    def _check_unreachable_statements(self, statements: List[ast.stmt]) -> None:
        """Flag statements positioned immediately after terminal statements (return, raise, break, continue)."""
        terminated = False
        terminal_lineno = 0

        for stmt in statements:
            if terminated:
                self.findings.append(
                    Finding(
                        title="Unreachable Code After Return/Raise",
                        severity=Severity.LOW,
                        file_path=self.file_path,
                        line_start=stmt.lineno,
                        line_end=stmt.end_lineno or stmt.lineno,
                        category="bug",
                        message=f"Statement is unreachable; follows return/raise at line {terminal_lineno}.",
                        why_it_matters="Dead code adds confusion, hides programmer intent, and indicates incomplete refactoring.",
                        suggested_fix="Remove or relocate the unreachable statement.",
                        rule_id="BUG-005",
                    )
                )
                break

            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True
                terminal_lineno = stmt.lineno

    def visit_Call(self, node: ast.Call) -> None:
        """Check for direct unchecked regex group call (e.g. re.search(...).group(1))."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "group":
            inner_call = node.func.value
            if isinstance(inner_call, ast.Call) and isinstance(inner_call.func, ast.Attribute):
                if inner_call.func.attr in ("search", "match"):
                    self.findings.append(
                        Finding(
                            title="Unchecked Regex Match Group Access",
                            severity=Severity.HIGH,
                            file_path=self.file_path,
                            line_start=node.lineno,
                            line_end=node.end_lineno or node.lineno,
                            category="bug",
                            message="Direct `.group()` call on regex search without validating match is not None.",
                            why_it_matters="Raises `AttributeError: 'NoneType' object has no attribute 'group'` if the pattern fails to match.",
                            suggested_fix="Assign match to variable and check `if match:` before calling `.group()`.",
                            rule_id="BUG-006",
                        )
                    )
        self.generic_visit(node)


class BugAnalyzer(BaseAnalyzer):
    """Identifies potential runtime exceptions, logic flaws, and edge cases."""

    def __init__(self) -> None:
        self._ast_scanner = ASTScanner()

    @property
    def name(self) -> str:
        return "bug_analyzer"

    def analyze(
        self,
        code_context: CodeContext,
        target_diff: Optional[GitDiff] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Target files or all files in context
        files_to_check = code_context.target_files or list(code_context.files.keys())

        for file_path in files_to_check:
            ctx = code_context.files.get(file_path)
            if not ctx or not ctx.raw_source:
                continue

            # 1. Deterministic AST scanner bugs
            scanner_findings = self._ast_scanner.scan_file(file_path, ctx.raw_source, ctx)
            for f in scanner_findings:
                if f.category == "bug":
                    # If target_diff is specified, only retain findings touching changed lines
                    if target_diff:
                        fdiff = target_diff.get_file(file_path)
                        if fdiff and not fdiff.touches_line(f.line_start):
                            continue
                    findings.append(f)

            # 2. Advanced logic checks
            try:
                tree = ast.parse(ctx.raw_source, filename=file_path)
                visitor = _BugVisitor(file_path=file_path)
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

