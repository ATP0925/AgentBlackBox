"""Logic bug, null safety, and dead code analyzer."""

import ast
from typing import List, Optional

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding, Severity
from agentblackbox.scanners.ast_scanner import ASTScanner


def _is_direct_chained_regex_group(node: ast.Call) -> bool:
    """Flag re.search(...).group() or re.match(...).group() chained directly without None check."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "group":
        return False
    receiver = node.func.value
    if not isinstance(receiver, ast.Call):
        return False
    if isinstance(receiver.func, ast.Attribute) and receiver.func.attr in ("search", "match", "fullmatch"):
        return True
    return False


class _BugVisitor(ast.NodeVisitor):
    """Detects logic errors, dead statements, and potential crash bugs."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: List[Finding] = []

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_unreachable_statements(node.body)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_unreachable_statements(node.body)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self._check_unreachable_statements(node.body)
        self._check_unreachable_statements(node.orelse)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._check_unreachable_statements(node.body)
        self._check_unreachable_statements(node.orelse)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._check_unreachable_statements(node.body)
        self._check_unreachable_statements(node.orelse)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._check_unreachable_statements(node.body)
        self._check_unreachable_statements(node.orelse)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._check_unreachable_statements(node.body)
        self._check_unreachable_statements(node.orelse)
        self._check_unreachable_statements(node.finalbody)
        for h in node.handlers:
            self._check_unreachable_statements(h.body)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self._check_unreachable_statements(node.body)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._check_unreachable_statements(node.body)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for direct unchecked regex group call (e.g. re.search(...).group(1))."""
        if _is_direct_chained_regex_group(node):
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
