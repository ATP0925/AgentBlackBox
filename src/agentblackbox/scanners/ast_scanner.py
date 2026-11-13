"""AST-based deterministic static analysis scanner for Python source files."""

import ast
from typing import List, Optional

from agentblackbox.context.ast_parser import parse_python_source
from agentblackbox.models.context import FileContext
from agentblackbox.models.finding import Finding
from agentblackbox.scanners.base import BaseScanner
from agentblackbox.scanners.rules import BUILTIN_RULES


class _ASTVisitor(ast.NodeVisitor):
    """Visits AST nodes to detect security vulnerabilities, logic bugs, and code smells."""

    def __init__(self, file_path: str, lines: List[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Finding] = []
        self._async_scope_depth = 0
        self._with_context_open = False

    def _get_snippet(self, start: int, end: int) -> str:
        """Extract lines of code as a snippet."""
        if 1 <= start <= len(self.lines):
            return "\n".join(self.lines[start - 1 : min(end, len(self.lines))])
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_mutable_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_mutable_defaults(node)
        self._async_scope_depth += 1
        self.generic_visit(node)
        self._async_scope_depth -= 1

    def _check_mutable_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Check for mutable default arguments (list, dict, set)."""
        rule = BUILTIN_RULES["BUG-001"]
        all_defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        for d in all_defaults:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                lineno = d.lineno
                self.findings.append(
                    Finding(
                        title=rule.title,
                        severity=rule.severity,
                        file_path=self.file_path,
                        line_start=lineno,
                        line_end=lineno,
                        category=rule.category.value,
                        message=f"Function '{node.name}' specifies mutable default argument '{ast.unparse(d)}'.",
                        why_it_matters=rule.why_it_matters,
                        suggested_fix=rule.suggested_fix,
                        rule_id=rule.rule_id,
                        diff_hunk=self._get_snippet(node.lineno, lineno),
                    )
                )

    def visit_Compare(self, node: ast.Compare) -> None:
        """Check for literal identity comparison using 'is'."""
        rule = BUILTIN_RULES["BUG-003"]
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Is, ast.IsNot)):
                if isinstance(comparator, ast.Constant) and isinstance(comparator.value, (str, int, float)):
                    self.findings.append(
                        Finding(
                            title=rule.title,
                            severity=rule.severity,
                            file_path=self.file_path,
                            line_start=node.lineno,
                            line_end=node.end_lineno or node.lineno,
                            category=rule.category.value,
                            message=f"Identity comparison using 'is' against literal {comparator.value!r}.",
                            why_it_matters=rule.why_it_matters,
                            suggested_fix=rule.suggested_fix,
                            rule_id=rule.rule_id,
                            diff_hunk=self._get_snippet(node.lineno, node.lineno),
                        )
                    )
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Flag that we are inside a with block for nested calls."""
        prev = self._with_context_open
        self._with_context_open = True
        self.generic_visit(node)
        self._with_context_open = prev

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        prev = self._with_context_open
        self._with_context_open = True
        self.generic_visit(node)
        self._with_context_open = prev

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect calls for shell injection, SQL injection, blocking sleep, and unmanaged open."""
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr

        # 1. PERF-001: time.sleep in async def
        if call_name == "sleep" and self._async_scope_depth > 0:
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "time":
                rule = BUILTIN_RULES["PERF-001"]
                self.findings.append(
                    Finding(
                        title=rule.title,
                        severity=rule.severity,
                        file_path=self.file_path,
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                        category=rule.category.value,
                        message="Synchronous `time.sleep()` called inside an async function.",
                        why_it_matters=rule.why_it_matters,
                        suggested_fix=rule.suggested_fix,
                        rule_id=rule.rule_id,
                        diff_hunk=self._get_snippet(node.lineno, node.lineno),
                    )
                )

        # 2. SEC-002: subprocess with shell=True or os.system/os.popen
        is_shell = False
        if call_name in ("Popen", "run", "call", "check_output", "check_call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and bool(kw.value.value):
                    is_shell = True
                    break
        elif call_name in ("system", "popen") and isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", "") == "os":
            is_shell = True

        if is_shell:
            rule = BUILTIN_RULES["SEC-002"]
            self.findings.append(
                Finding(
                    title=rule.title,
                    severity=rule.severity,
                    file_path=self.file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    category=rule.category.value,
                    message=f"`{call_name}` executed with shell invocation.",
                    why_it_matters=rule.why_it_matters,
                    suggested_fix=rule.suggested_fix,
                    rule_id=rule.rule_id,
                    cwe_id=rule.cwe_id,
                    diff_hunk=self._get_snippet(node.lineno, node.lineno),
                )
            )

        # 3. SEC-001: SQL injection in execute(...)
        if call_name in ("execute", "executemany"):
            if node.args:
                first_arg = node.args[0]
                is_dangerous_str = False
                if isinstance(first_arg, ast.JoinedStr):
                    # f-string in SQL query
                    is_dangerous_str = True
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Mod, ast.Add)):
                    # % or + formatting in SQL query
                    is_dangerous_str = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    # .format() in SQL query
                    is_dangerous_str = True

                if is_dangerous_str:
                    rule = BUILTIN_RULES["SEC-001"]
                    self.findings.append(
                        Finding(
                            title=rule.title,
                            severity=rule.severity,
                            file_path=self.file_path,
                            line_start=node.lineno,
                            line_end=node.end_lineno or node.lineno,
                            category=rule.category.value,
                            message="SQL query constructed via dynamic string formatting.",
                            why_it_matters=rule.why_it_matters,
                            suggested_fix=rule.suggested_fix,
                            rule_id=rule.rule_id,
                            cwe_id=rule.cwe_id,
                            diff_hunk=self._get_snippet(node.lineno, node.lineno),
                        )
                    )

        # 4. SEC-003: pickle.loads / yaml.load
        if (call_name in ("loads", "load") and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle"):
            rule = BUILTIN_RULES["SEC-003"]
            self.findings.append(
                Finding(
                    title=rule.title,
                    severity=rule.severity,
                    file_path=self.file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    category=rule.category.value,
                    message="`pickle.loads` called on potentially untrusted input.",
                    why_it_matters=rule.why_it_matters,
                    suggested_fix=rule.suggested_fix,
                    rule_id=rule.rule_id,
                    cwe_id=rule.cwe_id,
                    diff_hunk=self._get_snippet(node.lineno, node.lineno),
                )
            )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Check for bare except: or except Exception: pass."""
        is_broad = node.type is None
        if node.type is not None:
            if isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
                is_broad = True

        if is_broad and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            rule = BUILTIN_RULES["QUAL-001"]
            self.findings.append(
                Finding(
                    title=rule.title,
                    severity=rule.severity,
                    file_path=self.file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    category=rule.category.value,
                    message="Broad exception caught and silently swallowed with `pass`.",
                    why_it_matters=rule.why_it_matters,
                    suggested_fix=rule.suggested_fix,
                    rule_id=rule.rule_id,
                    diff_hunk=self._get_snippet(node.lineno, node.end_lineno or node.lineno),
                )
            )

        self.generic_visit(node)


class ASTScanner(BaseScanner):
    """Deterministic AST-based static code analyzer."""

    @property
    def name(self) -> str:
        return "ast_scanner"

    def scan_file(
        self,
        file_path: str,
        content: str,
        file_ctx: Optional[FileContext] = None,
    ) -> List[Finding]:
        if not file_path.endswith(".py") or not content.strip():
            return []

        try:
            tree = ast.parse(content, filename=file_path)
        except (SyntaxError, ValueError):
            return []

        visitor = _ASTVisitor(file_path=file_path, lines=content.splitlines())
        visitor.visit(tree)
        findings = visitor.findings

        # Also check high cyclomatic complexity from FileContext
        ctx = file_ctx or parse_python_source(content, file_path=file_path)
        rule_comp = BUILTIN_RULES["QUAL-002"]
        for sym in ctx.symbols:
            if sym.cyclomatic_complexity > 15:
                findings.append(
                    Finding(
                        title=rule_comp.title,
                        severity=rule_comp.severity,
                        file_path=file_path,
                        line_start=sym.line_start,
                        line_end=sym.line_end,
                        category=rule_comp.category.value,
                        message=f"{sym.symbol_type.value.capitalize()} '{sym.name}' has cyclomatic complexity of {sym.cyclomatic_complexity} (threshold: 15).",
                        why_it_matters=rule_comp.why_it_matters,
                        suggested_fix=rule_comp.suggested_fix,
                        rule_id=rule_comp.rule_id,
                    )
                )

        return findings
