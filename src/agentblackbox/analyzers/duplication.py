"""Code clone and structural duplication analyzer using O(N) AST structural hashing."""

import ast
import copy
import hashlib
from collections import defaultdict
from typing import List, Optional

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Category, Finding, Severity


class _ASTCanonicalizer(ast.NodeTransformer):
    """Strip variable/argument names and docstrings so structurally identical functions hash equally."""

    def visit_Name(self, node: ast.Name) -> ast.AST:
        return ast.copy_location(ast.Name(id="_var", ctx=node.ctx), node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        return ast.copy_location(ast.arg(arg="_arg", annotation=None), node)


def _structural_hash(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    body = list(func_node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(getattr(body[0], "value", None), ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if len(body) < 4:
        return None
    cloned = copy.deepcopy(func_node)
    cloned.name = "_fn"
    cloned.body = body
    canonical = _ASTCanonicalizer().visit(cloned)
    dumped = ast.dump(canonical, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


class DuplicationAnalyzer(BaseAnalyzer):
    name = "duplication"

    def analyze(
        self, code_context: CodeContext, target_diff: Optional[GitDiff] = None
    ) -> List[Finding]:
        buckets: dict[str, list[tuple[str, str, int, int]]] = defaultdict(list)
        for file_path, f_entry in code_context.files.items():
            source = f_entry if isinstance(f_entry, str) else getattr(f_entry, "raw_source", "")
            if not source:
                continue
            try:
                tree = ast.parse(source, filename=file_path)
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    digest = _structural_hash(node)
                    if digest:
                        end_line = getattr(node, "end_lineno", node.lineno + 4) or (node.lineno + 4)
                        buckets[digest].append((file_path, node.name, node.lineno, end_line))

        findings: List[Finding] = []
        for digest, locations in buckets.items():
            if len(locations) < 2:
                continue
            primary_file, primary_fn, _, _ = locations[0]
            for dup_file, dup_fn, start_line, end_line in locations[1:]:
                findings.append(
                    Finding(
                        rule_id="DUP-001",
                        title=f"Duplicate function logic in '{dup_fn}'",
                        severity=Severity.LOW,
                        category=Category.DUPLICATION,
                        file_path=dup_file,
                        line_start=start_line,
                        line_end=end_line,
                        message=(
                            f"Function '{dup_fn}' is structurally identical to "
                            f"'{primary_fn}' in {primary_file}."
                        ),
                        why_it_matters="Duplicated logic increases maintenance overhead and bug drift.",
                        suggested_fix=f"Extract shared logic from '{primary_fn}' and '{dup_fn}' into a reusable helper.",
                        confidence=0.9,
                    )
                )
        return findings
