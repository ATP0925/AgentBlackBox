"""Code clone and structural duplication analyzer."""

import ast
import copy
import hashlib
from typing import Dict, List, Optional, Tuple

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding, Severity


class _NodeNormalizer(ast.NodeTransformer):
    """Normalizes AST variable names, constants, and function/arg names to compute structural hashes."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        node.name = "func"
        for arg in node.args.args:
            arg.arg = "param"
        for arg in getattr(node.args, "posonlyargs", []):
            arg.arg = "param"
        for arg in getattr(node.args, "kwonlyargs", []):
            arg.arg = "param"
        if node.args.vararg:
            node.args.vararg.arg = "vararg"
        if node.args.kwarg:
            node.args.kwarg.arg = "kwarg"
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        self.generic_visit(node)
        node.name = "func"
        for arg in node.args.args:
            arg.arg = "param"
        for arg in getattr(node.args, "posonlyargs", []):
            arg.arg = "param"
        for arg in getattr(node.args, "kwonlyargs", []):
            arg.arg = "param"
        if node.args.vararg:
            node.args.vararg.arg = "vararg"
        if node.args.kwarg:
            node.args.kwarg.arg = "kwarg"
        return node

    def visit_Name(self, node: ast.Name) -> ast.Name:
        # Normalize all identifiers to 'var' for structural equivalence
        return ast.Name(id="var", ctx=node.ctx)

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        # Normalize constants
        return ast.Constant(value=None)


def _compute_structural_hash(node: ast.AST) -> str:
    """Compute normalized structural hash of an AST node."""
    cloned = copy.deepcopy(node)
    normalizer = _NodeNormalizer()
    normalized = normalizer.visit(cloned)
    ast.fix_missing_locations(normalized)
    dumped = ast.dump(normalized, annotate_fields=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()[:16]


class DuplicationAnalyzer(BaseAnalyzer):
    """Detects duplicated logic blocks and copy-pasted implementations."""

    @property
    def name(self) -> str:
        return "duplication_analyzer"

    def analyze(
        self,
        code_context: CodeContext,
        target_diff: Optional[GitDiff] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        # Map: structural_hash -> list of (file_path, fn_name, line_start, line_end)
        hash_to_fns: Dict[str, List[Tuple[str, str, int, int]]] = {}

        for file_path, ctx in code_context.files.items():
            if not ctx.raw_source:
                continue

            try:
                tree = ast.parse(ctx.raw_source, filename=file_path)
            except (SyntaxError, ValueError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_len = (node.end_lineno or node.lineno) - node.lineno + 1
                    # Only check meaningful functions (> 5 lines)
                    if fn_len >= 5:
                        shash = _compute_structural_hash(node)
                        hash_to_fns.setdefault(shash, []).append(
                            (file_path, node.name, node.lineno, node.end_lineno or node.lineno)
                        )

        # Flag duplicated instances
        reported_pairs = set()
        for shash, occurrences in hash_to_fns.items():
            if len(occurrences) > 1:
                for idx, (fpath, fname, start, end) in enumerate(occurrences):
                    other_occurrences = [
                        f"{o_path}:{o_name} (L{o_start})"
                        for o_idx, (o_path, o_name, o_start, _) in enumerate(occurrences)
                        if o_idx != idx
                    ]
                    pair_key = tuple(sorted([f"{fpath}:{fname}", other_occurrences[0]]))
                    if pair_key in reported_pairs:
                        continue
                    reported_pairs.add(pair_key)

                    findings.append(
                        Finding(
                            title=f"Duplicated Logic Clone: {fname}",
                            severity=Severity.MEDIUM,
                            file_path=fpath,
                            line_start=start,
                            line_end=end,
                            category="duplication",
                            message=f"Function '{fname}' has identical structural logic to {', '.join(other_occurrences)}.",
                            why_it_matters="Duplicated code increases maintenance costs and leads to inconsistent bug fixes across copies.",
                            suggested_fix="Extract common logic into a shared helper function or utility module.",
                            rule_id="DUPL-001",
                        )
                    )

        return findings
