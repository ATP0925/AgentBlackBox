"""Safe static Abstract Syntax Tree (AST) analyzer for Python source files."""

import ast
from typing import Dict, List, Optional, Set

from agentblackbox.models.context import FileContext, Symbol, SymbolType


class _ComplexityVisitor(ast.NodeVisitor):
    """Calculates McCabe cyclomatic complexity for an AST subtree."""

    def __init__(self) -> None:
        self.complexity = 1

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Each 'and' / 'or' condition adds to branching complexity
        self.complexity += max(0, len(node.values) - 1)
        self.generic_visit(node)


class _CallVisitor(ast.NodeVisitor):
    """Collects all function/method names invoked within an AST subtree."""

    def __init__(self) -> None:
        self.calls: Set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            self.calls.add(func.id)
        elif isinstance(func, ast.Attribute):
            self.calls.add(func.attr)
        self.generic_visit(node)


def _compute_complexity(node: ast.AST) -> int:
    """Compute cyclomatic complexity for an AST node."""
    visitor = _ComplexityVisitor()
    visitor.visit(node)
    return visitor.complexity


def _extract_calls(node: ast.AST) -> List[str]:
    """Extract list of called function names inside an AST node."""
    visitor = _CallVisitor()
    visitor.visit(node)
    return sorted(visitor.calls)


def _format_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Format parameter names and default hints into a readable signature string."""
    params: List[str] = []
    args = node.args

    for arg in args.posonlyargs:
        ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
        params.append(f"{arg.arg}{ann}")
    if args.posonlyargs:
        params.append("/")

    num_defaults = len(args.defaults)
    num_args = len(args.args)
    default_offset = num_args - num_defaults

    for idx, arg in enumerate(args.args):
        ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
        default_idx = idx - default_offset
        if default_idx >= 0 and default_idx < num_defaults:
            default_val = ast.unparse(args.defaults[default_idx])
            params.append(f"{arg.arg}{ann}={default_val}")
        else:
            params.append(f"{arg.arg}{ann}")

    if args.vararg:
        ann = f": {ast.unparse(args.vararg.annotation)}" if args.vararg.annotation else ""
        params.append(f"*{args.vararg.arg}{ann}")

    for idx, kw in enumerate(args.kwonlyargs):
        ann = f": {ast.unparse(kw.annotation)}" if kw.annotation else ""
        if idx < len(args.kw_defaults) and args.kw_defaults[idx] is not None:
            default_val = ast.unparse(args.kw_defaults[idx])
            params.append(f"{kw.arg}{ann}={default_val}")
        else:
            params.append(f"{kw.arg}{ann}")

    if args.kwarg:
        ann = f": {ast.unparse(args.kwarg.annotation)}" if args.kwarg.annotation else ""
        params.append(f"**{args.kwarg.arg}{ann}")

    ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    return f"{node.name}({', '.join(params)}){ret}"


def parse_python_source(code: str, file_path: str = "") -> FileContext:
    """Safely parse Python source code into a structured FileContext.

    Does NOT execute untrusted code. Catches syntax errors gracefully.

    Args:
        code: Python source code string.
        file_path: Relative or absolute file path for reference.

    Returns:
        Populated FileContext instance.
    """
    lines = code.splitlines()
    loc = len([ln for ln in lines if ln.strip() and not ln.strip().startswith("#")])

    if not code or not code.strip():
        return FileContext(file_path=file_path, lines_of_code=0, raw_source=code)

    try:
        tree = ast.parse(code, filename=file_path)
    except (SyntaxError, ValueError):
        # Gracefully handle non-Python, syntax errors, or null bytes
        return FileContext(file_path=file_path, lines_of_code=loc, raw_source=code)

    symbols: List[Symbol] = []
    imports: List[str] = []
    imported_from: Dict[str, List[str]] = {}
    all_calls: Set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names = [alias.name for alias in node.names]
            imports.append(mod)
            imported_from.setdefault(mod, []).extend(names)

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stype = (
                SymbolType.ASYNC_FUNCTION
                if isinstance(node, ast.AsyncFunctionDef)
                else SymbolType.FUNCTION
            )
            sig = _format_signature(node)
            doc = ast.get_docstring(node)
            calls = _extract_calls(node)
            all_calls.update(calls)
            comp = _compute_complexity(node)
            params = [a.arg for a in node.args.args]
            ret_type = ast.unparse(node.returns) if node.returns else None

            symbols.append(
                Symbol(
                    name=node.name,
                    symbol_type=stype,
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    signature=sig,
                    docstring=doc,
                    parameters=params,
                    return_type=ret_type,
                    calls=calls,
                    cyclomatic_complexity=comp,
                )
            )

        elif isinstance(node, ast.ClassDef):
            doc = ast.get_docstring(node)
            cls_calls = _extract_calls(node)
            all_calls.update(cls_calls)
            comp = _compute_complexity(node)

            symbols.append(
                Symbol(
                    name=node.name,
                    symbol_type=SymbolType.CLASS,
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    signature=f"class {node.name}",
                    docstring=doc,
                    calls=cls_calls,
                    cyclomatic_complexity=comp,
                )
            )

            # Extract class methods
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mtype = (
                        SymbolType.ASYNC_METHOD
                        if isinstance(item, ast.AsyncFunctionDef)
                        else SymbolType.METHOD
                    )
                    msig = _format_signature(item)
                    mdoc = ast.get_docstring(item)
                    mcalls = _extract_calls(item)
                    all_calls.update(mcalls)
                    mcomp = _compute_complexity(item)
                    mparams = [a.arg for a in item.args.args]
                    mret = ast.unparse(item.returns) if item.returns else None

                    symbols.append(
                        Symbol(
                            name=item.name,
                            symbol_type=mtype,
                            file_path=file_path,
                            line_start=item.lineno,
                            line_end=item.end_lineno or item.lineno,
                            signature=msig,
                            docstring=mdoc,
                            parameters=mparams,
                            return_type=mret,
                            calls=mcalls,
                            cyclomatic_complexity=mcomp,
                            parent_name=node.name,
                        )
                    )

    file_complexity = sum(s.cyclomatic_complexity for s in symbols)
    return FileContext(
        file_path=file_path,
        lines_of_code=loc,
        symbols=symbols,
        imports=sorted(set(imports)),
        imported_from=imported_from,
        called_functions=sorted(all_calls),
        cyclomatic_complexity=file_complexity,
        raw_source=code,
    )

