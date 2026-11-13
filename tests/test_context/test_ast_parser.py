"""Unit tests for safe AST source code parsing."""

from agentblackbox.context.ast_parser import parse_python_source
from agentblackbox.models.context import SymbolType


SAMPLE_SOURCE = '''"""Utility calculator."""

import os
from math import sqrt, ceil


class Calculator:
    """A sample calculator class."""

    def __init__(self, offset: int = 0) -> None:
        self.offset = offset

    def compute(self, x: int, y: int = 1) -> float:
        """Compute values based on conditions."""
        if x > 10 and y > 0:
            return sqrt(x) + self.offset
        elif x == 0:
            return 0.0
        return float(x * y)


async def fetch_result(url: str, retries: int = 3) -> str:
    """Async fetch helper."""
    for i in range(retries):
        if url:
            break
    return "ok"
'''


def test_parse_python_source_symbols() -> None:
    ctx = parse_python_source(SAMPLE_SOURCE, file_path="src/calc.py")

    assert ctx.file_path == "src/calc.py"
    assert "os" in ctx.imports
    assert "math" in ctx.imports
    assert ctx.imported_from["math"] == ["sqrt", "ceil"]

    # Symbols check
    symbols_by_name = {s.name: s for s in ctx.symbols}
    assert "Calculator" in symbols_by_name
    assert "compute" in symbols_by_name
    assert "fetch_result" in symbols_by_name

    calc = symbols_by_name["Calculator"]
    assert calc.symbol_type == SymbolType.CLASS
    assert calc.docstring == "A sample calculator class."

    compute = symbols_by_name["compute"]
    assert compute.symbol_type == SymbolType.METHOD
    assert compute.parent_name == "Calculator"
    assert compute.cyclomatic_complexity >= 3  # if with and + elif
    assert "x" in compute.parameters
    assert "y" in compute.parameters
    assert "sqrt" in compute.calls

    fetch = symbols_by_name["fetch_result"]
    assert fetch.symbol_type == SymbolType.ASYNC_FUNCTION
    assert fetch.return_type == "str"
    assert "range" in fetch.calls

    # Lookup symbol at line
    sym_at_line = ctx.get_symbol_at_line(15)
    assert sym_at_line is not None
    assert sym_at_line.name == "compute"


def test_parse_invalid_syntax_graceful() -> None:
    invalid_code = "def broken(:: : def 123"
    ctx = parse_python_source(invalid_code, file_path="broken.py")
    assert ctx.file_path == "broken.py"
    assert len(ctx.symbols) == 0


def test_parse_empty_source() -> None:
    ctx = parse_python_source("", file_path="empty.py")
    assert ctx.lines_of_code == 0
    assert len(ctx.symbols) == 0

