"""Data models for static AST symbols, file contexts, and multi-file code graphs."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SymbolType(str, Enum):
    """Classification of code symbols extracted by AST."""

    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    ASYNC_FUNCTION = "async_function"
    ASYNC_METHOD = "async_method"
    IMPORT = "import"
    GLOBAL_VAR = "global_var"


@dataclass
class Symbol:
    """A semantic symbol identified in a source file."""

    name: str
    symbol_type: SymbolType
    file_path: str
    line_start: int
    line_end: int
    signature: str = ""
    docstring: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    calls: List[str] = field(default_factory=list)
    cyclomatic_complexity: int = 1
    parent_name: Optional[str] = None


@dataclass
class FileContext:
    """Semantic context summary for a single source file."""

    file_path: str
    lines_of_code: int
    symbols: List[Symbol] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    imported_from: Dict[str, List[str]] = field(default_factory=dict)
    called_functions: List[str] = field(default_factory=list)
    cyclomatic_complexity: int = 0
    raw_source: str = ""

    def get_symbol_at_line(self, lineno: int) -> Optional[Symbol]:
        """Find the innermost symbol enclosing the given line number."""
        best: Optional[Symbol] = None
        for sym in self.symbols:
            if sym.line_start <= lineno <= sym.line_end:
                if best is None or (sym.line_end - sym.line_start) < (best.line_end - best.line_start):
                    best = sym
        return best


@dataclass
class CodeContext:
    """Multi-file dependency context assembled for an analysis or review run."""

    target_files: List[str] = field(default_factory=list)
    files: Dict[str, FileContext] = field(default_factory=dict)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    dependents: Dict[str, List[str]] = field(default_factory=dict)
    relevance_scores: Dict[str, float] = field(default_factory=dict)
    symbol_index: Dict[str, Symbol] = field(default_factory=dict)

    def get_context_slice(self, file_path: str) -> Optional[FileContext]:
        """Retrieve FileContext for a specific file path."""
        return self.files.get(file_path)
