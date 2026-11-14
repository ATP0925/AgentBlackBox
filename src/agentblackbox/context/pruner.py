"""Intelligent context pruning and token-budgeted prompt synthesizer."""

from typing import List, Optional, Union

from agentblackbox.models.context import CodeContext, FileContext, Symbol
from agentblackbox.models.diff import GitDiff


def _estimate_tokens(text: str) -> int:
    """Rough token estimation (approx 4 chars per token for code)."""
    return max(1, len(text) // 4)


class ContextPruner:
    """Selects high-signal code slices and compresses dependencies within token budgets."""

    def __init__(
        self,
        default_token_budget: int = 8000,
        max_tokens: Optional[int] = None,
    ) -> None:
        self.default_token_budget = max_tokens if max_tokens is not None else default_token_budget
        self.max_tokens = self.default_token_budget

    def create_minimal_symbol_stub(self, symbol: Symbol) -> str:
        """Create a compact signature + docstring stub for a symbol to preserve tokens."""
        doc = f'    """{symbol.docstring}"""\n' if symbol.docstring else ""
        if symbol.symbol_type.value.endswith("function") or symbol.symbol_type.value.endswith("method"):
            prefix = "async def " if "async" in symbol.symbol_type.value else "def "
            return f"{prefix}{symbol.signature}:\n{doc}    ...\n"
        elif symbol.symbol_type.value == "class":
            return f"class {symbol.name}:\n{doc}    ...\n"
        return f"{symbol.name} = ...\n"

    def summarize_dependency_file(self, ctx: FileContext, max_tokens: int = 400) -> str:
        """Summarize a dependency file to its external interface signatures."""
        lines: List[str] = [f"# Dependency interface for {ctx.file_path}"]
        current_len = 0
        for sym in ctx.symbols:
            stub = self.create_minimal_symbol_stub(sym)
            if _estimate_tokens("\n".join(lines) + stub) > max_tokens:
                lines.append("    # ... other symbols truncated ...")
                break
            lines.append(stub)
            current_len += len(stub)
        return "\n".join(lines)

    def assemble_review_context(
        self,
        code_context: CodeContext,
        target_diff: Optional[Union[GitDiff, List[str]]] = None,
        max_tokens: Optional[int] = None,
        target_files: Optional[List[str]] = None,
    ) -> str:
        """Assemble an optimal, high-signal context string within the token budget.

        Prioritizes:
        1. Changed git diff hunks (highest fidelity)
        2. Full source of primary changed files
        3. Compact signature stubs of direct dependencies
        """
        budget = max_tokens or self.default_token_budget
        sections: List[str] = []

        # If 2nd parameter is a list of file paths rather than GitDiff, accept it cleanly
        if isinstance(target_diff, list):
            effective_targets = target_diff
            diff_obj = None
        else:
            diff_obj = target_diff
            effective_targets = target_files or code_context.target_files

        # 1. Target Diff Section
        if diff_obj and getattr(diff_obj, "raw_diff", "").strip():
            diff_text = f"=== PULL REQUEST / GIT DIFF ===\n{diff_obj.raw_diff.strip()}\n"
            sections.append(diff_text)
            budget -= _estimate_tokens(diff_text)

        # 2. Directly Changed Files (Full source or target slices)
        for target_path in effective_targets:
            file_ctx = code_context.files.get(target_path)
            if not file_ctx or not file_ctx.raw_source:
                continue

            file_header = f"\n=== SOURCE FILE: {target_path} (Full Implementation) ===\n"
            source_content = file_ctx.raw_source
            candidate = file_header + source_content

            if _estimate_tokens(candidate) < budget * 0.7:
                sections.append(candidate)
                budget -= _estimate_tokens(candidate)
            else:
                # File too large, prune strictly on complete line / symbol boundaries
                lines = source_content.splitlines()
                accumulated_lines: List[str] = []
                for line in lines:
                    if _estimate_tokens("\n".join(accumulated_lines + [line])) > budget * 0.6:
                        accumulated_lines.append("# ... remaining lines truncated on line boundary ...")
                        break
                    accumulated_lines.append(line)
                sliced = file_header + "\n".join(accumulated_lines) + "\n"
                sections.append(sliced)
                budget -= _estimate_tokens(sliced)

        # 3. Direct Dependency Summaries (Signatures only)
        for dep_path, file_ctx in code_context.files.items():
            if dep_path in effective_targets:
                continue
            if budget <= 150:
                break

            dep_stub = "\n" + self.summarize_dependency_file(file_ctx, max_tokens=min(300, budget))
            sections.append(dep_stub)
            budget -= _estimate_tokens(dep_stub)

        return "\n".join(sections)
