"""Unit tests for ContextPruner and token budgeting."""

from agentblackbox.context.dependency_graph import DependencyGraph
from agentblackbox.context.pruner import ContextPruner, _estimate_tokens
from agentblackbox.models.diff import GitDiff, FileDiff, DiffHunk, DiffLine, DiffLineType


def test_context_pruner_token_budgeting() -> None:
    graph = DependencyGraph()
    graph.index_source("src/target.py", "def important_logic():\n    return 100\n")
    graph.index_source("src/dep.py", "def helper(val: int) -> int:\n    '''Helper doc.'''\n    return val * 2\n")
    graph.rebuild_edges()

    code_ctx = graph.build_code_context(["src/target.py"])

    diff = GitDiff(
        files=[
            FileDiff(
                old_path="src/target.py",
                new_path="src/target.py",
                hunks=[
                    DiffHunk(
                        old_start=1,
                        old_lines=1,
                        new_start=1,
                        new_lines=2,
                        header="important_logic",
                        lines=[
                            DiffLine(line_type=DiffLineType.CONTEXT, content="def important_logic():"),
                            DiffLine(line_type=DiffLineType.ADD, content="    # new line"),
                            DiffLine(line_type=DiffLineType.CONTEXT, content="    return 100"),
                        ],
                    )
                ],
            )
        ],
        raw_diff="@@ -1,1 +1,2 @@\n+    # new line",
    )

    pruner = ContextPruner(default_token_budget=1000)
    context_str = pruner.assemble_review_context(code_ctx, target_diff=diff, max_tokens=500)

    assert "PULL REQUEST / GIT DIFF" in context_str
    assert "src/target.py" in context_str
    assert _estimate_tokens(context_str) <= 500
