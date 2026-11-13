"""Unit tests for DependencyGraph cross-file resolution and impact radius."""

from pathlib import Path
from agentblackbox.context.dependency_graph import DependencyGraph


FILE_A = """
from src.utils import helper_func

def run_service():
    return helper_func()
"""

FILE_B = """
def helper_func():
    return 42
"""

FILE_C = """
from src.service import run_service

def main():
    return run_service()
"""


def test_dependency_graph_indexing_and_impact() -> None:
    graph = DependencyGraph()
    graph.index_source("src/service.py", FILE_A)
    graph.index_source("src/utils.py", FILE_B)
    graph.index_source("src/main.py", FILE_C)
    graph.rebuild_edges()

    # Verify dependency links
    assert "src/utils.py" in graph.dependencies["src/service.py"]
    assert "src/service.py" in graph.dependencies["src/main.py"]

    # Verify reverse dependents
    assert "src/service.py" in graph.dependents["src/utils.py"]
    assert "src/main.py" in graph.dependents["src/service.py"]

    # Impact radius: If utils.py changes, service.py and main.py should be impacted
    impact = graph.get_impact_radius(["src/utils.py"], max_depth=2)
    assert "src/utils.py" in impact
    assert "src/service.py" in impact
    assert "src/main.py" in impact

    # Build code context
    code_ctx = graph.build_code_context(["src/utils.py"])
    assert "src/utils.py" in code_ctx.target_files
    assert "src/service.py" in code_ctx.files
