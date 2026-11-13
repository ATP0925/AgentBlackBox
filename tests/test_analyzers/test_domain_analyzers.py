"""Comprehensive tests for Bug, Security, Quality, Performance, and Duplication analyzers."""

from agentblackbox.analyzers.bugs import BugAnalyzer
from agentblackbox.analyzers.duplication import DuplicationAnalyzer
from agentblackbox.analyzers.performance import PerformanceAnalyzer
from agentblackbox.analyzers.quality import QualityAnalyzer
from agentblackbox.analyzers.security import SecurityAnalyzer
from agentblackbox.context.dependency_graph import DependencyGraph


CODE_WITH_BUGS = """
import re

def compute(x):
    return x * 2
    y = x + 1  # Unreachable

def find_token(text):
    # Unchecked regex group
    return re.search(r"token:(\\w+)", text).group(1)
"""

CODE_WITH_QUALITY_ISSUES = """
def huge_function(a, b, c, d, e, f, g, h):
    # Excessive parameters
    x = 1
    return a + b + c + d + e + f + g + h
"""

CODE_WITH_PERF_ISSUES = """
def concat_loop(items):
    out = ""
    for it in items:
        out += str(it)
    return out
"""

CODE_WITH_DUPLICATION_1 = """
def calculate_tax(amount):
    sub = amount * 0.1
    if sub > 50:
        sub = 50.0
    total = amount + sub
    return total
"""

CODE_WITH_DUPLICATION_2 = """
def compute_fee(price):
    sub = price * 0.1
    if sub > 50:
        sub = 50.0
    total = price + sub
    return total
"""


def test_bug_analyzer() -> None:
    graph = DependencyGraph()
    graph.index_source("src/bugs.py", CODE_WITH_BUGS)
    code_ctx = graph.build_code_context(["src/bugs.py"])

    analyzer = BugAnalyzer()
    findings = analyzer.analyze(code_ctx)

    rule_ids = {f.rule_id for f in findings}
    assert "BUG-005" in rule_ids  # Unreachable code
    assert "BUG-006" in rule_ids  # Unchecked regex group


def test_guarded_regex_group_not_flagged() -> None:
    code = """
import re
def get_item(text):
    m = re.search(r"\\d+", text)
    if m:
        return m.group(0)
    return ""
"""
    graph = DependencyGraph()
    graph.index_source("src/safe_regex.py", code)
    code_ctx = graph.build_code_context(["src/safe_regex.py"])
    analyzer = BugAnalyzer()
    findings = analyzer.analyze(code_ctx)
    assert not any(f.rule_id == "BUG-006" for f in findings)


def test_quality_analyzer() -> None:
    graph = DependencyGraph()
    graph.index_source("src/quality.py", CODE_WITH_QUALITY_ISSUES)
    code_ctx = graph.build_code_context(["src/quality.py"])

    analyzer = QualityAnalyzer(max_params=6)
    findings = analyzer.analyze(code_ctx)

    assert any(f.rule_id == "QUAL-004" for f in findings)


def test_performance_analyzer() -> None:
    graph = DependencyGraph()
    graph.index_source("src/perf.py", CODE_WITH_PERF_ISSUES)
    code_ctx = graph.build_code_context(["src/perf.py"])

    analyzer = PerformanceAnalyzer()
    findings = analyzer.analyze(code_ctx)

    assert any(f.rule_id == "PERF-002" for f in findings)


def test_duplication_analyzer() -> None:
    graph = DependencyGraph()
    graph.index_source("src/file1.py", CODE_WITH_DUPLICATION_1)
    graph.index_source("src/file2.py", CODE_WITH_DUPLICATION_2)
    code_ctx = graph.build_code_context(["src/file1.py", "src/file2.py"])

    analyzer = DuplicationAnalyzer()
    findings = analyzer.analyze(code_ctx)

    assert len(findings) >= 1
    assert any(f.rule_id in ("DUP-001", "DUPL-001") for f in findings)


def test_duplication_analyzer_on_ast_hashing() -> None:
    graph = DependencyGraph()
    graph.index_source("src/file1.py", CODE_WITH_DUPLICATION_1)
    graph.index_source("src/file2.py", CODE_WITH_DUPLICATION_2)
    code_ctx = graph.build_code_context(["src/file1.py", "src/file2.py"])

    analyzer = DuplicationAnalyzer()
    findings = analyzer.analyze(code_ctx)

    assert len(findings) >= 1
    assert any(f.rule_id == "DUP-001" for f in findings)
    assert any("file1.py" in (f.file_path + f.message) and "file2.py" in (f.file_path + f.message) for f in findings)

