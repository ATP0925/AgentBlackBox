"""Unit tests for ASTScanner rules."""

from agentblackbox.scanners.ast_scanner import ASTScanner
from agentblackbox.models.finding import Severity


SAMPLE_VULNERABLE_CODE = """
import subprocess
import pickle
import time

def process_items(items=[], flags={}):
    pass

def run_cmd(user_input):
    subprocess.Popen(f"echo {user_input}", shell=True)

def query_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def load_data(raw):
    return pickle.loads(raw)

def compare_val(x):
    if x is "constant_str":
        return True
    return False

def bad_catch():
    try:
        x = 1 / 0
    except:
        pass

async def async_slow():
    time.sleep(2)
"""


def test_ast_scanner_catches_all_patterns() -> None:
    scanner = ASTScanner()
    findings = scanner.scan_file("src/vulnerable.py", SAMPLE_VULNERABLE_CODE)

    rule_ids = {f.rule_id for f in findings}

    # Should detect mutable defaults
    assert "BUG-001" in rule_ids
    # Should detect shell=True
    assert "SEC-002" in rule_ids
    # Should detect SQL injection
    assert "SEC-001" in rule_ids
    # Should detect pickle.loads
    assert "SEC-003" in rule_ids
    # Should detect 'is' literal comparison
    assert "BUG-003" in rule_ids
    # Should detect bare except pass
    assert "QUAL-001" in rule_ids
    # Should detect blocking sleep in async
    assert "PERF-001" in rule_ids

    # Check that critical/high severities are assigned
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 2  # SEC-001, SEC-002

