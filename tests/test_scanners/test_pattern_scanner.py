"""Unit tests for PatternScanner."""

from agentblackbox.scanners.pattern_scanner import PatternScanner


SAMPLE_CONFIG_CODE = """
import os
import tempfile

def setup_insecure_environment():
    temp_path = tempfile.mktemp()
    os.chmod(temp_path, 0o777)
    return temp_path
"""


def test_pattern_scanner_detects_mktemp_and_chmod() -> None:
    scanner = PatternScanner()
    findings = scanner.scan_file("src/setup.py", SAMPLE_CONFIG_CODE)

    rule_ids = {f.rule_id for f in findings}
    assert "SEC-005" in rule_ids  # chmod 777
    assert "SEC-006" in rule_ids  # tempfile.mktemp
