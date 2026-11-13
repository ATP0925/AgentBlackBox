"""Rule definitions and metadata for deterministic code analysis."""

from dataclasses import dataclass
from typing import Dict, Optional

from agentblackbox.models.finding import FindingCategory, Severity


@dataclass(frozen=True)
class Rule:
    """Static analysis rule definition."""

    rule_id: str
    title: str
    severity: Severity
    category: FindingCategory
    description: str
    why_it_matters: str
    suggested_fix: str
    cwe_id: Optional[str] = None


BUILTIN_RULES: Dict[str, Rule] = {
    "SEC-001": Rule(
        rule_id="SEC-001",
        title="SQL Injection via String Formatting",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECURITY,
        description="SQL query string is constructed using string interpolation or concatenation.",
        why_it_matters="Allows external attackers to execute arbitrary SQL commands, bypass authentication, and exfiltrate database records.",
        suggested_fix="Use parameterized queries with placeholder bindings (e.g. `cursor.execute('SELECT * FROM t WHERE id = ?', (val,))`).",
        cwe_id="CWE-89",
    ),
    "SEC-002": Rule(
        rule_id="SEC-002",
        title="Command Injection via shell=True",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECURITY,
        description="subprocess command executed with `shell=True` or raw shell string evaluation.",
        why_it_matters="If command string contains untrusted user input, attackers can escape arguments and execute arbitrary operating system commands.",
        suggested_fix="Pass command as a list of argument tokens with `shell=False` (e.g. `subprocess.run(['ls', '-l'])`).",
        cwe_id="CWE-78",
    ),
    "SEC-003": Rule(
        rule_id="SEC-003",
        title="Unsafe Deserialization via pickle or yaml",
        severity=Severity.HIGH,
        category=FindingCategory.SECURITY,
        description="Loading untrusted serialized data using pickle or PyYAML without SafeLoader.",
        why_it_matters="Arbitrary code execution can occur upon deserializing crafted byte payloads.",
        suggested_fix="Use safe serialization formats like JSON, or `yaml.safe_load()` instead of `pickle.loads()`.",
        cwe_id="CWE-502",
    ),
    "SEC-004": Rule(
        rule_id="SEC-004",
        title="Hardcoded API Secret or Private Key",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECURITY,
        description="Hardcoded credential, token, or private cryptographic key detected in source code.",
        why_it_matters="Committed secrets leak access to cloud infrastructure and production services to anyone with repository read access.",
        suggested_fix="Move the secret to an environment variable or secure secrets manager (e.g. AWS Secrets Manager, Vault).",
        cwe_id="CWE-798",
    ),
    "BUG-001": Rule(
        rule_id="BUG-001",
        title="Mutable Default Argument in Function Definition",
        severity=Severity.HIGH,
        category=FindingCategory.BUG,
        description="Function defines a mutable object (list, dict, set) as a default parameter value.",
        why_it_matters="Python binds default arguments once at definition time. Mutating the parameter mutates it across all subsequent invocations.",
        suggested_fix="Set default to None and initialize inside the function (e.g. `def f(items: list = None): if items is None: items = []`).",
    ),
    "BUG-002": Rule(
        rule_id="BUG-002",
        title="Resource Leak (Unclosed File/Socket Handle)",
        severity=Severity.MEDIUM,
        category=FindingCategory.BUG,
        description="`open()` call without a `with` context manager.",
        why_it_matters="Unclosed file handles cause resource leaks, file locking conflicts (especially on Windows), and delayed flush of data.",
        suggested_fix="Wrap the file access in a `with open(...) as fp:` block.",
    ),
    "BUG-003": Rule(
        rule_id="BUG-003",
        title="Literal Identity Comparison Using 'is'",
        severity=Severity.MEDIUM,
        category=FindingCategory.BUG,
        description="Comparison with string, integer, or float literal using `is` instead of `==`.",
        why_it_matters="`is` tests object memory identity, not value equality. Python interning behavior can cause subtle, unpredictable comparison failures.",
        suggested_fix="Use `==` for value comparison (e.g. `x == 'target'` instead of `x is 'target'`).",
    ),
    "QUAL-001": Rule(
        rule_id="QUAL-001",
        title="Bare or Silent Exception Catch",
        severity=Severity.MEDIUM,
        category=FindingCategory.QUALITY,
        description="Exception block catches bare `except:` or `except Exception:` followed only by `pass`.",
        why_it_matters="Swallows unexpected errors, masking critical failures and making debugging and post-mortems impossible.",
        suggested_fix="Catch specific expected exception types and at minimum log the failure using structlog or logger.",
    ),
    "QUAL-002": Rule(
        rule_id="QUAL-002",
        title="Excessive Cyclomatic Complexity",
        severity=Severity.LOW,
        category=FindingCategory.QUALITY,
        description="Function or method exceeds recommended cyclomatic complexity threshold (> 15).",
        why_it_matters="High cyclomatic complexity makes functions difficult to test, reason about, and maintain without introducing regressions.",
        suggested_fix="Refactor complex branching logic into smaller helper functions or lookup tables.",
    ),
    "PERF-001": Rule(
        rule_id="PERF-001",
        title="Synchronous Blocking Sleep in Async Function",
        severity=Severity.HIGH,
        category=FindingCategory.PERFORMANCE,
        description="`time.sleep()` invoked inside an `async def` function.",
        why_it_matters="Blocks the entire event loop thread, stalling all concurrent requests and coroutines in the application.",
        suggested_fix="Use `await asyncio.sleep(...)` instead of `time.sleep(...)`.",
    ),
}
