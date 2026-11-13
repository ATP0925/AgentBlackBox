"""Finding and severity data models for code review."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Severity levels for code review findings, ordered from highest to lowest impact."""

    CRITICAL = "Critical"  # Vulnerabilities, crash-inducing bugs, data loss risk
    HIGH = "High"          # Logic defects, security weaknesses, significant performance hits
    MEDIUM = "Medium"      # Code smells, unhandled edge cases, resource mismanagement
    LOW = "Low"            # Minor inefficiencies, naming/style issues, missing hints
    INFO = "Info"          # Style improvements, docstring suggestions, positive feedback

    @property
    def level(self) -> int:
        """Numeric rank for sorting (5 highest, 1 lowest)."""
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_str(cls, val: str) -> "Severity":
        """Convert string to Severity case-insensitively."""
        v = val.strip().capitalize()
        for member in cls:
            if member.value == v or member.name == val.strip().upper():
                return member
        return cls.INFO

    @classmethod
    def from_string(cls, val: str) -> "Severity":
        """Alias for from_str."""
        return cls.from_str(val)


class FindingCategory(str, Enum):
    """Classification category for findings."""

    SECURITY = "security"
    BUG = "bug"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    DUPLICATION = "duplication"
    STYLE = "style"


@dataclass
class Finding:
    """Individual code review finding with actionable remediation."""

    title: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    category: str
    message: str
    why_it_matters: str
    suggested_fix: str
    rule_id: str
    diff_hunk: Optional[str] = None
    cwe_id: Optional[str] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
