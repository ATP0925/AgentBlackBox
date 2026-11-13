"""Structured review report model with Markdown, SARIF, and JSON serializers."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agentblackbox.models.finding import Finding, Severity


@dataclass
class ReviewReport:
    """Comprehensive analysis report containing prioritized findings and metrics."""

    target: str
    findings: List[Finding] = field(default_factory=list)
    analyzed_files: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    model_name: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Return count of findings grouped by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def has_critical_or_high(self) -> bool:
        """Return True if any Critical or High severity findings exist."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to standard serializable dictionary."""
        return {
            "target": self.target,
            "created_at": self.created_at,
            "execution_time_ms": self.execution_time_ms,
            "model_name": self.model_name,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "analyzed_files": self.analyzed_files,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }

    def to_markdown(self) -> str:
        """Render report as a developer-friendly GitHub Pull Request review comment."""
        lines: List[str] = []
        lines.append(f"# 🔍 AI Code Review: `{self.target}`")
        lines.append("")

        counts = self.severity_counts
        summary_badges = [
            f"**Total Issues:** {self.total_findings}",
            f"🔴 Critical: {counts.get('Critical', 0)}",
            f"🟠 High: {counts.get('High', 0)}",
            f"🟡 Medium: {counts.get('Medium', 0)}",
            f"🔵 Low: {counts.get('Low', 0)}",
            f"⚪ Info: {counts.get('Info', 0)}",
        ]
        lines.append(" | ".join(summary_badges))
        lines.append("")

        if not self.findings:
            lines.append("✅ **Clean Bill of Health**: No defects, vulnerabilities, or quality issues were identified!")
            return "\n".join(lines)

        # Sort findings by severity level descending
        sorted_findings = sorted(self.findings, key=lambda f: f.severity.level, reverse=True)

        lines.append("## Key Findings")
        lines.append("")

        severity_icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "ℹ️",
        }

        for idx, f in enumerate(sorted_findings, 1):
            icon = severity_icons.get(f.severity, "⚠️")
            lines.append(f"### {idx}. {icon} [{f.severity.value}] {f.title}")
            lines.append(f"- **Location**: `{f.file_path}:{f.line_start}-{f.line_end}`")
            lines.append(f"- **Category**: `{f.category}` | **Rule**: `{f.rule_id}`" + (f" | **CWE**: `{f.cwe_id}`" if f.cwe_id else ""))
            lines.append("")
            lines.append(f"**Explanation:** {f.message}")
            lines.append("")
            lines.append(f"**Why It Matters:** {f.why_it_matters}")
            lines.append("")
            if f.suggested_fix:
                lines.append("**Suggested Remediation:**")
                lines.append("```python")
                lines.append(f.suggested_fix.strip())
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")

        lines.append(f"*Analyzed {len(self.analyzed_files)} files in {self.execution_time_ms:.1f}ms" + (f" using {self.model_name}*" if self.model_name else "*"))
        return "\n".join(lines)

    def to_sarif(self) -> Dict[str, Any]:
        """Export report to standard SARIF 2.1.0 JSON format for GitHub Security Scanning."""
        sarif_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        rules_dict: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in self.findings:
            if f.rule_id not in rules_dict:
                rules_dict[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.why_it_matters or f.message},
                    "defaultConfiguration": {"level": sarif_level_map.get(f.severity, "warning")},
                }
                if f.cwe_id:
                    rules_dict[f.rule_id]["properties"] = {"tags": [f"external/cwe/{f.cwe_id}"]}

            result = {
                "ruleId": f.rule_id,
                "level": sarif_level_map.get(f.severity, "warning"),
                "message": {"text": f"{f.message}\nWhy it matters: {f.why_it_matters}\nFix: {f.suggested_fix}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                            "region": {
                                "startLine": max(1, f.line_start),
                                "endLine": max(1, f.line_end),
                            },
                        }
                    }
                ],
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentBlackBox Code Review",
                            "version": "0.3.0",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

