"""SARIF v2.1.0 Export Generator for GitHub Pull Request Reviews.

Generates standard Static Analysis Results Format (SARIF) documents compatible with
GitHub Advanced Security code scanning alerts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentblackbox import __version__
from agentblackbox.models.finding import Finding, Severity


def generate_pr_sarif(
    findings: List[Finding],
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    drift_violations: Optional[List[Dict[str, Any]]] = None,
    owner: str = "",
    repo: str = "",
    pull_number: int = 0,
    commit_sha: str = "",
) -> Dict[str, Any]:
    """Generate SARIF v2.1.0 document from PR review findings.

    Args:
        findings: List of Finding objects.
        compliance_findings: Optional list of compliance findings dicts.
        drift_violations: Optional list of drift violation dicts.
        owner: Repository owner.
        repo: Repository name.
        pull_number: Pull request number.
        commit_sha: Reviewed commit SHA.

    Returns:
        SARIF v2.1.0 dictionary.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    # 1. Map core findings
    for f in findings:
        rule_id = f.rule_id or "ABB-GENERIC"
        if rule_id not in rules:
            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else ("warning" if f.severity == Severity.MEDIUM else "note")
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title.replace(" ", "")[:64],
                "shortDescription": {"text": f.title[:255]},
                "fullDescription": {"text": f.description[:1000]},
                "defaultConfiguration": {"level": level},
            }

        start_line = max(1, f.line_start)
        end_line = max(start_line, f.line_end)
        clean_path = f.file_path.replace("\\", "/").lstrip("/")

        result_item: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": rules[rule_id]["defaultConfiguration"]["level"],
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": clean_path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": start_line, "endLine": end_line},
                    }
                }
            ],
        }
        if f.suggestion:
            result_item["fixes"] = [
                {
                    "description": {"text": "Suggested fix"},
                    "replacement": f.suggestion,
                }
            ]
        results.append(result_item)

    # 2. Map compliance findings
    for c in (compliance_findings or []):
        r_id = c.get("rule_id", "COMPLIANCE-CHECK")
        if r_id not in rules:
            rules[r_id] = {
                "id": r_id,
                "name": "ComplianceCheck",
                "shortDescription": {"text": c.get("description", "Compliance policy violation")[:255]},
                "defaultConfiguration": {"level": "error"},
            }
        clean_path = str(c.get("file_path", "unknown")).replace("\\", "/").lstrip("/")
        line_num = max(1, c.get("line_number", 1))
        results.append({
            "ruleId": r_id,
            "level": "error",
            "message": {"text": c.get("description", "Compliance violation")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": clean_path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": line_num, "endLine": line_num},
                    }
                }
            ],
        })

    # 3. Map drift violations
    for d in (drift_violations or []):
        d_code = d.get("rule_code", "DRIFT-VIOLATION")
        if d_code not in rules:
            rules[d_code] = {
                "id": d_code,
                "name": "ArchitecturalDriftViolation",
                "shortDescription": {"text": d.get("description", "Architectural drift")[:255]},
                "defaultConfiguration": {"level": "error"},
            }
        clean_path = str(d.get("source_module", "unknown")).replace("\\", "/").lstrip("/")
        line_num = max(1, d.get("line", 1))
        results.append({
            "ruleId": d_code,
            "level": "error",
            "message": {"text": d.get("description", "Architectural boundary violation")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": clean_path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": line_num, "endLine": line_num},
                    }
                }
            ],
        })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentBlackBox",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/ATP0925/AgentBlackBox",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": f"https://github.com/{owner}/{repo}/blob/{commit_sha}/" if owner and repo else "file:///"
                    }
                },
            }
        ],
    }
    return sarif_doc
