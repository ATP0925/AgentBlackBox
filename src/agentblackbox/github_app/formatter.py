"""Markdown Formatter for GitHub Walkthrough Comments, Inline Reviews, and Check Runs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agentblackbox.github_app.diff import DiffMapper, DiffPosition
from agentblackbox.models.finding import Finding, Severity

WALKTHROUGH_MARKER = "<!-- agentblackbox-walkthrough -->"


def format_walkthrough(
    pr_number: int,
    pr_title: str,
    head_sha: str,
    files_analyzed: int,
    findings: List[Finding],
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    drift_violations: Optional[List[Dict[str, Any]]] = None,
    ai_summary: str = "",
    config_warnings: Optional[List[str]] = None,
    out_of_diff_findings: Optional[List[Finding]] = None,
    receipt: Optional[Any] = None,
    linked_session: Optional[Any] = None,
    risk_breakdown: Optional[Any] = None,
) -> str:
    """Generate or update the top-level PR Walkthrough comment with hidden marker."""
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity in (Severity.LOW, Severity.INFO))

    # Status badge
    if crit_count > 0:
        status_badge = "🔴 **Action Required: Critical Security or Logic Issues**"
    elif high_count > 0:
        status_badge = "🟠 **Changes Recommended: High-Severity Flaws Found**"
    elif med_count > 0:
        status_badge = "🟡 **Review Advised: Minor Quality or Security Smells**"
    else:
        status_badge = "🟢 **Review Passed: Clean Bill of Health**"

    lines = [
        WALKTHROUGH_MARKER,
        "## 🛸 AgentBlackBox In-Memory Code Review & Flight Audit",
        f"{status_badge}  •  **PR #{pr_number}** (`{pr_title}`)  •  `{files_analyzed}` files analyzed  •  `{head_sha[:7]}`",
        "",
    ]

    # Config warnings if any
    if config_warnings:
        lines.append("> [!WARNING]")
        for w in config_warnings:
            lines.append(f"> {w}")
        lines.append("")

    # AI Summary
    if ai_summary.strip():
        lines.append("### 📝 Walkthrough & Summary")
        lines.append(ai_summary.strip())
        lines.append("")
    else:
        lines.append("### 📝 Walkthrough & Summary")
        lines.append(f"Automated in-memory audit completed for PR #{pr_number}: `{pr_title}`.")
        lines.append("")

    # PR Risk Score Breakdown
    if risk_breakdown:
        score_val = getattr(risk_breakdown, "total_score", None)
        level_val = getattr(risk_breakdown, "risk_level", "LOW")
        if score_val is not None:
            color_icon = "🔴" if score_val >= 7.5 else ("🟠" if score_val >= 5.0 else ("🟡" if score_val >= 3.0 else "🟢"))
            lines.extend([
                "### 📈 Explainable PR Risk Score",
                f"{color_icon} **Risk Index: {score_val:.1f} / 10.0** (`{level_val}`)",
            ])
            factors = getattr(risk_breakdown, "factors", [])
            if factors:
                for fct in factors[:5]:
                    lines.append(f"- **{fct.get('factor')}**: {fct.get('path', '')} (+{fct.get('points', 0)} pts)")
            lines.append("")

    # Linked Agent Session Summary
    if linked_session and getattr(linked_session, "session_id", None):
        sess_icon = "🔴" if getattr(linked_session, "tamper_detected", False) else ("🟢" if getattr(linked_session, "is_valid", False) else "🟡")
        lines.extend([
            "### 🔗 Linked Agent Session Flight Log",
            f"{sess_icon} **Session ID**: `{linked_session.session_id}` — {getattr(linked_session, 'verification_message', '')}",
            f"- **Tools & Commands Executed**: {getattr(linked_session, 'tools_called', 0)} tool calls ({getattr(linked_session, 'commands_executed', 0)} shell commands)",
            f"- **Files Changed in Dark**: {getattr(linked_session, 'files_modified', 0)} modified, {getattr(linked_session, 'files_deleted', 0)} deleted",
            f"- **PreToolUse Blocks**: {getattr(linked_session, 'blocked_actions', 0)} unauthorized actions blocked by hooks",
        ])
        touched_tests = getattr(linked_session, "tests_touched", [])
        if touched_tests:
            lines.append(f"- **Tests Touched**: `{', '.join(touched_tests[:5])}`")
        lines.append("")

    # Severity overview table
    lines.extend([
        "### 📊 Review Overview",
        "| Severity | Findings | Status |",
        "| :--- | :---: | :--- |",
        f"| 🔴 **Critical** | {crit_count} | {'Needs Attention' if crit_count else 'Clean'} |",
        f"| 🟠 **High** | {high_count} | {'Needs Attention' if high_count else 'Clean'} |",
        f"| 🟡 **Medium** | {med_count} | {'Review' if med_count else 'Clean'} |",
        f"| 🔵 **Low / Smells** | {low_count} | {'Review' if low_count else 'Clean'} |",
        "",
    ])

    # Compliance & Drift highlights
    if compliance_findings or drift_violations:
        lines.append("### 🛡️ Compliance & Architectural Boundary Guard")
        if compliance_findings:
            for c in compliance_findings:
                lines.append(f"- **[{c.get('framework', 'Compliance')}]** `{c.get('rule_id')}`: {c.get('description')}")
        if drift_violations:
            for d in drift_violations:
                lines.append(f"- **[Drift Guard]** `{d.get('rule_code')}` in `{d.get('source_module')}`: {d.get('description')}")
        lines.append("")

    # Out of diff findings (so they are not dropped)
    if out_of_diff_findings:
        lines.append("### ⚠️ Additional Findings Outside Diff Context")
        lines.append("The following issues were identified in analyzed files but outside the modified diff hunks:")
        for oof in out_of_diff_findings[:10]:
            lines.append(f"- **{oof.file_path}:{oof.line_start}** [{oof.severity.name}] `{oof.rule_id}`: {oof.title} — {oof.description}")
        lines.append("")

    # Cryptographic Signed Review Receipt Footer
    if receipt and getattr(receipt, "receipt_id", None):
        tip_hash = getattr(receipt, "chain_tip_hash", "")
        tip_display = f"`{tip_hash[:16]}...`" if tip_hash else "*(unkeyed)*"
        lines.extend([
            "### 🔒 Cryptographic Review Receipt",
            f"- **Receipt ID**: `{receipt.receipt_id}`",
            f"- **Merkle Chain Root**: {tip_display} *(Sequence #{getattr(receipt, 'event_seq', 0)})*",
            f"- **Provable Zero Retention**: Diff SHA-256 `{getattr(receipt, 'diff_hash', '')[:16]}...` (ephemeral RAM processing, 0 customer code stored)",
            f"- **Offline Verification**: `abb verify-receipt {receipt.receipt_id}`",
            "",
        ])

    # Footer
    lines.extend([
        "---",
        "> 💬 **Commands**: Mention `@agentblackbox review` to re-run, `@agentblackbox full review` for all files, `@agentblackbox pause` to pause, `@agentblackbox resume` to resume, or `@agentblackbox help`.",
    ])

    return "\n".join(lines)


def format_inline_review_comments(
    findings: List[Finding],
    diff_mapper: DiffMapper,
    max_comments: int = 25,
) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    """Format inline PR review comments with one-click suggestion blocks where safe.

    Returns:
        Tuple of (inline_comments_payload, out_of_diff_findings).
    """
    inline_comments: List[Dict[str, Any]] = []
    out_of_diff: List[Finding] = []

    # Process findings prioritized by severity
    sorted_findings = sorted(findings, key=lambda f: (-f.severity.level, f.file_path, f.line_start))

    for f in sorted_findings:
        pos = diff_mapper.get_comment_position(f.file_path, f.line_start)
        if not pos:
            out_of_diff.append(f)
            continue

        if len(inline_comments) >= max_comments:
            out_of_diff.append(f)
            continue

        # Format body
        sev_badge = {
            Severity.CRITICAL: "🔴 **Critical**",
            Severity.HIGH: "🟠 **High**",
            Severity.MEDIUM: "🟡 **Medium**",
            Severity.LOW: "🔵 **Low**",
            Severity.INFO: "⚪ **Info**",
        }.get(f.severity, f.severity.name)

        body_parts = [
            f"### {sev_badge}: {f.title} (`{f.rule_id}`)",
            f"{f.description}",
        ]
        if f.impact:
            body_parts.append(f"\n**Why it matters:** {f.impact}")

        # Check if safe suggested fix block can be generated
        if f.suggestion and f.suggestion.strip() and not f.suggestion.strip().startswith("```"):
            body_parts.extend([
                "\n**Suggested Remediation:**",
                "```suggestion",
                f.suggestion.strip(),
                "```",
            ])
        elif f.suggestion:
            body_parts.extend(["\n**Suggested Remediation:**", f.suggestion.strip()])

        inline_comments.append({
            "path": pos.path,
            "line": pos.line,
            "side": pos.side,
            "body": "\n".join(body_parts),
        })

    return inline_comments, out_of_diff


def format_check_run_output(
    findings: List[Finding],
    fail_on: str = "high",
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    drift_violations: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, Dict[str, Any], List[List[Dict[str, Any]]]]:
    """Determine Check Run conclusion, summary, and batched annotations.

    GitHub API limits annotations to 50 items per check run request.

    Returns:
        Tuple of (conclusion, output_dict, list_of_annotation_batches).
    """
    threshold_level = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "none": 999,
    }.get(fail_on.lower(), 4)

    has_failures = any(f.severity.level >= threshold_level for f in findings)
    if compliance_findings:
        has_failures = True
    if drift_violations:
        has_failures = True

    conclusion = "failure" if has_failures else "success"
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

    title = f"AgentBlackBox: {'Failed' if has_failures else 'Passed'}"
    summary = (
        f"Automated Code Review: {len(findings)} findings "
        f"({crit_count} Critical, {high_count} High, {med_count} Medium). "
        f"Compliance issues: {len(compliance_findings or [])}. "
        f"Drift violations: {len(drift_violations or [])}."
    )

    # Convert findings to GitHub check annotations
    raw_annotations: List[Dict[str, Any]] = []
    for f in findings:
        level = "failure" if f.severity in (Severity.CRITICAL, Severity.HIGH) else ("warning" if f.severity == Severity.MEDIUM else "notice")
        start_line = max(1, f.line_start)
        end_line = max(start_line, f.line_end)

        annotation: Dict[str, Any] = {
            "path": f.file_path.replace("\\", "/").lstrip("/"),
            "start_line": start_line,
            "end_line": end_line,
            "annotation_level": level,
            "message": f"{f.title}: {f.description[:500]}",
            "title": f"[{f.rule_id}] {f.title}"[:255],
        }
        if f.suggestion:
            annotation["raw_details"] = f.suggestion[:1000]
        raw_annotations.append(annotation)

    # Batch annotations in chunks of 50
    annotation_batches: List[List[Dict[str, Any]]] = []
    chunk_size = 50
    for i in range(0, len(raw_annotations), chunk_size):
        annotation_batches.append(raw_annotations[i : i + chunk_size])

    first_batch = annotation_batches[0] if annotation_batches else []
    output_dict: Dict[str, Any] = {
        "title": title,
        "summary": summary,
        "annotations": first_batch,
    }

    return conclusion, output_dict, annotation_batches[1:]
