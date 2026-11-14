"""Export session data to JSON, CSV, or HTML formats."""

import csv
import io
import json
from pathlib import Path
from typing import Optional

from agentblackbox.replay.timeline import build_timeline
from agentblackbox.storage.event_store import EventStore


def export_json(store: EventStore, session_id: str) -> str:
    """Export a session and its events as JSON.

    Args:
        store: EventStore to query.
        session_id: Session to export.

    Returns:
        JSON string of session data.
    """
    session = store.get_session(session_id)
    if not session:
        return json.dumps({"error": f"Session {session_id} not found"})

    events = store.query_events(session_id=session_id, limit=100000)

    data = {
        "session": {
            "id": session.id,
            "name": session.name,
            "workspace_path": session.workspace_path,
            "agent_hint": session.agent_hint,
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "status": session.status,
            "total_events": session.total_events,
            "risk_score": session.risk_score,
        },
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "severity": e.severity,
                "risk_score": e.risk_score,
                "source_path": e.source_path,
                "payload": e.payload,
                "tags": e.tags,
            }
            for e in events
        ],
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "description": a.description,
                "acknowledged": a.acknowledged,
            }
            for a in store.get_alerts(session_id=session_id)
        ],
    }
    return json.dumps(data, indent=2, default=str)


def export_csv(store: EventStore, session_id: str) -> str:
    """Export session events as CSV.

    Args:
        store: EventStore to query.
        session_id: Session to export.

    Returns:
        CSV string of events.
    """
    events = store.query_events(session_id=session_id, limit=100000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "event_type", "severity", "risk_score", "source_path", "payload", "tags"])
    for e in events:
        writer.writerow([
            e.id, e.timestamp, e.event_type, e.severity,
            e.risk_score, e.source_path, json.dumps(e.payload),
            ",".join(e.tags),
        ])
    return output.getvalue()


def export_html(store: EventStore, session_id: str) -> str:
    """Export session as a standalone HTML report.

    Args:
        store: EventStore to query.
        session_id: Session to export.

    Returns:
        HTML string of the report.
    """
    session = store.get_session(session_id)
    if not session:
        return "<html><body><h1>Session not found</h1></body></html>"

    timeline = build_timeline(store, session_id)
    alerts = store.get_alerts(session_id=session_id)

    severity_colors = {
        "info": "#3b82f6",
        "warning": "#f59e0b",
        "danger": "#ef4444",
        "critical": "#dc2626",
    }

    rows = ""
    for entry in timeline.entries:
        e = entry.event
        color = severity_colors.get(e.severity, "#6b7280")
        rows += f"""
        <tr>
            <td>{e.timestamp[11:19] if len(e.timestamp) > 19 else e.timestamp}</td>
            <td><span style="color:{color};font-weight:bold">{e.severity.upper()}</span></td>
            <td>{e.risk_score}</td>
            <td>{entry.label}</td>
            <td>{e.source_path or '-'}</td>
        </tr>"""

    alert_rows = ""
    for a in alerts:
        alert_rows += f"<tr><td>{a.alert_type}</td><td>{a.description}</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AgentBlackBox Report — {session.id}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; background: #0a0a0a; color: #e5e5e5; padding: 2rem; }}
  h1 {{ color: #f97316; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #333; padding: 0.5rem; text-align: left; }}
  th {{ background: #1a1a1a; color: #f97316; }}
  tr:hover {{ background: #1a1a1a; }}
  .stat {{ display: inline-block; background: #1a1a1a; padding: 0.5rem 1rem; margin: 0.25rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>🔴 AgentBlackBox Report</h1>
<p><strong>Session:</strong> {session.id} | <strong>Name:</strong> {session.name or 'unnamed'}</p>
<p><strong>Workspace:</strong> {session.workspace_path}</p>
<p><strong>Started:</strong> {session.started_at} | <strong>Ended:</strong> {session.ended_at or 'still recording'}</p>
<p><strong>Status:</strong> {session.status} | <strong>Risk Score:</strong> {session.risk_score}</p>

<div>
  <span class="stat">📊 Total Events: {session.total_events}</span>
  <span class="stat">⚠️ Alerts: {len(alerts)}</span>
</div>

<h2>📋 Timeline</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Risk</th><th>Event</th><th>File</th></tr>
{rows}
</table>

{"<h2>🚨 Alerts</h2><table><tr><th>Type</th><th>Description</th></tr>" + alert_rows + "</table>" if alerts else ""}

<p style="color:#666;margin-top:2rem">Generated by AgentBlackBox v0.4.0</p>
</body>
</html>"""


def export_sarif(
    store: EventStore,
    session_id: Optional[str] = None,
    output_path: Optional[Path] = None,
) -> dict:
    """Export session security findings and compliance violations as SARIF v2.1.0 JSON.

    Args:
        store: EventStore instance to query.
        session_id: Target session ID (or latest if None).
        output_path: Optional file path to write SARIF JSON.

    Returns:
        SARIF v2.1.0 dictionary structure.
    """
    target_session_id = session_id
    if not target_session_id:
        sessions = store.list_sessions(limit=1)
        if sessions:
            target_session_id = sessions[0].id

    events = store.query_events(session_id=target_session_id, limit=50000) if target_session_id else []

    rules_map = {
        "SOC2-CC6.1": {
            "id": "SOC2-CC6.1",
            "name": "SecretOrCredentialExposure",
            "shortDescription": {"text": "Unredacted credential or secret detected in agent session"},
            "defaultConfiguration": {"level": "error"},
        },
        "OWASP-LLM06": {
            "id": "OWASP-LLM06",
            "name": "ExcessiveAgencyOrUnsafeExecution",
            "shortDescription": {"text": "Unsafe execution parameter (shell=True, verify=False, eval)"},
            "defaultConfiguration": {"level": "error"},
        },
        "GDPR-PII-01": {
            "id": "GDPR-PII-01",
            "name": "PIIExposure",
            "shortDescription": {"text": "Personally Identifiable Information detected in context"},
            "defaultConfiguration": {"level": "warning"},
        },
        "MIT-LICENSE-GUARD": {
            "id": "MIT-LICENSE-GUARD",
            "name": "LicenseComplianceDrift",
            "shortDescription": {"text": "Viral or non-compliant license introduced by agent"},
            "defaultConfiguration": {"level": "warning"},
        },
        "DRIFT-LAYER": {
            "id": "DRIFT-LAYER",
            "name": "ArchitecturalLayerViolation",
            "shortDescription": {"text": "Cross-layer import boundary violation"},
            "defaultConfiguration": {"level": "error"},
        },
        "DRIFT-SIG-BREAK": {
            "id": "DRIFT-SIG-BREAK",
            "name": "BreakingSignatureChange",
            "shortDescription": {"text": "Breaking public function signature contract change"},
            "defaultConfiguration": {"level": "error"},
        },
        "HIGH-RISK-COMMAND": {
            "id": "HIGH-RISK-COMMAND",
            "name": "HighRiskCommandExecution",
            "shortDescription": {"text": "High risk shell command executed by agent"},
            "defaultConfiguration": {"level": "error"},
        },
    }

    results = []

    for ev in events:
        source_uri = (ev.source_path or "agentblackbox/session").replace("\\", "/")
        payload = ev.payload if isinstance(ev.payload, dict) else {}

        # 1. Compliance findings in payload
        if "compliance_findings" in payload and isinstance(payload["compliance_findings"], list):
            for cf in payload["compliance_findings"]:
                r_id = cf.get("rule_id", "SOC2-CC6.1")
                sev = cf.get("severity", "high").lower()
                lvl = "error" if sev in ("critical", "high", "danger") else ("warning" if sev in ("medium", "warning") else "note")
                results.append({
                    "ruleId": r_id,
                    "level": lvl,
                    "message": {"text": cf.get("description", "Compliance finding")},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": (cf.get("file_path") or source_uri).replace("\\", "/")},
                            "region": {"startLine": int(cf.get("line_number") or 1)},
                        }
                    }],
                })

        # 2. Drift violations in payload
        if "drift_violations" in payload and isinstance(payload["drift_violations"], list):
            for dv in payload["drift_violations"]:
                r_id = dv.get("rule_code", "DRIFT-LAYER")
                results.append({
                    "ruleId": "DRIFT-LAYER" if "LAYER" in r_id else ("DRIFT-SIG-BREAK" if "SIG" in r_id else r_id),
                    "level": "error",
                    "message": {"text": dv.get("description", "Architectural drift violation")},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": (dv.get("source_module") or source_uri).replace("\\", "/")},
                            "region": {"startLine": int(dv.get("line") or 1)},
                        }
                    }],
                })

        # 3. Secret detected events
        if ev.event_type == "secret_detected" or payload.get("secret_matches"):
            matches = payload.get("secret_matches", [])
            for m in matches:
                pname = m.get("pattern_name", "secret") if isinstance(m, dict) else str(m)
                results.append({
                    "ruleId": "SOC2-CC6.1",
                    "level": "error",
                    "message": {"text": f"Unredacted secret detected: {pname}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": source_uri},
                            "region": {"startLine": int(m.get("line_number", 1)) if isinstance(m, dict) else 1},
                        }
                    }],
                })

        # 4. High-risk commands
        if ev.risk_score >= 7.0 and ev.event_type in ("cmd_execute", "git_force_push", "git_reset"):
            cmd = payload.get("command", "") if isinstance(payload, dict) else str(payload)
            results.append({
                "ruleId": "HIGH-RISK-COMMAND",
                "level": "error",
                "message": {"text": f"High risk agent execution (risk={ev.risk_score}): {cmd}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": source_uri},
                        "region": {"startLine": 1},
                    }
                }],
            })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentBlackBox",
                        "version": "0.4.0",
                        "informationUri": "https://github.com/ATP0925/AgentBlackBox",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc


