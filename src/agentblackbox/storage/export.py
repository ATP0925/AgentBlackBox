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

<p style="color:#666;margin-top:2rem">Generated by AgentBlackBox v0.1.0</p>
</body>
</html>"""

