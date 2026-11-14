"""Shared alerting helpers for daemon and agent hooks."""

from __future__ import annotations

from typing import Optional

from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Alert, Event


def maybe_create_alert(store: EventStore, event: Event) -> Optional[Alert]:
    """Create an Alert if the event has risk_score >= 5.0 or 'secret' in tags.

    Args:
        store: Connected EventStore instance.
        event: Inserted/stored Event with valid id and session_id.

    Returns:
        The created Alert if created, else None.
    """
    if event.id is None:
        return None

    tags = event.tags or []
    has_secret = any("secret" in str(t).lower() for t in tags)
    if event.risk_score >= 5.0 or has_secret:
        alert_type = "secret_leak" if has_secret else "high_risk_event"
        alert = Alert(
            event_id=event.id,
            session_id=event.session_id,
            alert_type=alert_type,
            description=f"{event.event_type} (risk {event.risk_score}) on {event.source_path or '-'}",
        )
        return store.create_alert(alert)
    return None
