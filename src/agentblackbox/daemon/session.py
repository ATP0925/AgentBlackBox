"""Session lifecycle manager."""

from pathlib import Path
from typing import Optional

import structlog

from agentblackbox.daemon.config import BlackBoxConfig
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Session

logger = structlog.get_logger()


class SessionManager:
    """Manages recording sessions — create, get current, stop.

    Args:
        config: BlackBox configuration.
        store: Event store instance.
    """

    def __init__(self, config: BlackBoxConfig, store: EventStore) -> None:
        self.config = config
        self.store = store
        self._current_session: Optional[Session] = None

    def start(self, name: Optional[str] = None, agent_hint: Optional[str] = None) -> Session:
        """Start a new recording session.

        Args:
            name: Optional human-readable name.
            agent_hint: Optional agent identifier (e.g., "cursor", "claude-code").

        Returns:
            The newly created Session.

        Raises:
            RuntimeError: If a session is already recording.
        """
        if self._current_session and self._current_session.status == "recording":
            raise RuntimeError(
                f"Session {self._current_session.id} is already recording. "
                "Stop it first with `abb stop`."
            )

        session = Session(
            workspace_path=str(self.config.workspace_path),
            name=name,
            agent_hint=agent_hint,
        )
        self.store.create_session(session)
        self._current_session = session
        logger.info("session_started", session_id=session.id, workspace=session.workspace_path)
        return session

    def stop(self) -> Optional[Session]:
        """Stop the current recording session.

        Returns:
            The stopped Session, or None if no session was active.
        """
        if not self._current_session:
            logger.warning("no_active_session")
            return None
        self.store.stop_session(self._current_session.id)
        self._current_session.stop()
        logger.info("session_stopped", session_id=self._current_session.id)
        stopped = self._current_session
        self._current_session = None
        return stopped

    @property
    def current(self) -> Optional[Session]:
        """Get the currently active session."""
        return self._current_session

    @property
    def is_recording(self) -> bool:
        """Check if a session is actively recording."""
        return (
            self._current_session is not None
            and self._current_session.status == "recording"
        )

