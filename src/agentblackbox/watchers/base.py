"""Abstract base class for all watchers."""

from abc import ABC, abstractmethod
from typing import Callable, List

from agentblackbox.storage.models import Event


class BaseWatcher(ABC):
    """Base class that all watchers must inherit.

    Args:
        session_id: The active session ID.
        on_event: Callback invoked with each new Event.
    """

    def __init__(self, session_id: str, on_event: Callable[[Event], None]) -> None:
        self.session_id = session_id
        self.on_event = on_event
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """Begin watching. Must be non-blocking or run in a thread."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop watching and clean up resources."""
        ...

    @property
    def is_running(self) -> bool:
        """Whether this watcher is currently active."""
        return self._running

