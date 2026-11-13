# src/agentblackbox/collectors/__init__.py
"""IDE and agent event collectors."""

from agentblackbox.collectors.ide_hooks import (
    NormalizedAgentEvent,
    UniversalIDECollector,
)

__all__ = ["NormalizedAgentEvent", "UniversalIDECollector"]

