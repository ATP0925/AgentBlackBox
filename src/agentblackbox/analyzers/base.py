"""Base interface for high-level code analyzers."""

from abc import ABC, abstractmethod
from typing import List, Optional

from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding


class BaseAnalyzer(ABC):
    """Abstract interface for extensible domain-specific code analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        ...

    @abstractmethod
    def analyze(
        self,
        code_context: CodeContext,
        target_diff: Optional[GitDiff] = None,
    ) -> List[Finding]:
        """Analyze code context and/or target git diff and yield findings.

        Args:
            code_context: Multi-file code context and symbol index.
            target_diff: Optional Git diff for incremental pull request review.

        Returns:
            List of prioritized Finding instances.
        """
        ...
