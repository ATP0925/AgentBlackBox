"""Base interface for deterministic static scanners."""

from abc import ABC, abstractmethod
from typing import List, Optional

from agentblackbox.models.context import FileContext
from agentblackbox.models.finding import Finding


class BaseScanner(ABC):
    """Abstract scanner interface for deterministic rule-based checks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner."""
        ...

    @abstractmethod
    def scan_file(
        self,
        file_path: str,
        content: str,
        file_ctx: Optional[FileContext] = None,
    ) -> List[Finding]:
        """Scan a file content or AST context and return identified findings.

        Args:
            file_path: Path of the target file.
            content: Raw source code string.
            file_ctx: Optional pre-parsed FileContext.

        Returns:
            List of Finding objects identified in this file.
        """
        ...

    def scan_source(
        self,
        content: str,
        file_path: str,
        file_ctx: Optional[FileContext] = None,
    ) -> List[Finding]:
        """Convenience method scanning source code string directly."""
        return self.scan_file(file_path=file_path, content=content, file_ctx=file_ctx)
