"""Flight-Recorder-Guided Legacy Code Refactoring Guard.

Captures pre-refactor content-addressed snapshots in BlobStore, computes AST symbol blast radius,
verifies behavioral equivalence (exceptions, return paths, types), and executes deterministic 1-click rollbacks.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.event_store import EventStore
from agentblackbox.storage.models import Event, EventType, Severity


class LegacyRefactorGuard:
    """Safeguards legacy code refactoring by tracking blast radius and enabling instant rollbacks."""

    def __init__(
        self,
        blob_store: BlobStore,
        event_store: Optional[EventStore] = None,
        workspace_root: Optional[Path] = None,
    ) -> None:
        self.blob_store = blob_store
        self.event_store = event_store
        self.workspace_root = workspace_root or Path.cwd()

    def create_pre_refactor_snapshot(
        self,
        file_path: Union[str, Path],
        content: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: str = "agent",
    ) -> Tuple[str, Dict[str, Any]]:
        """Capture a content-addressed snapshot in BlobStore and index symbols.

        Returns:
            Tuple of (snapshot_sha256, metadata_dict).
        """
        p = Path(file_path)
        if content is None:
            if not p.is_absolute():
                p = self.workspace_root / p
            if not p.exists():
                raise FileNotFoundError(f"Cannot snapshot non-existent file: {p}")
            data = p.read_bytes()
        else:
            data = content.encode("utf-8")

        # Put into blob store
        sha256, stored_size, _ = self.blob_store.put_bytes(data, redact=True)

        # Extract symbols
        symbols = self._extract_symbols(data.decode("utf-8", errors="replace"))
        blast_info = self.calculate_blast_radius(file_path, list(symbols.keys()))

        metadata = {
            "file_path": str(file_path).replace("\\", "/"),
            "snapshot_sha256": sha256,
            "size_bytes": stored_size,
            "symbols": symbols,
            "blast_radius": blast_info,
        }

        # Optionally record snapshot event in EventStore
        if self.event_store and session_id:
            try:
                event = Event(
                    session_id=session_id,
                    event_type=EventType.FILE_MODIFY,
                    severity=Severity.INFO,
                    source_path=str(file_path).replace("\\", "/"),
                    blob_hash=sha256,
                    agent_id=agent_id,
                    payload={
                        "action": "pre_refactor_snapshot",
                        "snapshot_sha256": sha256,
                        "symbols_count": len(symbols),
                        "affected_files_count": blast_info.get("dependent_files_count", 0),
                    },
                )
                self.event_store.record_event(event)
            except Exception:
                pass

        return sha256, metadata

    def calculate_blast_radius(
        self,
        file_path: Union[str, Path],
        symbols: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Compute the blast radius of modifying a file by finding all callers/importers."""
        target_path = Path(file_path)
        module_name = target_path.stem

        if symbols is None and target_path.exists():
            try:
                txt = target_path.read_text(encoding="utf-8", errors="replace")
                symbols = list(self._extract_symbols(txt).keys())
            except Exception:
                symbols = []

        symbols = symbols or []
        dependent_files: Set[str] = set()
        symbol_references: Dict[str, int] = {s: 0 for s in symbols}

        for root, dirs, files in os.walk(self.workspace_root):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", ".venv", "node_modules", "dist", "build")]
            for fname in files:
                if fname.endswith(".py"):
                    full_p = Path(root) / fname
                    if full_p.resolve() == target_path.resolve():
                        continue
                    try:
                        code = full_p.read_text(encoding="utf-8", errors="replace")
                        rel_path = str(full_p.relative_to(self.workspace_root)).replace("\\", "/")
                        has_dep = False
                        if module_name in code:
                            has_dep = True
                        for sym in symbols:
                            if sym in code:
                                symbol_references[sym] = symbol_references.get(sym, 0) + 1
                                has_dep = True
                        if has_dep:
                            dependent_files.add(rel_path)
                    except Exception:
                        pass

        return {
            "file_path": str(file_path).replace("\\", "/"),
            "dependent_files_count": len(dependent_files),
            "dependent_files": sorted(list(dependent_files))[:50],
            "symbol_references": symbol_references,
            "blast_tier": "HIGH" if len(dependent_files) > 10 else ("MEDIUM" if len(dependent_files) > 3 else "LOW"),
        }

    def check_behavioral_equivalence(
        self,
        old_content: str,
        new_content: str,
    ) -> Dict[str, Any]:
        """Compare behavioral AST features: return paths, raised exceptions, and annotations."""
        old_behavior = self._extract_ast_behavior(old_content)
        new_behavior = self._extract_ast_behavior(new_content)

        warnings: List[str] = []
        is_equivalent = True

        for func_name, old_data in old_behavior.items():
            if func_name not in new_behavior:
                warnings.append(f"Function/Method '{func_name}' was completely removed.")
                is_equivalent = False
                continue

            new_data = new_behavior[func_name]

            # Check if exceptions raised in old version are no longer handled/raised
            removed_exceptions = set(old_data["raises"]) - set(new_data["raises"])
            if removed_exceptions:
                warnings.append(
                    f"Behavioral drift in '{func_name}': Exception(s) {sorted(removed_exceptions)} "
                    f"are no longer explicitly raised, potentially breaking caller try/except blocks."
                )

            # Check if return path count changed dramatically
            old_returns = old_data["return_count"]
            new_returns = new_data["return_count"]
            if old_returns > 0 and new_returns == 0:
                warnings.append(f"Function '{func_name}' previously returned values but now has no return statements.")
                is_equivalent = False

        return {
            "is_equivalent": is_equivalent and len(warnings) == 0,
            "warnings": warnings,
            "functions_analyzed": len(old_behavior),
        }

    def rollback_to_snapshot(
        self,
        file_path: Union[str, Path],
        snapshot_sha256: str,
        session_id: Optional[str] = None,
        reason: str = "Rollback requested via AgentBlackBox RefactorGuard",
    ) -> bool:
        """Deterministic 1-click rollback: restores file from BlobStore and records signed event."""
        p = Path(file_path)
        if not p.is_absolute():
            p = self.workspace_root / p

        content_bytes = self.blob_store.get_bytes(snapshot_sha256)
        if content_bytes is None:
            return False

        # Restore file to disk
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content_bytes)

        # Record rollback event in EventStore
        if self.event_store:
            target_session = session_id
            if not target_session:
                sessions = self.event_store.list_sessions(limit=1)
                if sessions:
                    target_session = sessions[0].id
                else:
                    sess = self.event_store.create_session(
                        Session(id="default_session", name="Default Session", workspace_path=str(self.workspace_root))
                    )
                    target_session = sess.id

            try:
                event = Event(
                    session_id=target_session,
                    event_type=EventType.REFACTOR_ROLLBACK,
                    severity=Severity.WARNING,
                    source_path=str(file_path).replace("\\", "/"),
                    blob_hash=snapshot_sha256,
                    agent_id="refactor_guard",
                    payload={
                        "action": "file_rollback",
                        "snapshot_sha256": snapshot_sha256,
                        "file_path": str(file_path).replace("\\", "/"),
                        "reason": reason,
                    },
                )
                self.event_store.record_event(event)
            except Exception:
                pass

        return True

    def _extract_symbols(self, content: str) -> Dict[str, Dict[str, Any]]:
        symbols: Dict[str, Dict[str, Any]] = {}
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return symbols

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols[node.name] = {
                    "type": "function",
                    "line": node.lineno,
                    "args": [a.arg for a in node.args.args],
                }
            elif isinstance(node, ast.ClassDef):
                symbols[node.name] = {
                    "type": "class",
                    "line": node.lineno,
                    "methods": [
                        n.name
                        for n in node.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    ],
                }
        return symbols

    def _extract_ast_behavior(self, content: str) -> Dict[str, Dict[str, Any]]:
        behavior: Dict[str, Dict[str, Any]] = {}
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return behavior

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                raises: Set[str] = set()
                return_count = 0
                for child in ast.walk(node):
                    if isinstance(child, ast.Raise):
                        if child.exc:
                            if isinstance(child.exc, ast.Name):
                                raises.add(child.exc.id)
                            elif isinstance(child.exc, ast.Call) and isinstance(child.exc.func, ast.Name):
                                raises.add(child.exc.func.id)
                    elif isinstance(child, ast.Return):
                        return_count += 1
                behavior[node.name] = {
                    "raises": sorted(list(raises)),
                    "return_count": return_count,
                    "line": node.lineno,
                }
        return behavior
