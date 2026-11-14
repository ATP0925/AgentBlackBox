"""Real-Time Architectural Drift Detection.

Enforces module layer boundaries, public signature contracts, and anti-god-module
rules against an architectural contract (.agentblackbox/architecture.json).
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from agentblackbox.storage.blob_store import BlobStore
from agentblackbox.storage.models import Severity

DEFAULT_ARCHITECTURE_CONFIG: Dict[str, Any] = {
    "version": "1.0",
    "layers": {
        "storage": {
            "forbidden_imports": ["cli", "watchers", "daemon", "api"],
            "description": "Storage layer must remain decoupled from presentation, daemon, and watchers."
        },
        "analysis": {
            "forbidden_imports": ["cli", "daemon", "watchers", "api"],
            "description": "Analysis algorithms must remain pure and free of CLI and daemon state."
        },
        "core": {
            "forbidden_imports": ["cli", "api"],
            "description": "Core domain logic must not depend directly on outer CLI or HTTP layers."
        },
        "watchers": {
            "forbidden_imports": ["cli"],
            "description": "Watchers and collectors must not depend on CLI commands."
        }
    },
    "max_function_lines": 80,
    "max_cyclomatic_complexity": 15,
}


@dataclass
class DriftViolation:
    """Represents an architectural boundary or signature contract violation."""

    rule_code: str
    source_module: str
    imported_module: Optional[str]
    line: int
    col: int
    description: str
    severity: str
    breaking_change_diff: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ArchitecturalDriftDetector:
    """Enforces architectural boundaries and signature stability."""

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        config_path: Optional[Path] = None,
        blob_store: Optional[BlobStore] = None,
    ) -> None:
        self.workspace_root = workspace_root or Path.cwd()
        self.config_path = config_path or (self.workspace_root / ".agentblackbox" / "architecture.json")
        self.blob_store = blob_store
        self.config = self._load_or_create_config()

    def _load_or_create_config(self) -> Dict[str, Any]:
        if self.config_path.exists():
            try:
                return json.loads(self.config_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        # Auto-generate sensible default config
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(json.dumps(DEFAULT_ARCHITECTURE_CONFIG, indent=2), encoding="utf-8")
        except Exception:
            pass
        return DEFAULT_ARCHITECTURE_CONFIG

    def check_file(
        self,
        file_path: Union[str, Path],
        content: Optional[str] = None,
        prev_blob_hash: Optional[str] = None,
        prev_content: Optional[str] = None,
    ) -> List[DriftViolation]:
        """Audit a file for layer import violations, signature drift, and complexity."""
        violations: List[DriftViolation] = []
        path_obj = Path(file_path)
        source_name = str(file_path).replace("\\", "/")

        if content is None:
            if not path_obj.exists():
                return violations
            try:
                content = path_obj.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return violations

        if not str(file_path).endswith(".py"):
            return violations

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return violations

        # 1. Layer boundary enforcement
        violations.extend(self.check_layer_imports(source_name, tree))

        # 2. Function complexity and god-module checks
        violations.extend(self.check_complexity(source_name, tree))

        # 3. Signature & contract drift against previous blob
        old_text = prev_content
        if old_text is None and prev_blob_hash and self.blob_store:
            old_text = self.blob_store.get_text(prev_blob_hash)

        if old_text:
            try:
                old_tree = ast.parse(old_text)
                violations.extend(self.check_signature_drift(source_name, tree, old_tree))
            except SyntaxError:
                pass

        return violations

    def check_layer_imports(self, source_path: str, tree: ast.AST) -> List[DriftViolation]:
        """Detect forbidden imports based on architectural layers."""
        violations: List[DriftViolation] = []
        layers_cfg = self.config.get("layers", {})

        current_layer: Optional[str] = None
        for layer_name in layers_cfg:
            if f"/{layer_name}/" in f"/{source_path}" or f"\\{layer_name}\\" in f"\\{source_path}":
                current_layer = layer_name
                break

        if not current_layer:
            return violations

        forbidden = set(layers_cfg[current_layer].get("forbidden_imports", []))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    # Check if importing from forbidden layer
                    for part in parts:
                        if part in forbidden:
                            violations.append(
                                DriftViolation(
                                    rule_code=f"DRIFT-LAYER-{current_layer.upper()}",
                                    source_module=source_path,
                                    imported_module=alias.name,
                                    line=node.lineno,
                                    col=node.col_offset,
                                    description=(
                                        f"Layer isolation breach: Layer '{current_layer}' is forbidden from "
                                        f"importing '{alias.name}' ({layers_cfg[current_layer].get('description', '')})."
                                    ),
                                    severity=Severity.HIGH,
                                )
                            )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    parts = node.module.split(".")
                    for part in parts:
                        if part in forbidden:
                            violations.append(
                                DriftViolation(
                                    rule_code=f"DRIFT-LAYER-{current_layer.upper()}",
                                    source_module=source_path,
                                    imported_module=node.module,
                                    line=node.lineno,
                                    col=node.col_offset,
                                    description=(
                                        f"Layer isolation breach: Layer '{current_layer}' is forbidden from "
                                        f"importing from '{node.module}' ({layers_cfg[current_layer].get('description', '')})."
                                    ),
                                    severity=Severity.HIGH,
                                )
                            )

        return violations

    def check_signature_drift(
        self,
        source_path: str,
        new_tree: ast.AST,
        old_tree: ast.AST,
    ) -> List[DriftViolation]:
        """Compare public function and method signatures against previous version."""
        violations: List[DriftViolation] = []

        old_funcs = self._extract_public_signatures(old_tree)
        new_funcs = self._extract_public_signatures(new_tree)

        for name, old_sig in old_funcs.items():
            if name not in new_funcs:
                violations.append(
                    DriftViolation(
                        rule_code="DRIFT-SIG-REMOVED",
                        source_module=source_path,
                        imported_module=None,
                        line=old_sig.get("line", 1),
                        col=0,
                        description=f"Breaking change: Public function or method '{name}' was removed without deprecation.",
                        severity=Severity.HIGH,
                        breaking_change_diff=f"- def {name}({', '.join(old_sig.get('params', []))})",
                    )
                )
            else:
                new_sig = new_funcs[name]
                old_req = old_sig.get("required_params", [])
                new_req = new_sig.get("required_params", [])

                # If new signature requires parameters not present in old signature
                new_added_required = [p for p in new_req if p not in old_req]
                if new_added_required:
                    violations.append(
                        DriftViolation(
                            rule_code="DRIFT-SIG-BREAK",
                            source_module=source_path,
                            imported_module=None,
                            line=new_sig.get("line", 1),
                            col=0,
                            description=(
                                f"Breaking signature change in '{name}': New required parameter(s) "
                                f"{new_added_required} break existing callers."
                            ),
                            severity=Severity.HIGH,
                            breaking_change_diff=(
                                f"Required params: [{', '.join(old_req)}] -> [{', '.join(new_req)}]"
                            ),
                        )
                    )

        # Check __all__ contract drift
        old_all = self._extract_dunder_all(old_tree)
        new_all = self._extract_dunder_all(new_tree)
        if old_all and new_all is not None:
            removed_exports = old_all - new_all
            if removed_exports:
                violations.append(
                    DriftViolation(
                        rule_code="DRIFT-ALL-REMOVED",
                        source_module=source_path,
                        imported_module=None,
                        line=1,
                        col=0,
                        description=f"Breaking change: Exported symbols {sorted(removed_exports)} removed from __all__.",
                        severity=Severity.HIGH,
                        breaking_change_diff=f"Removed from __all__: {sorted(removed_exports)}",
                    )
                )

        return violations

    def check_complexity(self, source_path: str, tree: ast.AST) -> List[DriftViolation]:
        """Detect god-functions and extreme cyclomatic complexity."""
        violations: List[DriftViolation] = []
        max_lines = self.config.get("max_function_lines", 80)
        max_complexity = self.config.get("max_cyclomatic_complexity", 15)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = (node.end_lineno or node.lineno) - node.lineno + 1
                if length > max_lines:
                    violations.append(
                        DriftViolation(
                            rule_code="DRIFT-GOD-FUNCTION",
                            source_module=source_path,
                            imported_module=None,
                            line=node.lineno,
                            col=node.col_offset,
                            description=f"Function '{node.name}' spans {length} lines (threshold: {max_lines}).",
                            severity=Severity.MEDIUM,
                        )
                    )

                complexity = self._calculate_complexity(node)
                if complexity > max_complexity:
                    violations.append(
                        DriftViolation(
                            rule_code="DRIFT-CYCLOMATIC",
                            source_module=source_path,
                            imported_module=None,
                            line=node.lineno,
                            col=node.col_offset,
                            description=f"Function '{node.name}' cyclomatic complexity is {complexity} (threshold: {max_complexity}).",
                            severity=Severity.MEDIUM,
                        )
                    )

        return violations

    def _extract_public_signatures(self, tree: ast.AST) -> Dict[str, Dict[str, Any]]:
        signatures: Dict[str, Dict[str, Any]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    all_params = [a.arg for a in node.args.args if a.arg != "self"]
                    num_defaults = len(node.args.defaults)
                    required_params = all_params[:-num_defaults] if num_defaults > 0 else all_params
                    signatures[node.name] = {
                        "name": node.name,
                        "line": node.lineno,
                        "params": all_params,
                        "required_params": required_params,
                    }
        return signatures

    def _extract_dunder_all(self, tree: ast.AST) -> Optional[Set[str]]:
        for node in tree.body if hasattr(tree, "body") else []:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                            exports = set()
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    exports.add(elt.value)
                            return exports
        return None

    def _calculate_complexity(self, node: ast.AST) -> int:
        score = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.AsyncWith)):
                score += 1
            elif isinstance(child, ast.BoolOp):
                score += len(child.values) - 1
        return score
