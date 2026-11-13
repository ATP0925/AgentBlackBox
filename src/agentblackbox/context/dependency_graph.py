"""Multi-file dependency graph and symbol call-radius analyzer."""

from pathlib import Path
from typing import Dict, List, Optional, Set

from agentblackbox.context.ast_parser import parse_python_source
from agentblackbox.models.context import CodeContext, FileContext, Symbol


class DependencyGraph:
    """Builds and queries cross-file import and call dependencies across a codebase."""

    def __init__(
        self,
        root_dir: Optional[Path] = None,
        repo_root: Optional[Path] = None,
    ) -> None:
        target = repo_root or root_dir or Path.cwd()
        self.root_dir = target.resolve()
        self.file_contexts: Dict[str, FileContext] = {}
        self.module_to_file: Dict[str, str] = {}
        self.dependencies: Dict[str, Set[str]] = {}   # file -> set of files it imports
        self.dependents: Dict[str, Set[str]] = {}     # file -> set of files that import it
        self.symbol_index: Dict[str, Symbol] = {}    # symbol_name -> Symbol

    def index_source(self, file_path: str, code: str) -> FileContext:
        """Parse and index a single source file in the dependency graph."""
        norm_path = file_path.replace("\\", "/")
        ctx = parse_python_source(code, file_path=norm_path)
        self.file_contexts[norm_path] = ctx

        # Map module dots to relative path (e.g., foo.bar -> foo/bar.py)
        mod_name = norm_path.removesuffix(".py").replace("/", ".")
        self.module_to_file[mod_name] = norm_path

        for sym in ctx.symbols:
            self.symbol_index[sym.name] = sym
            self.symbol_index[f"{norm_path}:{sym.name}"] = sym

        return ctx

    def index_directory(self, directory: Optional[Path] = None, glob_pattern: str = "**/*.py") -> None:
        """Recursively index all Python source files in the target directory."""
        target_dir = directory.resolve() if directory else self.root_dir
        if not target_dir.is_dir():
            return

        for p in target_dir.glob(glob_pattern):
            if any(part in (".git", "__pycache__", ".venv", "venv", ".pytest_cache", "build", "dist") for part in p.parts):
                continue
            if p.is_file():
                try:
                    rel_path = str(p.relative_to(self.root_dir)).replace("\\", "/")
                    content = p.read_text(encoding="utf-8", errors="replace")
                    self.index_source(rel_path, content)
                except (OSError, UnicodeDecodeError):
                    continue

        self.rebuild_edges()

    def rebuild_edges(self) -> None:
        """Resolve import references into graph edges between files."""
        self.dependencies.clear()
        self.dependents.clear()

        for path in self.file_contexts:
            self.dependencies[path] = set()
            self.dependents[path] = set()

        for source_path, ctx in self.file_contexts.items():
            for imp in ctx.imports:
                target_file = self._resolve_import_to_file(imp, source_path)
                if target_file and target_file in self.file_contexts and target_file != source_path:
                    self.dependencies[source_path].add(target_file)
                    self.dependents[target_file].add(source_path)

    def _resolve_import_to_file(self, module_name: str, from_path: str) -> Optional[str]:
        """Resolve a Python import string to a relative file path in the indexed project."""
        # Exact module match
        if module_name in self.module_to_file:
            return self.module_to_file[module_name]

        # Suffix matching (e.g. import "agentblackbox.storage.event_store")
        for mod, fpath in self.module_to_file.items():
            if mod.endswith(module_name) or module_name.endswith(mod):
                return fpath

        # Relative sibling check
        from_dir = Path(from_path).parent
        sibling = (from_dir / f"{module_name}.py").as_posix()
        if sibling in self.file_contexts:
            return sibling

        return None

    def get_impact_radius(self, changed_files: List[str], max_depth: int = 2) -> Set[str]:
        """Find all files affected by changes in changed_files up to max_depth."""
        impacted: Set[str] = set()
        queue: List[tuple[str, int]] = [(f.replace("\\", "/"), 0) for f in changed_files]
        visited: Set[str] = set()

        while queue:
            curr_file, depth = queue.pop(0)
            if curr_file in visited:
                continue
            visited.add(curr_file)
            impacted.add(curr_file)

            if depth < max_depth:
                # Direct dependents (files that import this changed file)
                for dep in self.dependents.get(curr_file, set()):
                    if dep not in visited:
                        queue.append((dep, depth + 1))

        return impacted

    def build_code_context(self, target_files: List[str]) -> CodeContext:
        """Assemble a cohesive CodeContext bundle containing target files and dependencies."""
        impacted = self.get_impact_radius(target_files, max_depth=1)
        sub_files = {p: self.file_contexts[p] for p in impacted if p in self.file_contexts}
        sub_deps = {p: list(self.dependencies.get(p, set())) for p in impacted}
        sub_dependents = {p: list(self.dependents.get(p, set())) for p in impacted}

        return CodeContext(
            target_files=[f.replace("\\", "/") for f in target_files],
            files=sub_files,
            dependencies=sub_deps,
            dependents=sub_dependents,
            relevance_scores={p: 1.0 if p in target_files else 0.6 for p in impacted},
            symbol_index={k: v for k, v in self.symbol_index.items() if v.file_path in impacted},
        )
