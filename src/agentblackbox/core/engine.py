"""Core analysis engine orchestrating scanners, analyzers, context pruners, and AI providers."""

import fnmatch
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import structlog

from agentblackbox.analyzers.base import BaseAnalyzer
from agentblackbox.analyzers.bugs import BugAnalyzer
from agentblackbox.analyzers.duplication import DuplicationAnalyzer
from agentblackbox.analyzers.performance import PerformanceAnalyzer
from agentblackbox.analyzers.quality import QualityAnalyzer
from agentblackbox.analyzers.security import SecurityAnalyzer
from agentblackbox.context.dependency_graph import DependencyGraph
from agentblackbox.context.pruner import ContextPruner
from agentblackbox.core.config import ReviewConfig
from agentblackbox.integrations.ai_provider import BaseAIProvider, get_ai_provider
from agentblackbox.integrations.git_client import GitClient
from agentblackbox.integrations.prompt_builder import (
    build_diff_review_prompt,
    build_file_review_prompt,
    build_system_prompt,
)
from agentblackbox.models.context import CodeContext
from agentblackbox.models.diff import GitDiff
from agentblackbox.models.finding import Finding, Severity
from agentblackbox.models.report import ReviewReport
from agentblackbox.scanners.ast_scanner import ASTScanner
from agentblackbox.scanners.base import BaseScanner
from agentblackbox.scanners.pattern_scanner import PatternScanner

logger = structlog.get_logger(__name__)


class ReviewEngine:
    """Orchestrates deterministic static scanning and AI-assisted deep code review."""

    def __init__(
        self,
        config: Optional[ReviewConfig] = None,
        ai_provider: Optional[BaseAIProvider] = None,
        git_client: Optional[GitClient] = None,
    ):
        self.config = config or ReviewConfig()
        self.git_client = git_client or GitClient()

        # Deterministic Scanners
        self.scanners: List[BaseScanner] = [
            ASTScanner(),
            PatternScanner(),
        ]

        # Semantic Domain Analyzers
        self.analyzers: List[BaseAnalyzer] = [
            BugAnalyzer(),
            SecurityAnalyzer(),
            QualityAnalyzer(),
            PerformanceAnalyzer(),
            DuplicationAnalyzer(),
        ]

        # AI Provider (lazy or injected)
        if ai_provider is not None:
            self.ai_provider = ai_provider
        elif self.config.enable_ai:
            self.ai_provider = get_ai_provider(
                provider_name=self.config.ai_provider,
                model=self.config.ai_model,
            )
        else:
            self.ai_provider = None

    def _should_ignore_file(self, file_path: str) -> bool:
        """Check if file path matches configured ignore patterns."""
        norm_path = file_path.replace("\\", "/")
        parts = norm_path.split("/")
        for pattern in self.config.ignore_paths:
            for part in parts:
                if fnmatch.fnmatch(part, pattern):
                    return True
            if fnmatch.fnmatch(norm_path, pattern):
                return True
        return False

    def _filter_and_sort_findings(
        self,
        findings: List[Finding],
    ) -> List[Finding]:
        """Deduplicate findings, filter by minimum severity, and sort by priority."""
        seen: Set[Tuple[str, int, str]] = set()
        deduped: List[Finding] = []

        for f in findings:
            # Severity threshold check
            if f.severity.level < self.config.min_severity.level:
                continue

            # Rule filters check
            if self.config.rule_filters and f.rule_id not in self.config.rule_filters:
                continue

            dedup_key = (f.file_path.replace("\\", "/"), f.line_start, f.rule_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            deduped.append(f)

        # Sort: highest severity first (5 down to 1), then file path, then line number
        deduped.sort(key=lambda x: (-x.severity.level, x.file_path, x.line_start))
        return deduped

    def review_diff(
        self,
        git_diff: GitDiff,
        repo_root: Optional[Path] = None,
    ) -> ReviewReport:
        """Review code changes represented by a unified GitDiff."""
        start_time = time.perf_counter()
        repo_root = repo_root or self.git_client.repo_path

        # Identify changed files (excluding deleted files)
        target_files = [
            f.new_path
            for f in git_diff.files
            if f.new_path and f.new_path != "/dev/null" and not self._should_ignore_file(f.new_path)
        ]

        # Build dependency graph and index repository context
        graph = DependencyGraph(repo_root=repo_root)
        for rel_path in target_files:
            abs_p = repo_root / rel_path
            if abs_p.is_file():
                try:
                    content = abs_p.read_text(encoding="utf-8", errors="replace")
                    graph.index_source(rel_path, content)
                except Exception:
                    continue

        code_ctx = graph.build_code_context(target_files)

        all_findings: List[Finding] = []

        # 1. Run deterministic scanners
        for file_path, f_ctx in code_ctx.files.items():
            if not f_ctx.raw_source:
                continue
            for scanner in self.scanners:
                try:
                    all_findings.extend(scanner.scan_source(f_ctx.raw_source, file_path))
                except Exception as exc:
                    logger.warning(
                        "scanner_execution_failed",
                        scanner=getattr(scanner, "name", str(scanner)),
                        file=file_path,
                        error=str(exc),
                    )

        # 2. Run domain analyzers
        for analyzer in self.analyzers:
            try:
                all_findings.extend(analyzer.analyze(code_ctx, target_diff=git_diff))
            except Exception as exc:
                logger.warning(
                    "analyzer_execution_failed",
                    analyzer=getattr(analyzer, "name", str(analyzer)),
                    error=str(exc),
                )

        # 3. Attribute findings to diff hunks
        for f in all_findings:
            fdiff = git_diff.get_file(f.file_path)
            if fdiff:
                for hunk in fdiff.hunks:
                    if hunk.contains_line(f.line_start):
                        f.metadata["in_diff"] = True
                        if not f.diff_hunk:
                            f.diff_hunk = hunk.header
                        break

        # 4. Run AI reasoning layer (if enabled)
        ai_summary = ""
        model_name = None
        if self.ai_provider is not None:
            pruner = ContextPruner(max_tokens=self.config.max_context_tokens)
            context_summary = pruner.assemble_review_context(code_ctx, target_diff=git_diff, target_files=target_files)
            system_prompt = build_system_prompt()
            user_prompt = build_diff_review_prompt(
                diff_text=git_diff.raw_diff,
                context_summary=context_summary,
                scanner_findings=all_findings[:10],
            )
            try:
                ai_summary, ai_findings = self.ai_provider.generate_review(
                    system_prompt,
                    user_prompt,
                    default_file=target_files[0] if target_files else "app.py",
                )
                all_findings.extend(ai_findings)
                model_name = getattr(self.ai_provider, "model", self.ai_provider.__class__.__name__)
            except Exception:
                ai_summary = "AI review skipped due to provider execution failure."

        final_findings = self._filter_and_sort_findings(all_findings)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ReviewReport(
            target="git-diff",
            findings=final_findings,
            analyzed_files=target_files,
            execution_time_ms=elapsed_ms,
            model_name=model_name,
            metadata={"ai_summary": ai_summary} if ai_summary else {},
        )

    def analyze_repository(
        self,
        repo_path: Optional[Path] = None,
        files: Optional[List[str]] = None,
    ) -> ReviewReport:
        """Analyze an entire repository or specified file list."""
        start_time = time.perf_counter()
        target_dir = repo_path or Path.cwd()

        # Collect files
        target_files: List[str] = []
        if files:
            target_files = [f for f in files if not self._should_ignore_file(f)]
        else:
            for root, dirs, filenames in os.walk(target_dir):
                dirs[:] = [d for d in dirs if not self._should_ignore_file(d)]
                for fname in filenames:
                    if fname.endswith(".py"):
                        full_p = Path(root) / fname
                        try:
                            rel_p = str(full_p.relative_to(target_dir)).replace("\\", "/")
                        except ValueError:
                            rel_p = str(full_p).replace("\\", "/")
                        if not self._should_ignore_file(rel_p):
                            target_files.append(rel_p)

        # Index into dependency graph
        graph = DependencyGraph(repo_root=target_dir)
        for rel_path in target_files:
            abs_p = target_dir / rel_path
            if abs_p.is_file():
                try:
                    content = abs_p.read_text(encoding="utf-8", errors="replace")
                    graph.index_source(rel_path, content)
                except Exception:
                    continue

        code_ctx = graph.build_code_context(target_files)

        all_findings: List[Finding] = []

        # 1. Scanners
        for file_path, f_ctx in code_ctx.files.items():
            if not f_ctx.raw_source:
                continue
            for scanner in self.scanners:
                try:
                    all_findings.extend(scanner.scan_source(f_ctx.raw_source, file_path))
                except Exception as exc:
                    logger.warning(
                        "scanner_execution_failed",
                        scanner=getattr(scanner, "name", str(scanner)),
                        file=file_path,
                        error=str(exc),
                    )

        # 2. Analyzers
        for analyzer in self.analyzers:
            try:
                all_findings.extend(analyzer.analyze(code_ctx))
            except Exception as exc:
                logger.warning(
                    "analyzer_execution_failed",
                    analyzer=getattr(analyzer, "name", str(analyzer)),
                    error=str(exc),
                )

        # 3. AI provider (optional)
        ai_summary = ""
        model_name = None
        if self.ai_provider is not None and target_files:
            pruner = ContextPruner(max_tokens=self.config.max_context_tokens)
            context_summary = pruner.assemble_review_context(code_ctx, target_files=target_files[:5])
            sample_file = target_files[0]
            sample_content = code_ctx.files[sample_file].raw_source if sample_file in code_ctx.files else ""
            system_prompt = build_system_prompt()
            user_prompt = build_file_review_prompt(
                file_path=sample_file,
                source_code=sample_content,
                context_summary=context_summary,
                scanner_findings=all_findings[:10],
            )
            try:
                ai_summary, ai_findings = self.ai_provider.generate_review(
                    system_prompt,
                    user_prompt,
                    default_file=sample_file,
                )
                all_findings.extend(ai_findings)
                model_name = getattr(self.ai_provider, "model", self.ai_provider.__class__.__name__)
            except Exception:
                ai_summary = "AI review skipped."

        final_findings = self._filter_and_sort_findings(all_findings)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ReviewReport(
            target=str(target_dir),
            findings=final_findings,
            analyzed_files=target_files,
            execution_time_ms=elapsed_ms,
            model_name=model_name,
            metadata={"ai_summary": ai_summary} if ai_summary else {},
        )

    def analyze_file(self, file_path: Path) -> ReviewReport:
        """Analyze a single file directly."""
        start_time = time.perf_counter()
        abs_path = file_path.resolve()
        if not abs_path.is_file():
            raise FileNotFoundError(f"File not found: {abs_path}")

        content = abs_path.read_text(encoding="utf-8", errors="replace")
        rel_path = file_path.name

        graph = DependencyGraph()
        graph.index_source(rel_path, content)
        code_ctx = graph.build_code_context([rel_path])

        all_findings: List[Finding] = []

        # Scanners
        for scanner in self.scanners:
            try:
                all_findings.extend(scanner.scan_source(content, rel_path))
            except Exception as exc:
                logger.warning(
                    "scanner_execution_failed",
                    scanner=getattr(scanner, "name", str(scanner)),
                    file=rel_path,
                    error=str(exc),
                )

        # Analyzers
        for analyzer in self.analyzers:
            try:
                all_findings.extend(analyzer.analyze(code_ctx))
            except Exception as exc:
                logger.warning(
                    "analyzer_execution_failed",
                    analyzer=getattr(analyzer, "name", str(analyzer)),
                    error=str(exc),
                )

        # AI reasoning
        ai_summary = ""
        model_name = None
        if self.ai_provider is not None:
            system_prompt = build_system_prompt()
            user_prompt = build_file_review_prompt(
                file_path=rel_path,
                source_code=content,
                scanner_findings=all_findings[:10],
            )
            try:
                ai_summary, ai_findings = self.ai_provider.generate_review(
                    system_prompt,
                    user_prompt,
                    default_file=rel_path,
                )
                all_findings.extend(ai_findings)
                model_name = getattr(self.ai_provider, "model", self.ai_provider.__class__.__name__)
            except Exception:
                ai_summary = "AI review skipped."

        final_findings = self._filter_and_sort_findings(all_findings)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ReviewReport(
            target=str(file_path),
            findings=final_findings,
            analyzed_files=[rel_path],
            execution_time_ms=elapsed_ms,
            model_name=model_name,
            metadata={"ai_summary": ai_summary} if ai_summary else {},
        )

