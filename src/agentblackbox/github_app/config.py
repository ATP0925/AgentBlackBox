"""Repository Configuration Reader for AgentBlackBox GitHub App.

Loads `.agentblackbox.yaml` strictly from the base branch to prevent untrusted
PR authors from overriding security policies or suppressing reviews.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
import structlog

from agentblackbox.github_app.client import GitHubClient

logger = structlog.get_logger(__name__)

KNOWN_ROOT_KEYS: Set[str] = {"reviews", "paths", "custom_instructions", "scanners", "version"}
KNOWN_REVIEWS_KEYS: Set[str] = {"enabled", "draft_prs", "fail_on", "min_confidence", "max_comments", "language"}
KNOWN_SCANNERS_KEYS: Set[str] = {"security", "bugs", "drift", "perf", "compliance"}


@dataclass
class ReviewSettings:
    """Configurable settings for PR reviews."""
    enabled: bool = True
    draft_prs: bool = False
    fail_on: str = "high"  # critical, high, medium, low, none
    min_confidence: float = 0.5
    max_comments: int = 25
    language: str = "en"


@dataclass
class PathSettings:
    """Path inclusion and exclusion glob filters."""
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)


@dataclass
class ScannerSettings:
    """Toggles for individual scanner engines."""
    security: bool = True
    bugs: bool = True
    drift: bool = True
    perf: bool = True
    compliance: bool = True


@dataclass
class AgentBlackBoxConfig:
    """Top-level configuration loaded from repository base branch."""
    reviews: ReviewSettings = field(default_factory=ReviewSettings)
    paths: PathSettings = field(default_factory=PathSettings)
    custom_instructions: str = ""
    scanners: ScannerSettings = field(default_factory=ScannerSettings)
    warnings: List[str] = field(default_factory=list)


def parse_config_yaml(yaml_content: str) -> AgentBlackBoxConfig:
    """Parse and validate YAML configuration safely, tracking unknown keys."""
    warnings: List[str] = []
    if not yaml_content or not yaml_content.strip():
        return AgentBlackBoxConfig()

    try:
        data = yaml.safe_load(yaml_content)
    except Exception as exc:
        logger.warning("invalid_config_yaml", error=str(exc))
        return AgentBlackBoxConfig(warnings=[f"Failed to parse `.agentblackbox.yaml`: {exc}. Using default settings."])

    if not isinstance(data, dict):
        return AgentBlackBoxConfig(warnings=["`.agentblackbox.yaml` must be a YAML dictionary. Using default settings."])

    # Check unknown root keys
    for k in data.keys():
        if k not in KNOWN_ROOT_KEYS:
            warnings.append(f"Ignored unknown configuration key `{k}` in `.agentblackbox.yaml`.")

    # Parse reviews
    rev_raw = data.get("reviews", {})
    rev_settings = ReviewSettings()
    if isinstance(rev_raw, dict):
        for k in rev_raw.keys():
            if k not in KNOWN_REVIEWS_KEYS:
                warnings.append(f"Ignored unknown reviews setting `{k}`.")
        rev_settings.enabled = bool(rev_raw.get("enabled", True))
        rev_settings.draft_prs = bool(rev_raw.get("draft_prs", False))
        fail_on = str(rev_raw.get("fail_on", "high")).lower()
        rev_settings.fail_on = fail_on if fail_on in ("critical", "high", "medium", "low", "none") else "high"
        try:
            rev_settings.min_confidence = float(rev_raw.get("min_confidence", 0.5))
        except (ValueError, TypeError):
            rev_settings.min_confidence = 0.5
        try:
            rev_settings.max_comments = int(rev_raw.get("max_comments", 25))
        except (ValueError, TypeError):
            rev_settings.max_comments = 25
        rev_settings.language = str(rev_raw.get("language", "en"))

    # Parse paths
    paths_raw = data.get("paths", {})
    path_settings = PathSettings()
    if isinstance(paths_raw, dict):
        inc = paths_raw.get("include", [])
        exc_paths = paths_raw.get("exclude", [])
        path_settings.include = [str(x) for x in inc if isinstance(x, (str, int))] if isinstance(inc, list) else []
        path_settings.exclude = [str(x) for x in exc_paths if isinstance(x, (str, int))] if isinstance(exc_paths, list) else []

    # Parse scanners
    scan_raw = data.get("scanners", {})
    scan_settings = ScannerSettings()
    if isinstance(scan_raw, dict):
        for k in scan_raw.keys():
            if k not in KNOWN_SCANNERS_KEYS:
                warnings.append(f"Ignored unknown scanners setting `{k}`.")
        scan_settings.security = bool(scan_raw.get("security", True))
        scan_settings.bugs = bool(scan_raw.get("bugs", True))
        scan_settings.drift = bool(scan_raw.get("drift", True))
        scan_settings.perf = bool(scan_raw.get("perf", True))
        scan_settings.compliance = bool(scan_raw.get("compliance", True))

    custom_instr = str(data.get("custom_instructions", "") or "").strip()

    return AgentBlackBoxConfig(
        reviews=rev_settings,
        paths=path_settings,
        custom_instructions=custom_instr,
        scanners=scan_settings,
        warnings=warnings,
    )


async def load_repo_config(
    client: GitHubClient,
    owner: str,
    repo: str,
    base_ref: str,
    installation_id: Optional[int] = None,
) -> AgentBlackBoxConfig:
    """Fetch `.agentblackbox.yaml` strictly from the target base branch."""
    for filename in (".agentblackbox.yaml", ".agentblackbox.yml"):
        content = await client.get_file_contents(
            owner=owner,
            repo=repo,
            path=filename,
            ref=base_ref,
            installation_id=installation_id,
        )
        if content is not None:
            return parse_config_yaml(content)

    return AgentBlackBoxConfig()
