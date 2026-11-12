# AgentBlackBox — AGENTS.md
# Master Build Instructions for ANY Model (Flash / Sonnet / Opus)
# ================================================================
# This file removes ALL ambiguity. Follow it line by line.
# DO NOT improvise. DO NOT rename files. DO NOT change signatures.
# Every decision has been pre-made by Opus.

## PROJECT IDENTITY
- Name: AgentBlackBox
- Tagline: "The Flight Recorder for Autonomous AI Agents"
- Language: Python 3.11+
- Package Manager: uv (if available) or pip
- Database: SQLite with WAL mode
- API: FastAPI
- CLI: typer
- Testing: pytest
- Async: asyncio
- File Watching: watchdog

## ABSOLUTE RULES (NEVER BREAK)
1. ALL imports at file top, stdlib first, then third-party, then local
2. ALL functions have type hints — NO exceptions
3. ALL public functions have docstrings (Google style)
4. ALL classes use dataclasses or Pydantic BaseModel — NO raw dicts for data
5. NO print() — use structlog or logging module ONLY
6. NO global mutable state — use dependency injection
7. Every SQLite write uses WAL mode and connection context manager
8. Every file path uses pathlib.Path — NO string concatenation for paths
9. Every CLI command returns exit code 0 on success, 1 on error
10. Tests MUST pass before moving to next phase

## CODE STYLE
```python
# CORRECT
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List
import hashlib
import json

@dataclass
class Event:
    """Represents a single recorded event."""
    id: int
    session_id: str
    timestamp: str  # ISO 8601
    event_type: str
    severity: str = "info"
    risk_score: float = 0.0
    source_path: Optional[str] = None
    payload: dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

# WRONG — never do this:
event = {"id": 1, "type": "file_create"}  # raw dict instead of dataclass
```

## DIRECTORY STRUCTURE (EXACT — do not deviate)
```
AgentBlackBox/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── agentblackbox/
│       ├── __init__.py
│       ├── __main__.py
│       ├── daemon/
│       │   ├── __init__.py
│       │   ├── core.py
│       │   ├── session.py
│       │   └── config.py
│       ├── watchers/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── filesystem.py
│       │   ├── terminal.py
│       │   └── git_observer.py
│       ├── analysis/
│       │   ├── __init__.py
│       │   ├── secret_detector.py
│       │   ├── risk_scorer.py
│       │   └── pattern_matcher.py
│       ├── storage/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   ├── event_store.py
│       │   └── export.py
│       ├── replay/
│       │   ├── __init__.py
│       │   ├── timeline.py
│       │   └── blame.py
│       ├── api/
│       │   ├── __init__.py
│       │   ├── main.py
│       │   └── routes/
│       │       ├── __init__.py
│       │       ├── sessions.py
│       │       ├── events.py
│       │       └── timeline.py
│       └── cli/
│           ├── __init__.py
│           └── main.py
└── tests/
    ├── conftest.py
    ├── test_watchers/
    │   ├── test_filesystem.py
    │   └── test_git_observer.py
    ├── test_analysis/
    │   ├── test_secret_detector.py
    │   └── test_risk_scorer.py
    ├── test_storage/
    │   └── test_event_store.py
    └── test_replay/
        └── test_timeline.py
```

## PHASE EXECUTION ORDER
Read and execute ONE phase file at a time:
1. `.build/phase1_core.md` — Models + Storage + Session
2. `.build/phase2_watchers.md` — FileWatcher + SecretDetector + RiskScorer
3. `.build/phase3_investigation.md` — Timeline + Blame + Search + CLI
4. `.build/phase4_api.md` — FastAPI + WebSocket + Dashboard

## VERIFICATION AFTER EACH PHASE
After completing each phase, run:
```bash
cd AgentBlackBox
python -m pytest tests/ -v --tb=short
```
ALL tests for that phase MUST pass before proceeding.

