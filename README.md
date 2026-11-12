# 🔴 AgentBlackBox (`abb-recorder`)

**The flight recorder for autonomous AI coding agents.**

> Every autonomous system needs a black box.

**Status:** `v0.1.0` (Early Alpha — core storage, analysis, replay, CLI, and REST/WebSocket API built; 66 tests passing. Live background daemon & terminal/git hooks are in `v0.2`.)

---

## Problem

AI coding agents (Claude Code, Cursor, Codex, Cline) now have full terminal and filesystem access on developer machines. When something goes wrong — files deleted, secrets leaked, code broken — there's **zero forensic trail**. No way to see what the agent did, when, or why.

AgentBlackBox is designed to record OS-level agent actions on the developer machine and let you replay, search, blame, and export forensic timelines.

---

## Feature Status (Built vs Planned)

### ✅ Implemented in `v0.1.0`
- 📁 **FileSystem Watcher (`watchers/filesystem.py`)** — Tracks file create, modify, delete, rename via `watchdog` with debouncing and SHA-256 dedup
- 🗄️ **SQLite Event Store (`storage/event_store.py`)** — WAL-mode persistence for sessions, events, and alerts with full-text search
- 🔐 **Secret Detector (`analysis/secret_detector.py`)** — Detects API keys, tokens, passwords, private keys, and DB URLs (14 regex patterns + Shannon entropy + false-positive filtering)
- ⚠️ **Risk Scorer & Pattern Matcher (`analysis/`)** — Deterministic `0.0–10.0` risk scoring and destructive command classification
- ⏮️ **Timeline Builder & Blame (`replay/`)** — Chronological session timelines with relative ms offsets and reverse-chronological file blame
- 💻 **CLI (`abb`)** — Session lifecycle (`start`, `stop`, `sessions`), `search`, `blame`, `alerts`, `report`, `version`
- 🌐 **FastAPI + WebSocket API (`api/`)** — REST endpoints (`/api/v1/...`) and `/ws/live` WebSocket manager
- 📄 **Exporters (`storage/export.py`)** — Standalone JSON, CSV, and dark-theme HTML reports

### 🚧 Planned in `v0.2.0`
- ⛓️ **Integrity & Redaction** — Per-session `seq` counter, tamper-evident cryptographic hash chain, and payload secret redaction before disk write
- 🌿 **Git Observer** — Capturing `git` state changes via `reference-transaction` hooks
- 🔄 **Live Daemon & Terminal Logger** — Wiring `abb start` to spawn the background watcher daemon + shell/process logging + agent attribution hooks (e.g., Claude Code hooks)
- 🔒 **API Token Auth** — Optional bearer token protection for local dashboard/API access

> **Note on `abb start` in `v0.1.0`:** Currently `abb start` creates and tracks the session record in SQLite; `FileSystemWatcher` runs via the Python module/API and is not yet auto-daemonized by `abb start`.

---

## Install (Development)

> **Package Naming Note:** The PyPI name `agentblackbox` is already taken by an unrelated SDK-level project, so this project uses **`abb-recorder`** on PyPI (currently unpublished — install from source below).

```bash
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Check CLI
abb version

# Create and list a session in SQLite
abb start --name "refactor-auth"
abb sessions
abb stop

# Investigate recorded events
abb search "rm -rf"
abb blame src/auth.py
abb alerts
abb report sess-abc123def --format html
```

---

## CLI Commands

| Command | Status | Description |
|---------|--------|-------------|
| `abb start` | ✅ | Create a session record in SQLite (`🚧` daemon auto-attach in v0.2) |
| `abb stop` | ✅ | Mark active or specified session as stopped |
| `abb sessions` | ✅ | List recorded sessions |
| `abb search <query>` | ✅ | Search event payloads, paths, and tags |
| `abb blame <file>` | ✅ | Show file change history |
| `abb alerts` | ✅ | Show unacknowledged security alerts |
| `abb report <session_id>` | ✅ | Export session report (`json`, `csv`, `html`) |
| `abb version` | ✅ | Show version |

---

## API (Local Only)

Start the API server bound explicitly to localhost:

```bash
uvicorn agentblackbox.api.main:app --host 127.0.0.1 --port 7700
```

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/sessions` | List sessions |
| `POST /api/v1/sessions` | Create session |
| `GET /api/v1/sessions/{session_id}` | Get session details |
| `PATCH /api/v1/sessions/{session_id}` | Stop session |
| `GET /api/v1/events` | Query events |
| `GET /api/v1/search?q=...` | Search events |
| `GET /api/v1/timeline/{session_id}` | Session timeline |
| `GET /api/v1/blame?file=...` | File blame |
| `GET /api/v1/export/{session_id}` | Export data (`json`, `csv`, `html`) |
| `WS /ws/live` | WebSocket live channel |

---

## Tests

```bash
python -m pytest tests/ -v --tb=short
```

Currently **66 tests** pass across storage, filesystem watcher, secret detection, risk scoring, timeline, blame, and FastAPI routes.

---

## Part of the AI Agent Safety Suite

| Tool | Purpose |
|------|---------|
| [AgentShield](https://github.com/ATP0925/AgentShield) | **Prevents** disasters (pre-commit gate) |
| **AgentBlackBox** | **Investigates** what happened (flight recorder) |

> *AgentShield is the seatbelt. AgentBlackBox is the black box.*

---

## Tech Stack

- Python 3.11+
- FastAPI + WebSockets
- SQLite (WAL mode)
- watchdog
- typer + rich
- pytest

## License

MIT

---

Built by [Pratik Atpadkar](https://linkedin.com/in/pratik-atpadkar)
