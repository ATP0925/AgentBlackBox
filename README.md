# 🔴 AgentBlackBox (`abb-recorder`)

[![CI](https://github.com/ATP0925/AgentBlackBox/actions/workflows/ci.yml/badge.svg)](https://github.com/ATP0925/AgentBlackBox/actions/workflows/ci.yml)

**The flight recorder for autonomous AI coding agents.**

> Every autonomous system needs a black box.

**Status:** `v0.2.0a2` (Live background daemon, redact-first storage, tamper-evident hash chain with optional HMAC signing, content-addressed blob store, git & terminal recording, Claude Code attribution hooks, and localhost Bearer-auth API — **112 tests passing**.)

---

## Problem

AI coding agents (Claude Code, Cursor, Codex, Cline) now have full terminal and filesystem access on developer machines. When something goes wrong — files deleted, secrets leaked, code broken — there's **zero forensic trail**. No way to see what the agent did, when, or why.

AgentBlackBox records OS-level agent actions on the developer machine and lets you replay, verify, search, blame, and export forensic timelines.

---

## Features (`v0.2`)

- 🔄 **Live Background Daemon (`daemon/core.py`)** — `abb start` launches a detached background recorder (`FileSystemWatcher` + `GitObserver`) and `abb stop` shuts it down cleanly
- 🔒 **Redact-First → Store-Later (`analysis/redactor.py`)** — Redacts secrets (`[REDACTED:<type>]`) from event payloads, command outputs, and file snapshots *before* hashing or writing to SQLite/disk
- ⛓️ **Tamper-Evident Hash Chain (`verify_chain`, `abb verify`)** — Monotonic per-session `seq` + chained `prev_hash` / `event_hash` (SHA-256) to detect DB edits or deletions
- 📦 **Content-Addressed Blob Store (`storage/blob_store.py`)** — Deduplicated, secret-redacted file snapshots under `.agentblackbox/blobs/<sha256>` linked via `file_snapshots`
- 💻 **Terminal Command Recorder (`abb run`, `watchers/terminal.py`)** — Captures command, exit code, stdout/stderr, PID, duration, and propagates `ABB_SESSION_ID` / `ABB_PARENT_EVENT_ID` / `ABB_AGENT_ID`
- 🌿 **Git Observer (`watchers/git_observer.py`)** — Installs `reference-transaction` hook (preserving existing hooks) and polls `HEAD`/reflog for commits and resets
- 🤖 **Agent Attribution (`watchers/agent_hooks.py`, `abb hook-install`)** — Installs Claude Code `PreToolUse` hooks into `.claude/settings.local.json` with `agent_id`, `pid`, and `parent_event_id` columns
- 📁 **FileSystem Watcher (`watchers/filesystem.py`)** — Tracks file create, modify, delete, rename via `watchdog` with debouncing and SHA-256 dedup
- 🔐 **Secret Detector & Risk Scorer (`analysis/`)** — 14 regex patterns + Shannon entropy + deterministic `0.0–10.0` scoring and alerts
- ⏮️ **Timeline Builder & Blame (`replay/`)** — Chronological session timelines and reverse-chronological file blame
- 🌐 **Localhost FastAPI + WebSocket API (`api/`, `abb serve`)** — Bound explicitly to `127.0.0.1` with Bearer token auth (`ABB_API_TOKEN`)
- 📄 **Exporters (`storage/export.py`)** — Standalone JSON, CSV, and dark-theme HTML reports

---

## Install

> **Package Naming Note:** The PyPI name `agentblackbox` is already taken by an unrelated SDK-level project, so this project uses **`abb-recorder`**.

```bash
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Start live background recording (filesystem + git observer)
abb start --name "refactor-auth" --agent claude-code

# Optional: run commands with full stdout/stderr & parent attribution
abb run --agent claude-code -- pytest

# Optional: install Claude Code PreToolUse attribution hook
abb hook-install --agent claude-code

# Check live daemon status
abb status

# Stop daemon cleanly
abb stop

# Investigate & verify integrity
abb sessions
abb verify <session_id>
abb search "rm -rf"
abb blame src/auth.py
abb alerts
abb report <session_id> --format html
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `abb start` | Launch live background recording daemon |
| `abb stop` | Stop background recording daemon & close session |
| `abb status` | Show live daemon status, PID, and event count |
| `abb run -- <cmd>` | Execute a command with full output, redaction, and attribution |
| `abb hook-install` | Install Claude Code `PreToolUse` attribution hook |
| `abb verify <session_id>` | Verify tamper-evident event hash chain |
| `abb sessions` | List recorded sessions |
| `abb search <query>` | Search event payloads, paths, and tags |
| `abb blame <file>` | Show file change history |
| `abb alerts` | Show unacknowledged security alerts |
| `abb report <session_id>` | Export session report (`json`, `csv`, `html`) |
| `abb serve` | Start local API on `127.0.0.1` with generated bearer token |
| `abb version` | Show version |

---

## API (Local Only)

Start the API server bound explicitly to `127.0.0.1` with bearer token auth:

```bash
abb serve --port 7700
# or directly:
ABB_API_TOKEN="<your-token>" uvicorn agentblackbox.api.main:app --host 127.0.0.1 --port 7700
```

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/sessions` | List sessions |
| `POST /api/v1/sessions` | Create session |
| `GET /api/v1/sessions/{session_id}` | Get session details |
| `PATCH /api/v1/sessions/{session_id}` | Stop session |
| `GET /api/v1/sessions/{session_id}/verify` | Verify hash chain integrity |
| `GET /api/v1/events` | Query events |
| `GET /api/v1/search?q=...` | Search events |
| `GET /api/v1/timeline/{session_id}` | Session timeline |
| `GET /api/v1/blame?file=...` | File blame |
| `GET /api/v1/export/{session_id}` | Export data (`json`, `csv`, `html`) |
| `WS /ws/live` | WebSocket live channel (`?token=` or `Bearer` header) |

---

## Tests

```bash
python -m pytest tests/ -v --tb=short
```

**112 tests passing** across redactor, secret detection & HMAC fingerprinting, risk scoring, hash chain & migration, HMAC chain signing, blob store, filesystem watcher, git observer & hooks, terminal recorder, agent hooks, background daemon, timeline, blame, API auth, and FastAPI routes.

---

## Threat Model & Security Boundaries

AgentBlackBox is an **observability & forensic flight recorder** designed to capture what autonomous coding agents do on a developer machine. Like user-space audit daemons, it operates under explicit security boundaries:

### What AgentBlackBox Solves (In Scope)
- **Accidental & Runaway Damage:** Catches accidental recursive file deletions, unauthorized `.env` modifications, runaway git resets, and mass edits.
- **Accidental Secret Leaks (Best-Effort):** 14 regex provider signatures + Shannon entropy redact sensitive tokens (`[REDACTED:<type>]`) before payloads or file snapshots are written to SQLite or blob disk.
- **Forensic Reconstruction:** Provides full timeline replay, reverse-chronological file blame, and verifiable event sequences for post-mortems.
- **Opportunistic & Naive Tampering:** A cryptographic SHA-256 linear hash chain detects SQLite row modifications, event tampering, out-of-order mutations, and middle-of-chain deletions via `abb verify <session_id>`.

### Explicit Limitations & Out-of-Scope (Roadmap)
- **Tail-Truncation & Same-UID Tampering:** If a malicious agent runs under the same OS user without container/VM sandboxing, it can write to `.agentblackbox/`. While middle-chain edits break hashes, deleting the tail of a session leaves the remaining sub-chain internally valid from `GENESIS`. Tail-truncation cannot be mathematically prevented locally without external head-hash anchoring (e.g. remote witness, RFC 3161 timestamping, or append-only signed checkpoints — planned for v0.3).
- **Heuristic Redaction is Best-Effort:** Regex + Shannon entropy detects high-entropy and standard provider tokens. Custom split tokens, base64-obfuscated keys, or non-standard formats are not guaranteed to be caught.
- **Attribution Depth:** Claude Code is monitored via structured `.claude/settings.local.json` `PreToolUse` hooks; generic terminal tools are monitored via `abb run` wrappers. IDE extensions without hook interfaces (Cursor, Cline) are currently tracked via time-correlated filesystem and git events.

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
- SQLite (WAL mode) + content-addressed blob store
- watchdog
- typer + rich
- pytest

## License

MIT

---

Built by [Pratik Atpadkar](https://linkedin.com/in/pratik-atpadkar)
