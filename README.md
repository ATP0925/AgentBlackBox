# 🔴 AgentBlackBox (`abb-recorder`)

[![CI](https://github.com/ATP0925/AgentBlackBox/actions/workflows/ci.yml/badge.svg)](https://github.com/ATP0925/AgentBlackBox/actions/workflows/ci.yml)

**The flight recorder for autonomous AI coding agents.**

> Every autonomous system needs a black box.

**Status:** `v0.2.0a4` (Live background daemon, redact-first storage, tamper-evident hash chain with HMAC session metadata protection (`session_meta_mac`), watermark downgrade protection, external signed tip checkpointing, auto-checkpoint on stop, content-addressed blob store, git & terminal recording, Claude Code attribution hooks, and localhost Bearer-auth API — **128 tests passing**.)

---

## Problem

AI coding agents (Claude Code, Cursor, Codex, Cline) now have full terminal and filesystem access on developer machines. When something goes wrong — files deleted, secrets leaked, code broken — there's **zero forensic trail**. No way to see what the agent did, when, or why.

AgentBlackBox records OS-level agent actions on the developer machine and lets you replay, verify, search, blame, and export forensic timelines.

---

## Features (`v0.2`)

- 🔄 **Live Background Daemon (`daemon/core.py`)** — `abb start` launches a detached background recorder (`FileSystemWatcher` + `GitObserver`) and `abb stop` shuts it down cleanly and auto-checkpoints the chain tip
- 🔒 **Redact-First → Store-Later (`analysis/redactor.py`)** — Redacts secrets (`[REDACTED:<type>]`) from event payloads, command outputs, and file snapshots *before* hashing or writing to SQLite/disk. Smart classification protects credentials while preserving working directory paths (`PWD`) and LLM token usage counters
- ⛓️ **Tamper-Evident Hash Chain (`verify_chain`, `abb verify`)** — Monotonic per-session `seq` + chained `prev_hash` / `event_hash` (SHA-256 or HMAC-SHA256) with `meta_mac` protection over session flags to detect DB edits, direct SQLite flag manipulation, or sequence deletion
- 📌 **External Signed Checkpoints (`abb export-checkpoint`, `abb verify --checkpoint`)** — Writes HMAC-signed head tip checkpoints (`<db_parent>/checkpoints/<session_id>.tip`) to detect tail truncation attacks
- 📦 **Content-Addressed Blob Store (`storage/blob_store.py`)** — Deduplicated, secret-redacted file snapshots under `.agentblackbox/blobs/<sha256>` linked via `file_snapshots`
- 💻 **Terminal Command Recorder (`abb run`, `watchers/terminal.py`)** — Captures command, exit code, stdout/stderr, PID, duration, and propagates `ABB_SESSION_ID` / `ABB_PARENT_EVENT_ID` / `ABB_AGENT_ID`
- 🌿 **Git Observer (`watchers/git_observer.py`)** — Installs `reference-transaction` hook (preserving existing hooks) and polls `HEAD`/reflog for commits and resets
- 🤖 **Agent Attribution (`watchers/agent_hooks.py`, `abb hook-install`)** — Installs Claude Code `PreToolUse` hooks into `.claude/settings.local.json` with `agent_id`, `pid`, and `parent_event_id` columns
- 📁 **FileSystem Watcher (`watchers/filesystem.py`)** — Tracks file create, modify, delete, rename via `watchdog` with debouncing and SHA-256 dedup
- 🔐 **Secret Detector & Risk Scorer (`analysis/`)** — 14 regex patterns + Shannon entropy + deterministic `0.0–10.0` scoring and alerts with dynamic random salt stored at `~/.agentblackbox/.secret_salt` (mode `0600`)
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
| `abb stop` | Stop background recording daemon & auto-checkpoint tip |
| `abb status` | Show live daemon status, PID, and event count |
| `abb run -- <cmd>` | Execute a command with full output, redaction, and attribution |
| `abb hook-install` | Install Claude Code `PreToolUse` attribution hook |
| `abb hook-ingest [file]` | Ingest & normalize events from Cursor, Cline, Claude, Antigravity (`--source`) |
| `abb verify <session_id>` | Verify tamper-evident event hash chain (`--checkpoint`, `--require-keyed`, `--require-checkpoint`) |
| `abb export-checkpoint <session_id>` | Export HMAC-signed head tip checkpoint JSON |
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

**146 tests passing** across OS Keychain integration & process env scrubbing (`keyring`, DPAPI/SecretService), `TamperGuard` out-of-tree shadow checkpoint mirroring & rollback detection, multi-pass Base64/Hex/URL & split-token secret scanner, Universal IDE Hook Collector (Claude Code, Cursor Composer, Cline, Google Antigravity), tokenized key redactor, exact `pwd`/`PWD` path exemption, cross-install salt divergence, dynamic random salt HMAC fingerprinting with Windows `icacls` / POSIX `0600` ACLs, risk scoring, hash chain watermark downgrade protection, default-on HMAC enforcement, domain-separated subkeys (`abb-event-mac-v1`, `abb-session-meta-mac-v1`, `abb-checkpoint-mac-v1`), session metadata MAC (`meta_mac`), periodic and signed tip checkpointing (`--require-checkpoint`), filesystem debounce coalescing, blob store, git observer & hooks, terminal recorder, background daemon, timeline, blame, API auth, and FastAPI routes.

---

## Threat Model & Security Boundaries (v0.3.0)

AgentBlackBox is an **observability & forensic flight recorder** designed to capture what autonomous coding agents do on a developer machine. In v0.3.0, all four core architectural boundaries are hardened:

### What AgentBlackBox Solves (In Scope)
- **Same-User Key Protection & Process Isolation:** `KeyProvider` stores master HMAC keys directly inside the OS Keychain (Windows DPAPI, Linux SecretService, macOS Keychain). When initialized, `ABB_HMAC_KEY` is scrubbed from process memory (`os.environ`), and child processes spawned via `abb run` have secrets explicitly stripped via `build_sanitized_child_env()`. Subkeys are derived per-domain using RFC 5869 HKDF-SHA256 (`abb-event-mac-v1`, `abb-session-meta-mac-v1`, `abb-checkpoint-mac-v1`).
- **Tamper-Evident Shadow Mirroring & Deletion Recovery:** `TamperGuard` writes signed `.tip` checkpoints to both the workspace `.agentblackbox/checkpoints/` and an out-of-tree protected user directory (`%LOCALAPPDATA%\agentblackbox\shadow_mirrors` on Windows or `~/.local/share/agentblackbox/shadow_mirrors` on Linux/macOS). It detects sequence rollbacks and MAC tampering, automatically restores deleted workspace checkpoints from shadow storage, applies read-only OS guards, and optionally replicates checkpoints via HTTP/HTTPS webhook (`ABB_CHECKPOINT_WEBHOOK_URL`).
- **Multi-Pass Secret Scanner & Split-Token Reassembly:** Catches direct secrets as well as Base64-encoded, Hex-encoded, URL-encoded, and adjacent split string literals (e.g. `'sk-ant-' + 'api03-...'`). Redaction operates before disk write, preventing secret leakage into SQLite or blob stores. Working directory paths (`PWD`, exact `pwd` with path values) and LLM token usage counters remain cleanly exempt.
- **Universal IDE Hook & Log Collector:** `UniversalIDECollector` parses and canonicalizes tool invocations from Claude Code (`PreToolUse`/`PostToolUse`), Cursor IDE Composer & MCP tools, Cline VS Code tasks, and Google Antigravity IDE events into unified `NormalizedAgentEvent` records, ingestible via `abb hook-ingest`.
- **Chain Integrity & Attribution Protection:** A canonical v2 JSON hash covers sequence, predecessor, timestamp, event type, payload hash, source path, attribution fields (`agent_id`, `pid`, `parent_event_id`), blob references, severity, risk score, and tags. When configured with `ABB_HMAC_KEY`, HMAC-SHA256 signatures protect event hashes and session metadata (`session_meta_mac` covers `is_keyed` and migration cutoffs), detecting direct SQLite tampering. Verification strictly enforces keyed events across all v2 rows by default when a key is present.
- **Tail-Truncation Defense & Crash Resilience:** External signed tip checkpoints are exported automatically every 50 events (`checkpoint_interval`) and on `abb stop`. Even if an agent process is forcibly killed or crashes, events up to the latest periodic checkpoint remain verifiable. `--require-checkpoint` flags missing checkpoints as verification failures.

### Explicit Limitations & Out-of-Scope (Roadmap)
- **Root / Administrator Compromise:** If an attacker or agent gains elevated OS administrator/root privileges, kernel-level drivers or OS memory dump facilities can bypass user-space security controls.
- **Physical Machine Access:** Encrypted hardware storage / TPM binding is planned for enterprise compliance extensions.
- **Heuristic Redaction is Best-Effort:** Multi-pass Base64/Hex/URL decoding and split-token normalization catches common obfuscations. Custom proprietary ciphers or polymorphic payloads require behavioral analysis.

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
