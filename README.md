# 🔴 AgentBlackBox

**The flight recorder for autonomous AI agents.**

> Every autonomous system needs a black box.

---

## Problem

AI coding agents (Claude Code, Cursor, Codex, Cline) now have full terminal and filesystem access on developer machines. When something goes wrong — files deleted, secrets leaked, code broken — there's **zero forensic trail**. No way to see what the agent did, when, or why.

AgentBlackBox records everything an AI agent does and lets you replay, search, and investigate.

## Features

- 📁 **File Watcher** — Tracks every file create, modify, delete, rename
- 💻 **Terminal Logger** — Records shell commands and their output
- 🌿 **Git Observer** — Captures git add, commit, push, force-push, reset
- 🔐 **Secret Detector** — Auto-detects API keys, tokens, passwords (15+ patterns)
- ⚠️ **Risk Scoring** — Every event scored 0-10 with severity classification
- 🔍 **Search** — Full-text search across all events
- 📋 **Blame** — "Which event changed this file?"
- ⏮️ **Timeline Replay** — Reconstruct exactly what happened
- 🚨 **Alerts** — Auto-flag destructive commands and secret leaks
- 📊 **Dashboard** — Web UI with live event feed (localhost:7700)
- 📄 **Export** — JSON, CSV, HTML reports

## Install

```bash
pip install agentblackbox
```

## Quick Start

```bash
# Start recording
abb start --name "refactor-auth"

# ... run your AI agent ...

# Stop recording
abb stop

# See what happened
abb sessions
abb search "rm -rf"
abb blame src/auth.py
abb report sess-abc123def --format html
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `abb start` | Start recording |
| `abb stop` | Stop recording |
| `abb sessions` | List all sessions |
| `abb search <query>` | Search events |
| `abb blame <file>` | File change history |
| `abb alerts` | Show security alerts |
| `abb report <session_id>` | Export report |
| `abb version` | Show version |

## API

Start the dashboard:
```bash
uvicorn agentblackbox.api.main:app --port 7700
```

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/sessions` | List sessions |
| `POST /api/v1/sessions` | Start session |
| `GET /api/v1/events` | Query events |
| `GET /api/v1/search?q=...` | Search |
| `GET /api/v1/timeline/:id` | Session timeline |
| `GET /api/v1/blame?file=...` | File blame |
| `GET /api/v1/export/:id` | Export data |
| `WS /ws/live` | Live event stream |

## Part of the AI Agent Safety Suite

| Tool | Purpose |
|------|---------|
| [AgentShield](https://github.com/ATP0925/AgentShield) | **Prevents** disasters (pre-commit gate) |
| **AgentBlackBox** | **Investigates** what happened (flight recorder) |

> *AgentShield is the seatbelt. AgentBlackBox is the black box.*

## Tech Stack

- Python 3.11+
- FastAPI (API + WebSocket)
- SQLite (WAL mode)
- watchdog (filesystem monitoring)
- typer + rich (CLI)
- pytest (64+ tests)

## License

MIT

---

Built by [Pratik Atpadkar](https://linkedin.com/in/pratik-atpadkar)

