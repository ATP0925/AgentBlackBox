# AgentBlackBox (`abb`)

**Local-first audit and replay flight recorder for autonomous AI coding agents.**

When an AI agent (Claude Code, Cursor, OpenCode, or custom scripts) edits files, runs shell commands, or touches Git history, **AgentBlackBox** records every action locally—redacting secrets *before* they hit disk, scoring command risk, linking file diffs to exact tool invocations, and maintaining a verifiable SHA-256/HMAC event timeline.

## Why AgentBlackBox?

- **Redact-First Storage**: API keys, JWTs, AWS secrets, and high-entropy tokens are scrubbed (`[REDACTED:<TYPE>]`) in memory before hashing or saving to SQLite.
- **Zero-Cloud Privacy**: Runs 100% locally in `.agentblackbox/` with SQLite WAL persistence and content-addressed file snapshots.
- **Deterministic Risk Scoring**: Evaluates executed shell commands (`shlex` AST token analysis) and file mutations on a `0.0–10.0` scale without false alarms on comments or `echo` strings.
- **Tamper-Evident Timeline & File Blame**: Reconstructs chronological session timelines (`abb report`), traces which agent action modified a file (`abb blame`), and verifies chain integrity (`abb verify`).

## Quickstart (60 Seconds)

```bash
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox
pip install -e ".[dev]"

# 1. Start the background recorder in your project workspace
abb start --name "auth-refactor" --agent claude-code

# 2. Run commands or let your AI agent work via hooks
abb hook-install
abb run --agent claude-code -- pytest -q

# 3. Inspect status, file blame, and security alerts
abb status
abb alerts
abb blame src/agentblackbox/cli/main.py

# 4. Stop daemon, verify hash chain, and export an HTML timeline report
abb stop
abb verify <session_id>
abb report <session_id> --format html
```

## CLI Command Reference

| Command | Purpose |
| :--- | :--- |
| `abb start [--name NAME]` | Launch background recorder (`FileSystemWatcher` + `GitObserver`) |
| `abb stop` | Gracefully drain events, stop daemon, and write signed head checkpoint |
| `abb status` | Show active daemon PID, session ID, and recorded event count |
| `abb run -- <cmd>` | Execute a command while capturing redacted stdout/stderr, exit code, and duration |
| `abb hook-install` | Install Claude Code `PreToolUse` attribution hook into `.claude/settings.local.json` |
| `abb sessions` | List recorded sessions with event counts and risk summaries |
| `abb search <query>` | Search redacted event payloads, file paths, and command histories |
| `abb blame <file>` | Show reverse-chronological modification history and agent attribution for a file |
| `abb alerts` | List unacknowledged secret detections and high-risk command alerts |
| `abb verify <session_id>` | Verify SQLite HMAC hash chain and external head tip checkpoint |
| `abb report <session_id>` | Export standalone timeline report (`--format html`, `json`, or `csv`) |
| `abb serve` | Launch localhost (`127.0.0.1`) FastAPI & WebSocket inspector with Bearer auth |

## Architecture Overview

```text
src/agentblackbox/
├── analysis/     # Tokenized Shannon entropy secret detector, redactor & shlex risk scorer
├── storage/      # Thread-safe SQLite WAL EventStore, HMAC tamper guard & SHA-256 BlobStore
├── daemon/       # Background supervisor with atomic signal drain & PID identity verification
├── watchers/     # Watchdog filesystem observer, Git ref-transaction hook & terminal wrapper
├── replay/       # Timeline builder & file-blame correlation engine
├── api/          # Localhost-bound FastAPI REST + WebSocket server with Bearer token auth
└── cli/          # Typer CLI commands with shared context & strict exit-code discipline
```

## License

MIT License — see [LICENSE](LICENSE).
