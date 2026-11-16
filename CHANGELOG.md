# Changelog

All notable changes to the AgentBlackBox project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0] - 2026-11-16

### Added
- **Production Hosted GitHub App**:
  - 1-Click App Manifest registration workflow (`/github/manifest` & `/github/manifest/callback`).
  - Automated credential persistence to `.env` with restricted operating system permissions.
  - Ephemeral RS256 App JWT auth with cached installation token manager.
  - Constant-time HMAC-SHA256 signature verification on all incoming webhooks.
  - Asynchronous background review queue with Redis support, in-memory fallback, and dead-letter tracking.
  - Idempotency store on `X-GitHub-Delivery` with 1-hour TTL expiration.
- **Signed Review Receipts (`abb verify-receipt`)**:
  - Cryptographic flight-ledger entries for every review run (diff SHA-256 hash, config hash, finding hashes).
  - Offline CLI verification command (`abb verify-receipt <id>`).
  - Tamper detection tests asserting ledger and finding integrity.
- **Agent-Session Linkage (`AgentBlackBox-Session: <id>`)**:
  - Automatic extraction of session IDs from PR bodies, commit messages, and branch names.
  - Auditing of local agent execution history: tool calls, blocked commands, deleted files, and touched tests.
  - Escalation of broken chains or session tampering to critical review findings.
- **Agent-Misbehavior Drift Rules**:
  - Detection of deleted unit test files and stripped assertions.
  - Detection of weakened test suites (`skip`, `xfail`).
  - Detection of modified CI/CD workflows and flight-gate configurations.
  - Detection of typosquatted or suspicious third-party dependencies.
  - Detection of disabled linters and security suppressions (`noqa`, `type: ignore`).
  - Explainable PR risk scoring breakdown.
- **Provable Zero Retention**:
  - Strict in-memory RAM execution buffer for diffs and file contents.
  - Edge secret detection and masking before model ingestion without echoing secret values.
  - Comprehensive zero-retention canary test suite (`test_zero_retention_canary.py`) scanning database, disk, and queue state.
- **Quality & Ops**:
  - Evaluation harness (`tests/eval/test_eval_harness.py`) benchmarked against seeded-bug, security, and agent-misbehavior corpora.
  - Structured JSON logging with delivery IDs and performance metrics.
  - Health and readiness endpoints (`/github/healthz`, `/github/readyz`).
  - Non-root production `Dockerfile` (unprivileged `appuser` uid 10001).
  - Docker Compose service with integrated Redis instance.
  - Webhook replay utilities with cross-platform support (`scripts/replay_webhook.py` and `scripts/replay_webhook.ps1`).

---

## [0.4.0] - 2026-11-15

### Added
- Multi-agent PreToolUse interception hooks for Claude Code, Cursor, Codex CLI, and Gemini CLI.
- AST-level code analyzer modules (`bugs.py`, `security.py`, `quality.py`, `performance.py`, `duplication.py`).
- Real-time architectural drift detector against `.agentblackbox/architecture.json`.
- Compliance tracker mapping file operations to SOC2-CC6.1 and OWASP-LLM06 rules.
- Local CI/CD pre-push gate command (`abb ci-gate`).
- SARIF 2.1.0 export formatting for GitHub Advanced Security.
- Web dashboard API and WebSocket streaming endpoints (`/ws/live`, `/ws/stream`).

---

## [0.3.0] - 2026-11-14

### Added
- Tamper-evident cryptographic flight recorder using keyed HMAC-SHA256 and SQLite WAL.
- Head-tip checkpointing (`.tip` files) to guarantee chain monotonicity.
- Automatic snapshotting of modified files to blob store (`.agentblackbox/blobs/<sha256>`).
- 1-click refactor rollback CLI (`abb rollback`).
- CLI command suite (`abb start`, `abb stop`, `abb verify`, `abb blame`, `abb timeline`).

---

## [0.2.0] - 2026-11-10

### Added
- Basic filesystem watcher based on `watchdog`.
- Session management daemon.
- Keyring-backed HMAC secret management.

---

## [0.1.0] - 2026-11-01

### Added
- Initial project scaffolding and proof of concept.
