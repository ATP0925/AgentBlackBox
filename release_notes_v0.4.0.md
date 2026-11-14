# 🚀 AgentBlackBox v0.4.0: Autonomous In-Memory PR Review Engine & Cryptographic AI Flight Recorder

AgentBlackBox v0.4.0 transforms autonomous AI agent governance. We are proud to introduce a complete, open-core, production-grade **Autonomous GitHub App In-Memory PR Review Engine**, paired with universal multi-agent interception for **Claude Code, Cursor, Codex CLI, and Gemini CLI**.

---

## 🌟 Major Highlights in v0.4.0

### 1. 🤖 Autonomous Pull Request Review Engine (`src/agentblackbox/github_app/`)
Turn any GitHub repository into an AI-guarded codebase with automated in-memory pull request reviews:
- **Auto-Updating Walkthrough Comments**: Posts a high-level summary of changes, file-by-file risk tables, sequence/flow notes, and finding breakdown. Edits cleanly in place using idempotency markers (`<!-- agentblackbox-walkthrough -->`).
- **One-Click Fixes (`suggestion` Blocks)**: Inline comments placed accurately on changed hunks with diff-safe suggestions that developers can commit directly from GitHub's UI.
- **GitHub Check Runs**: Pass/fail status checks with batched line annotations (strictly adhering to GitHub's 50-annotation batch limits).
- **Interactive Bot Commands**: Developers can talk to the bot in PR comments (`@agentblackbox review`, `full review`, `pause`, `resume`, `resolve`, `help`).
- **1-Click GitHub App Manifest Flow**: Scaffold and register the GitHub App on your account with zero manual config (`GET /github/manifest`).

### 2. 🛡️ Zero-Retention Privacy & Prompt-Injection Quarantine
- **Zero Customer Code Retention**: PR diffs, files, and annotations are processed strictly in-memory and discarded. Customer source code is never stored in databases, logs, or external persistent stores.
- **Strict Prompt-Injection Defense**: Diffs, commit messages, and PR comments are treated as untrusted data blocks wrapped in `<UNTRUSTED_PR_DATA>` delimiters.
- **In-Flight Secret Redaction**: Intercepts and masks API keys, AWS tokens, JWTs, and private keys *before* prompts reach any model.

### 3. 🔌 Universal Multi-Agent Interceptor Hooks (`abb hook-install`)
- One global command (`abb hook-install --agent all --global`) configures pre-tool-use hooks across your system.
- Supported agent environments:
  - **Claude Code & Codex CLI**: Hooks into `PreToolUse` for `Bash`, `Write`, `Edit`, `MultiEdit`, `Read`, `WebFetch`, and MCP tools.
  - **Cursor**: Intercepts `beforeShellExecution`, `afterFileEdit`, `beforeReadFile`, and `beforeMCPExecution`.
  - **Gemini CLI**: Intercepts `BeforeTool` with automatic payload normalization.
- **Agent Immunity Guarantee**: Hooks execute in isolated try/except blocks with silent stdout and always exit code 0—guaranteeing your agent workflows never crash or stall.

### 4. 🔗 Cryptographic Merkle Flight Recorder
- Every file write, shell execution, and MCP tool call is recorded into an append-only SQLite store with HMAC-SHA256 chaining.
- Tamper-evident verification (`abb verify`) detects deleted events or altered history with sub-second integrity checks.

---

## 📦 Quick Installation

```bash
# Clone and install
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox
pip install -e .

# Install universal interceptor hooks for all agents
abb hook-install --agent all --global

# Run test suite (257 passing tests)
python -m pytest tests -q
```

## 🐳 Docker Deployment

```bash
docker compose up -d
# Health check: http://localhost:8000/github/healthz
```

---
**Full Changelog**: https://github.com/ATP0925/AgentBlackBox/compare/v0.3.0...v0.4.0
