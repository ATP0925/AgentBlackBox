# AgentBlackBox (`abb`)
### *Cryptographic Flight Recorder, Real-Time Architectural Drift Guard & Automated Code Review Engine for Autonomous AI Agents*

[![PyPI Version](https://img.shields.io/badge/pypi-v0.4.0-blue.svg)](https://pypi.org/project/abb-recorder/)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Supported Agents](https://img.shields.io/badge/Agents-Claude%20%7C%20Codex%20%7C%20Cursor%20%7C%20Gemini%20%7C%20Antigravity-orange.svg)](#-multi-agent-hook-matrix)
[![CI Security Gate](https://img.shields.io/badge/Gate-HMAC--SHA256%20Cryptographic%20Proof-brightgreen.svg)](#-cicd-cryptographic-gate)

---

## 🎯 What is AgentBlackBox?

Autonomous AI coding agents (**Claude Code**, **OpenAI Codex**, **Cursor**, **Gemini CLI**, and **Google Antigravity IDE**) edit files, execute terminal commands, and query APIs faster than human engineering teams can review. 

Traditional application security tools (SonarQube, Snyk) scan only static code *after* commits land, while AI coding assistants leave zero verifiable audit trails. If an agent executes an unsafe command, leaks a token, or breaks architecture boundaries, the damage is already done.

**AgentBlackBox is the missing cryptographic flight recorder and real-time guardrail for autonomous AI development**:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Autonomous AI Coding Agents                               │
│       Claude Code   •   Cursor   •   Codex CLI   •   Gemini CLI   •   Antigravity      │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ PreToolUse / beforeShellExecution
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                     AgentBlackBox Real-Time Intent Interceptor                         │
│   • In-Memory Secret Neutralization (Redaction before disk writes)                     │
│   • shlex AST Command Risk Scorer (0.0 - 10.0 Risk Spectrum)                           │
│   • Sensitive File Target Shield (.env, .pem, .ssh, aws credentials)                   │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Redacted & Scored Payloads
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        Cryptographic Flight Recorder Core                              │
│   • SQLite WAL Engine with Keyed HMAC-SHA256 Chaining                                  │
│   • Signed Head-Tip Checkpoints (.agentblackbox/checkpoints/*.tip)                     │
│   • Content-Addressed BlobStore Snapshots (.agentblackbox/blobs/<sha256>)              │
└─────────────────────┬──────────────────────────────────────────┬───────────────────────┘
                      │                                          │
                      ▼                                          ▼
┌───────────────────────────────────────────┐  ┌─────────────────────────────────────────┐
│     Google Antigravity / VS Code IDE      │  │        CI/CD Zero-Trust Flight Gate     │
│   • Real-Time WebSocket Event Stream      │  │  • abb ci-gate Verification             │
│   • In-Editor AST Layer Drift Diagnostics │  │  • SARIF 2.1.0 GitHub Scanning Export   │
│   • 1-Click Rollback to Safe Pre-Agent Blo│  │  • Hard Block on Hash Tampering or Risk │
└───────────────────────────────────────────┘  └─────────────────────────────────────────┘
```

---

## 🌟 Core Pillars

### 1. In-Flight Cryptographic Flight Recorder (`abb start`, `abb verify`, `abb blame`)
- **Keyed HMAC-SHA256 Audit Trail**: Every file modification, terminal command, git commit, and agent tool execution is cryptographically linked to its predecessor.
- **Redaction Prior to Storage**: Detected credentials, JWTs, private keys, and high-entropy secrets are scrubbed in memory *before* being recorded to disk.
- **Attribution & Blame**: Trace any line or file mutation directly back to the exact agent prompt, tool call, and session timeline with `abb blame <file>`.

### 2. Real-Time Architectural Drift & Compliance (`src/agentblackbox/analysis/`)
- **Layer Boundary Enforcement**: AST-based static validation prevents agents from introducing cross-layer architectural violations (e.g., storage modules importing presentation or CLI components).
- **Public API Contract Protection**: Automatically compares pre-agent AST symbols with post-edit files; flags broken function signatures, dropped parameters, or removed `__all__` exports.
- **Context-Aware Compliance**: Binds agent actions and diffs directly to audit standards (`SOC2-CC6.1`, `OWASP-LLM06`, `GDPR-PII`).

### 3. Flight-Recorder Guided Refactor Safety (`abb rollback`)
- **Pre-Edit BlobStore Snapshots**: Before an agent modifies code, an atomic snapshot is preserved in `.agentblackbox/blobs/<sha256>`.
- **Blast Radius Analysis**: Automatically calculates how many external modules depend on the symbols being modified.
- **Deterministic 1-Click Rollback**: Instantly revert dangerous or hallucinated agent refactors back to the exact pre-agent state with signed audit verification.

### 4. Automated Code Review & Static Analysis (`abb review`, `abb analyze`)
- **Git Diff & PR Inspection**: Pinpoint bugs, security vulnerabilities, and quadratic complexity directly inside added/modified diff hunks.
- **Pluggable AI & Deterministic Scanners**: Combines millisecond AST checks with optional AI reasoning (`gemini-2.5-flash`, OpenAI, Claude, or offline deterministic mode).
- **SARIF 2.1.0 Standard**: Produces native SARIF outputs for GitHub Advanced Security, GitLab CI, and corporate security dashboards.

### 5. CI/CD Pre-Push Flight Gate (`abb ci-gate`)
- Blocks merges and PRs if the HMAC-SHA256 chain is tampered with, if unmitigated high-risk commands were executed, or if architectural drift thresholds were breached.

### 6. Production Hosted GitHub App (`abb github-app`, `abb verify-receipt`)
- **In-Memory PR Reviews**: Posts one auto-updating Walkthrough comment, inline PR review comments with one-click ```suggestion blocks, and Check Runs with SARIF annotations.
- **Signed Review Receipts**: Cryptographically seals review audits into the flight ledger (`diff_hash`, `config_hash`, finding hashes) with offline verification (`abb verify-receipt <id>`).
- **Agent-Session Linkage**: Automatically binds pull requests to local agent sessions (`AgentBlackBox-Session: <id>`) to audit executed commands, file mutations, and blocked actions.
- **Provable Zero Retention**: Customer source code is processed strictly in volatile RAM; diffs, comments, and secrets are never persisted to disk or databases (verified by automated canary CI tests).
- **Agent-Misbehavior Drift Checks**: Detects deleted test assertions, skipped tests, CI workflow tampering, and linter suppressions with an explainable PR Risk Score.

---

## 🛡️ Feature Architecture Matrix (Why This Beats SonarQube, Snyk & Copilot)

| Capability | SonarQube / Snyk | GitHub Copilot | AgentBlackBox v0.4.0 + Antigravity Extension |
| :--- | :--- | :--- | :--- |
| **Cryptographic Audit Trail** | None (static point-in-time scan) | None (ephemeral chat logs) | **HMAC-SHA256 hash chain** + signed `.tip` checkpoints in `.agentblackbox/` |
| **Context-Aware Compliance** | Static rule matching only | No compliance enforcement | **Links prompt + tool call + file diff** to `SOC2-CC6.1` / `OWASP-LLM06` with hash proofs |
| **Real-Time Architectural Drift** | Post-commit / CI-only | Can accidentally violate layer rules | **In-editor AST & layer boundary check** (`drift_detector.py`) against `.agentblackbox/architecture.json` |
| **Legacy Refactor Safety** | Shows code smells only | Edits files without rollback guarantee | **Auto-snapshots to `.agentblackbox/blobs/<sha256>`** + AST signature diff + 1-click IDE rollback |
| **CI/CD Tamper & Risk Gate** | Scans code only, blind to agent actions | No local flight verification | **`abb ci-gate` CLI** blocks PRs if hash chain is tampered, risk > `7.0`, or SARIF has blockers |

---

## 🚀 Quickstart

### Prerequisites
- **Python**: 3.10+ (`python --version` or `py --version`)
- **Git**: (`git --version`) — On Windows, install via `winget install --id Git.Git -e --source winget`

---

### Windows (PowerShell)

#### ⚡ One-Click Auto Installer (Works with or without Git)
Open PowerShell and paste this single command:
```powershell
irm https://raw.githubusercontent.com/ATP0925/AgentBlackBox/main/install.ps1 | iex
```

---

#### Manual Step-by-Step

```powershell
# 1. Clone repository (or download ZIP if Git is not installed)
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox

# 2. Install package and dependencies (use python -m to avoid Windows binary execution policies)
python -m pip install -e ".[dev]"

# 3. Review current uncommitted git changes (working tree)
abb review
# Note: If 'abb' is not in PATH yet, run: python -m agentblackbox review (or .\abb.cmd review)

# 4. Review a pull request or branch diff against main
abb review feature-branch --base main --format markdown

# 5. Export SARIF 2.1.0 report for GitHub Advanced Security
abb review --format sarif --output results.sarif

# 6. Analyze an entire repository for bugs, security risks, and duplication
abb analyze . --min-severity medium

# 7. Enable AI reasoning layer (Claude, Codex, Gemini, or Offline)
$env:GEMINI_API_KEY="your-api-key"
abb review --ai gemini

# 8. Cryptographic & Policy CI/CD Gate
abb ci-gate --max-risk 7.0 --sarif-out abb-results.sarif

# 9. Start Google Antigravity IDE / VS Code Bridge Server
$env:ABB_API_TOKEN="abb-local-dev-token"
abb ide-bridge --host 127.0.0.1 --port 8765

# 10. (Optional) Build the IDE Extension
cd ide-extension
npm install
npm run compile

# Or with OpenAI Codex / Anthropic Claude:
# $env:OPENAI_API_KEY="your-api-key"; abb review --ai codex
# $env:ANTHROPIC_API_KEY="your-api-key"; abb review --ai claude
```

> **Tip for brand new Windows PCs without Git:**
> Run in PowerShell:
> ```powershell
> Invoke-WebRequest -Uri "https://github.com/ATP0925/AgentBlackBox/archive/refs/heads/main.zip" -OutFile "AgentBlackBox.zip"
> Expand-Archive -Path "AgentBlackBox.zip" -DestinationPath "."
> cd AgentBlackBox-main
> python -m pip install -e ".[dev]"
> ```

---

### Linux & macOS (Bash / Zsh)

```bash
# 1. Clone and install
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox
pip install -e ".[dev]"

# 2. Review current uncommitted git changes (working tree)
abb review

# 3. Review a pull request or branch diff against main
abb review feature-branch --base main --format markdown

# 4. Export SARIF 2.1.0 report for GitHub Advanced Security
abb review --format sarif --output results.sarif

# 5. Analyze an entire repository for bugs, security risks, and duplication
abb analyze . --min-severity medium

# 6. Enable AI reasoning layer with Gemini, Codex, or Claude
export GEMINI_API_KEY="your-api-key"
abb review --ai gemini
```

---

## 🛠️ CLI Command Reference

### Code Review & Analysis Commands

| Command | Description |
| :--- | :--- |
| `abb review [TARGET]` | Review working tree diff, commit range (`HEAD~1..HEAD`), or branch diff against base. |
| `abb review --base <BRANCH>` | Compare target branch against a base branch (e.g. `main`). |
| `abb review --format <FMT>` | Output format: `terminal` (default), `markdown`, `json`, or `sarif`. |
| `abb review --output <PATH>` | Save generated review report directly to file. |
| `abb review --min-severity <SEV>` | Filter findings: `critical`, `high`, `medium`, `low`, `info`. |
| `abb review --ai <PROVIDER>` | Enable AI reasoning: `gemini`, `openai`, `anthropic`, or `offline`. |
| `abb review --exit-zero` | Exit with status code 0 even if Critical/High findings are present. |
| `abb analyze [PATH]` | Perform deep static and AI code analysis on a repository or single file. |

### Audit Flight Recorder Commands

| Command | Description |
| :--- | :--- |
| `abb start [--name NAME]` | Launch background recorder (`FileSystemWatcher` + `GitObserver`). |
| `abb stop` | Gracefully drain events, stop daemon, and write signed head checkpoint. |
| `abb status` | Show active daemon PID, session ID, and recorded event count. |
| `abb run -- <cmd>` | Execute a command while capturing redacted stdout/stderr and attribution. |
| `abb hook-install [--agent <agent>]` | Install agent hooks (`claude`, `codex`, `cursor`, `gemini`, `all`) with `--global` / `--project`. |
| `abb hook-verify [--global]` | Verify installed hooks across all supported coding agent configurations. |
| `abb sessions` | List recorded sessions with event counts and risk summaries. |
| `abb search <query>` | Search redacted event payloads, file paths, and command histories. |
| `abb blame <file>` | Show reverse-chronological modification history and agent attribution. |
| `abb alerts` | List unacknowledged secret detections and high-risk command alerts. |
| `abb verify <session_id>` | Verify SQLite HMAC hash chain and external head-tip checkpoint. |
| `abb export-checkpoint <id>` | Export head-tip checkpoint JSON to an external file or stdout. |
| `abb report <session_id>` | Export standalone timeline report (`--format html`, `json`, or `csv`). |
| `abb serve` | Launch localhost (`127.0.0.1`) FastAPI & WebSocket inspector. |
| `abb github-app [--port PORT]` | Launch GitHub App Webhook server for automated in-memory PR code reviews. |

---

## 🛡️ Autonomous GitHub App In-Memory PR Review Engine

AgentBlackBox includes a full production-ready **GitHub App module** (`src/agentblackbox/github_app/`) that runs automated AI & AST code reviews on Pull Requests with zero source code retention.

### 🌟 How It Works
1. **Developer opens/updates a PR** &rarr; GitHub delivers webhook to `POST /github/webhook`.
2. **Instant HMAC-SHA256 Verification** &rarr; Constant-time signature verification rejects unauthorized requests with `401`.
3. **In-Flight In-Memory Analysis**:
   - Diffs are scanned and **secrets are redacted in memory** before reaching any LLM.
   - Deterministic AST scanners and domain analyzers identify bugs, security flaws, and performance anti-patterns.
   - Architectural drift & compliance controls (`SOC2-CC6.1`, `OWASP-LLM06`) are verified.
4. **Three-Layer GitHub Feedback**:
   - **Walkthrough Comment**: Single auto-updating comment with marker `<!-- agentblackbox-walkthrough -->`, severity overview table, change summary, and bot command guide.
   - **Inline PR Review**: Formal PR review with line comments and one-click ```suggestion code replacements.
   - **Check Run & Annotations**: Passes/fails CI status check with line-by-line annotations (batched in 50s).

### 🚀 1-Click Setup
Start the server and open the manifest setup page:
```bash
python -m agentblackbox github-app --port 8000
```
Visit `http://localhost:8000/github/manifest` to register the GitHub App on your GitHub account with pre-filled least-privilege permissions. See [docs/INSTALL.md](docs/INSTALL.md) for full setup instructions and [docs/SECURITY.md](docs/SECURITY.md) for data privacy guarantees.

---

## 🤖 Multi-Agent Hook Integration

AgentBlackBox integrates natively into AI coding agent workflows via configuration hooks. When an agent invokes a tool (shell command, file modification, web search, MCP call), the hook forwards the payload to `abb hook-ingest`, recording the action in the cryptographic HMAC hash chain.

### Agent Configuration Matrix

| Agent | Scope | Configuration File | Install Command |
| :--- | :--- | :--- | :--- |
| **Claude Code** | Project | `.claude/settings.local.json` | `abb hook-install --agent claude` |
| | Global | `~/.claude/settings.json` | `abb hook-install --agent claude --global` |
| **Codex CLI** | Project | `.codex/hooks.json` | `abb hook-install --agent codex` |
| | Global | `~/.codex/hooks.json` | `abb hook-install --agent codex --global` |
| **Cursor** | Project | `.cursor/hooks.json` | `abb hook-install --agent cursor` |
| | Global | `~/.cursor/hooks.json` | `abb hook-install --agent cursor --global` |
| **Gemini CLI** | Project | `.gemini/settings.json` | `abb hook-install --agent gemini` |
| | Global | `~/.gemini/settings.json` | `abb hook-install --agent gemini --global` |
| **All Agents** | Both | All supported configuration files | `abb hook-install --agent all [--global]` |

### Hook Verification

Check the operational health and presence of all hooks across your project or global environment:
```bash
# Verify current project hooks
abb hook-verify

# Verify global configuration hooks
abb hook-verify --global
```

---

## ⚠️ Known Limitations

1. **Pre-Execution Intent vs. Post-Execution Results**: Agent hooks record tool invocation intent (`PreToolUse`, `beforeShellExecution`, `BeforeTool`), capturing commands and file paths before execution. They do not capture stdout output or subprocess exit codes from the agent's internal runner.
2. **Codex CLI File Edit Tracking**: Codex hooks capture shell actions directly; for full AST-level tracking of edits performed by Codex, run `abb start` alongside it to enable the background `FileSystemWatcher`.
3. **Selective Read Logging**: To prevent log explosion and high storage volume during repository indexing, only reads to sensitive targets (`.env`, `.pem`, `id_rsa`, `.ssh/`, `credentials`, `.aws/`) are stored in the flight chain; non-sensitive file reads are skipped.
4. **Agent Hook Failure Isolation**: Agent hooks run fail-safe (`exit 0` with silent stdout). Any hook execution or serialization error is recorded to `<workspace>/.agentblackbox/hook_errors.log` without breaking or aborting the host agent's operation.

---

## 🏗️ Architecture Overview

```text
src/agentblackbox/
├── models/         # Domain models: Finding, Severity, GitDiff, DiffHunk, CodeContext, ReviewReport
├── context/        # Safe AST parser, dependency graph, context pruner & unified diff parser
├── scanners/       # Deterministic static scanners: AST rules (SEC, BUG, QUAL, PERF) & pattern scanner
├── analyzers/      # Semantic domain analyzers: bugs, security, quality, performance, duplication
├── integrations/   # GitClient, AI providers (Gemini, OpenAI, Anthropic, Mock), PromptBuilder
├── reporting/      # Rich terminal UI renderer, Markdown PR commenter, JSON & SARIF 2.1.0
├── core/           # ReviewEngine orchestrator & ReviewConfig
├── analysis/       # Secret detector, redactor & shlex command risk scorer
├── storage/        # SQLite WAL EventStore with HMAC tamper-evident chaining
├── daemon/         # Background supervisor & atomic session management
├── watchers/       # Filesystem observer, terminal wrapper, and IDE hooks
├── github_app/     # Production GitHub App (Webhooks, Async Queue, Session Linker, Receipts, SARIF)
├── cli/            # Typer CLI application (`abb review`, `abb analyze`, `abb start`, etc.)
```

---

## 🔒 Security Principles

1. **Non-Executing Analysis**: AgentBlackBox analyzes code exclusively through AST parsing, lexical tokenization, and pattern matching. It never calls `exec`, `eval`, or imports untrusted Python code.
2. **Redaction Prior to Storage**: All detected API tokens, private keys, and passwords are neutralized in memory.
3. **Tamper-Evident Integrity**: Keyed HMAC session chains prevent unauthorized retrospective tampering with audit logs.

---

## 📜 License

MIT License — see [LICENSE](LICENSE).
