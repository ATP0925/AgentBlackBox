# AgentBlackBox (`abb`)

**The Flight Recorder & Automated Code Review Guard for Autonomous AI Agents.**

AgentBlackBox protects your codebase across two phases of autonomous AI coding (Claude Code, Cursor, Antigravity, OpenCode):
1. **Live Flight Recorder (`abb start`, `abb run`, `abb verify`, `abb blame`)**: Records file mutations, git ref transitions, and shell executions in a tamper-evident SQLite WAL hash chain—redacting secrets *before* they touch disk and scoring command risk via `shlex` token analysis.
2. **Automated Diff & Static Code Review (`abb review`, `abb analyze`)**: Runs deterministic AST/CWE security scanners, O(N) structural duplication analysis, and AI-assisted diff review (`gemini-2.5-flash` / OpenAI / Anthropic / Offline) before agent changes are merged.

---

## 🌟 Key Capabilities

### 1. Advanced Automated Code Review (`abb review`)
- **Git Diff & Pull Request Analysis**: Inspects unstaged working tree diffs, staged commits, branch comparisons (`--base main`), or specific commit ranges (`HEAD~1..HEAD`).
- **Diff Attribution**: Precisely maps identified issues to added or modified diff hunks.
- **Context-Aware Cross-File Intelligence**: Safely parses ASTs without executing untrusted code, resolving imports, call hierarchies, and multi-file dependencies.
- **Context Token Budgeting & Pruning**: Intelligently stubs irrelevant symbols and distills critical dependencies into token-budgeted prompts for LLM reasoning.

### 2. Comprehensive Repository & File Analysis (`abb analyze`)
- **Multi-Level Scopes**: Analyze individual files or recursively scan entire repositories.
- **Multi-Tier Severity System**: Every finding is strictly classified into:
  - 🔴 **Critical**: Remote execution, SQL/Command injection, active credential leakage.
  - 🟠 **High**: Mutable defaults, unhandled exceptions in regex/logic, unsafe deserialization.
  - 🟡 **Medium**: Code duplication, copy-paste clones, quadratic complexity in loops.
  - 🔵 **Low**: Function length thresholds, excessive parameters, maintainability smells.
  - ⚪ **Info**: Clean idioms, docstrings, and style suggestions.
- **Actionable Remediation**: Every issue contains the exact file location, rule ID, CWE tag, clear problem statement, real-world impact explanation ("Why it matters"), and syntax-highlighted replacement code snippet.

### 3. Hybrid Analysis Engine (Deterministic + AI)
- **Fast Deterministic Scanners**: AST visitors and pattern detectors run in milliseconds without external network calls.
- **Pluggable AI Reasoning Layer**: Supports Google Gemini (`gemini-2.5-flash`), OpenAI-compatible models (`gpt-4o-mini`, Ollama, vLLM, DeepSeek, Groq), Anthropic, and offline deterministic modes (`--ai offline`).
- **Zero Execution Risk**: Pure static analysis that NEVER imports or executes analyzed project code.

### 4. Enterprise-Ready Reporting & CI/CD Export
- **Rich Terminal UI**: Formatted console panels, color badges, and syntax-highlighted code previews.
- **GitHub PR Review Comments**: Markdown output (`--format markdown`) ready to paste into GitHub PR discussions.
- **SARIF 2.1.0 Standard**: Export standard SARIF JSON (`--format sarif --output report.sarif`) for native GitHub Code Scanning alerts and security dashboards.
- **Machine-Readable JSON**: Full structured report with execution metrics and severity breakdowns.

### 5. AI Coding Agent Audit Flight Recorder
- **Redact-First Storage**: API keys, JWTs, and high-entropy secrets are scrubbed in memory before disk writes.
- **Tamper-Evident Hash Chain**: Keyed HMAC SHA-256 event chaining with external head-tip checkpoints.
- **Command Risk Scorer**: Evaluates shell commands via `shlex` AST token analysis on a 0.0–10.0 risk scale.
- **File Blame & Timeline Replay**: Traces exact agent tool invocations and file mutations (`abb blame`).

---

## 🚀 Quickstart

```bash
# Clone and install
git clone https://github.com/ATP0925/AgentBlackBox.git
cd AgentBlackBox
pip install -e ".[dev]"

# 1. Review current uncommitted git changes (working tree)
abb review

# 2. Review a pull request or branch diff against main
abb review feature-branch --base main --format markdown

# 3. Export SARIF 2.1.0 report for GitHub Advanced Security
abb review --format sarif --output results.sarif

# 4. Analyze an entire repository for bugs, security risks, and duplication
abb analyze . --min-severity medium

# 5. Enable AI reasoning layer with Gemini or OpenAI
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
| `abb hook-install` | Install Claude Code `PreToolUse` attribution hook into settings. |
| `abb sessions` | List recorded sessions with event counts and risk summaries. |
| `abb search <query>` | Search redacted event payloads, file paths, and command histories. |
| `abb blame <file>` | Show reverse-chronological modification history and agent attribution. |
| `abb alerts` | List unacknowledged secret detections and high-risk command alerts. |
| `abb verify <session_id>` | Verify SQLite HMAC hash chain and external head-tip checkpoint. |
| `abb export-checkpoint <id>` | Export head-tip checkpoint JSON to an external file or stdout. |
| `abb report <session_id>` | Export standalone timeline report (`--format html`, `json`, or `csv`). |
| `abb serve` | Launch localhost (`127.0.0.1`) FastAPI & WebSocket inspector. |

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
└── cli/            # Typer CLI application (`abb review`, `abb analyze`, `abb start`, etc.)
```

---

## 🔒 Security Principles

1. **Non-Executing Analysis**: AgentBlackBox analyzes code exclusively through AST parsing, lexical tokenization, and pattern matching. It never calls `exec`, `eval`, or imports untrusted Python code.
2. **Redaction Prior to Storage**: All detected API tokens, private keys, and passwords are neutralized in memory.
3. **Tamper-Evident Integrity**: Keyed HMAC session chains prevent unauthorized retrospective tampering with audit logs.

---

## 📜 License

MIT License — see [LICENSE](LICENSE).
