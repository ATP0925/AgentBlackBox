# 🚀 AgentBlackBox v0.5.0: Production Hosted GitHub App, Signed Review Receipts & Provable Zero Retention

AgentBlackBox v0.5.0 elevates AgentBlackBox from a local flight recorder into a production-grade hosted GitHub App and cryptographic verification platform for autonomous AI coding agents.

This release introduces high-assurance differentiators specifically engineered for agentic workflows: **Signed Review Receipts**, **Agent-Session Linkage**, **Agent-Misbehavior Drift Rules**, and **Provable Zero Retention**.

---

## 🌟 Major Highlights in v0.5.0

### 1. 📜 Cryptographically Signed Review Receipts (`abb verify-receipt`)
Every review run cryptographically seals its findings into the AgentBlackBox Merkle flight ledger:
- **Zero-Retention Hashes**: Records commit SHA, diff SHA-256 (hash only, never source code), config hash, model ID, and finding fingerprints.
- **Offline CLI Verification**: Anyone can verify receipt integrity offline without network access or cloud dependencies:
  ```powershell
  # Windows PowerShell
  abb verify-receipt <receipt-id>
  ```
  ```bash
  # Linux / macOS
  abb verify-receipt <receipt-id>
  ```
- **Tamper Evident**: Any modification to the flight ledger or finding hashes triggers instant verification failure.

### 2. 🔗 Agent-Session Linkage (`AgentBlackBox-Session: <id>`)
Connects what an agent did during local execution to the resulting pull request:
- Pull request descriptions, branch names, or commit trailers carrying `AgentBlackBox-Session: <session-id>` are automatically linked.
- The GitHub App audits the agent's pre-commit flight logs: tools invoked, terminal commands blocked by PreToolUse hooks, files deleted, and test suites modified.
- If a session chain is tampered or mismatched, a critical finding is reported on the PR.

### 3. 🚨 Agent-Misbehavior Drift Rules & Explainable Risk Scoring
Static analyzers specifically targeting common autonomous AI agent pitfalls:
- **Test Weakening Detection**: Catches deleted unit tests, removed assertions, or newly injected `@pytest.mark.skip` / `xfail` markers intended to force passing builds.
- **CI/CD Tampering**: Detects modified GitHub Actions workflows or disabled security gates.
- **Dependency Guard**: Flags suspicious or typosquatted packages in `pyproject.toml`, `requirements.txt`, and `package.json`.
- **Linter & Type Suppressions**: Flags newly introduced `# noqa`, `# type: ignore`, and `/* eslint-disable */`.
- **Explainable PR Risk Score**: Computes a transparent 0.0 to 10.0 risk rating itemized across test health, security, and supply chain.

### 4. 🔒 Provable Zero Retention & Secret Redaction
Guaranteed customer privacy and intellectual property protection:
- **In-Memory Volatile Processing**: Code diffs exist solely in transient RAM buffers and are immediately garbage-collected upon review completion.
- **Edge Secret Neutralization**: 16+ credential and API key patterns are detected and masked (`[REDACTED:<type>]`) before any text reaches an AI reasoning model.
- **Continuous Canary Verification**: Automated test suite (`test_zero_retention_canary.py`) injects high-entropy canary tokens and verifies zero occurrences across databases, logs, queues, and disk.

### 5. ⚡ Enterprise GitHub App Hardening & 1-Click Manifest Flow
- **1-Click Manifest Setup**: Register the GitHub App via GitHub's official manifest API (`POST /app-manifests/{code}/conversions`) with least-privilege permissions.
- **RS256 JWT & Cached Installation Tokens**: Ephemeral authentication tokens refreshed automatically with clock-drift buffers.
- **Single Auto-Updating Walkthrough**: One comment edited in place via hidden idempotency markers (`<!-- agentblackbox-walkthrough -->`).
- **Diff-Bounded Suggestions**: Inline comments strictly mapped to diff hunks with one-click committable fixes.
- **Batched Check Run Annotations**: 50-annotation batching with configurable `fail_on` severity gates.
- **Async Queue & Circuit Breakers**: Non-blocking 202 webhook reception with Redis or in-memory backing, dead-letter queues, and hourly rate caps.

---

## 📊 Verification & Test Metrics

- **Test Suite**: 288 passed, 0 failed across unit, integration, and security tests.
- **Eval Benchmark Suite**: Precision > 90%, False Positive Rate < 5% on seeded security and agent-misbehavior corpora.
- **Zero-Retention Assurance**: 100% verified by recursive canary scan.

---

## 🛠️ Upgrading to v0.5.0

**Windows (PowerShell):**
```powershell
pip install --upgrade .
abb --version
```

**Linux / macOS:**
```bash
pip install --upgrade .
abb --version
```
