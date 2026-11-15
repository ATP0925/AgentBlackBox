# AgentBlackBox Architecture & Open-Core Specification

AgentBlackBox is an open-core autonomous AI guardrail and in-memory PR review engine designed for engineering teams adopting autonomous coding agents (Claude Code, Cursor, Codex CLI, Gemini CLI).

---

## 1. Open-Core Boundary Matrix

AgentBlackBox maintains a transparent, developer-first boundary between its fully open-source local core and its production GitHub App capabilities:

| Component | Open-Source Core (`src/agentblackbox/`) | Production GitHub App (`src/agentblackbox/github_app/`) |
| :--- | :---: | :---: |
| **Tamper-Evident Flight Recorder** | ✅ Keyed HMAC-SHA256 SQLite WAL engine | ✅ Head-tip checkpointing into GitHub App reviews |
| **Universal PreToolUse Hooks** | ✅ Claude Code, Cursor, Codex, Gemini | ✅ Linked session audit (`AgentBlackBox-Session`) |
| **Deterministic AST Analyzers** | ✅ Bugs, Security, Perf, Complexity | ✅ Incremental diff mapper (`DiffMapper`) |
| **Secret Detection & Redaction** | ✅ Regex & Entropy In-Memory Redactor | ✅ Pre-analysis edge redaction |
| **Local CLI (`abb`)** | ✅ Review, analyze, rollback, blame, ci-gate | ✅ `abb verify-receipt <id>` offline verification |
| **GitHub App Server** | ❌ (CLI review only) | ✅ FastAPI webhook listener + RS256 App JWT auth |
| **Background Review Queue** | ❌ (Synchronous) | ✅ Async queue with Redis backend & dead-letter queue |
| **Cryptographic Review Receipts** | ❌ | ✅ Signed Merkle receipts with offline verification |
| **Agent Misbehavior Scanner** | ❌ | ✅ Detects deleted asserts, skipped tests, CI tampers |
| **Zero-Retention Guarantee** | ✅ Local storage | ✅ Provable RAM-only processing verified via canary tests |
| **Feedback Calibration Telemetry**| ❌ | ✅ Thumbs up/down rule confidence tuning |

---

## 2. In-Memory PR Review Data Flow

```text
GitHub Pull Request Webhook
        │ (X-Hub-Signature-256 Verified BEFORE parsing)
        ▼
FastAPI Ingestion Endpoint (`/github/webhook`)
        │ 202 Accepted returned immediately (< 20ms)
        │ Delivery ID recorded in Idempotency Store (TTL eviction)
        ▼
Background Review Queue (`ReviewJobQueue`)
        │ Enqueues ReviewJobDescriptor (IDs & commit SHAs ONLY; ZERO code)
        ▼
Incremental Diff Engine (`DiffMapper`)
        │ Incremental mode: reviews only last_reviewed_sha -> new_head_sha
        │ Skips lockfiles, minified bundles, vendor packages, and binary files
        ▼
Security Pre-Processor (`src/agentblackbox/github_app/security.py`)
        │ In-Memory Secret Redaction: High-entropy credentials masked to [REDACTED:<type>]
        │ Fences untrusted inputs inside <UNTRUSTED_PR_DATA> containers
        │ Neutralizes invisible unicode and bidirectional Trojan Source overrides
        ▼
Multi-Dimensional Analysis Pipeline
   ├── Agent Misbehavior Scanner (`agent_drift.py`)
   │      - Deleted assertions in tests (`DRIFT-ASSERT-DELETED`)
   │      - Weakened/skipped tests (`DRIFT-TEST-WEAKENED`)
   │      - Tampered CI/CD workflows (`DRIFT-CI-WORKFLOW-ALTERED`)
   │      - Suppressed linters / `# noqa` abuse (`DRIFT-LINTER-SUPPRESSED`)
   │      - Generates PR Risk Score breakdown (0.0 - 10.0)
   ├── Deterministic AST Scanners (`src/agentblackbox/scanners/`)
   │      - AST Security (CWE-89, CWE-78, CWE-798, CWE-502)
   │      - AST Bug Detector (unhandled None, resource leaks, mutables)
   │      - AST Quality & Performance (O(N^2) complexity, dead code)
   └── Agent-Session Linker (`session_linker.py`)
          - Extracts `AgentBlackBox-Session: <id>` from PR body, branch, or commits
          - Audits session flight ledger: commands run, files touched, blocked actions
          - Flags broken chains with `SEC-TAMPERED-AGENT-SESSION`
        ▼
Cryptographic Review Receipt Manager (`receipts.py`)
        │ Computes SHA-256 hashes: diff_hash, config_hash, findings_hash
        │ Signs receipt into HMAC flight ledger and returns receipt ID
        ▼
Output Delivery Layer
   ├── Walkthrough Comment: Single comment edited in place via hidden marker
   ├── PR Review: Inline comments inside diff hunks with one-click ```suggestion blocks
   ├── Check Run: Completed status with conclusion based on fail_on threshold + batch annotations
   └── SARIF Export: Standard SARIF 2.1.0 output for GitHub Security tab
```

---

## 3. Cryptographic Non-Repudiation Model

Review receipts allow developers and auditors to prove that a pull request was audited without storing customer code:

$$\text{Receipt} = \langle \text{Owner}, \text{Repo}, \text{PR\#}, \text{HeadSHA}, H(\text{Diff}), H(\text{Config}), H(\text{Findings}), T \rangle$$

The receipt is appended to the local SQLite WAL ledger with HMAC-SHA256 chaining:

$$\text{Hash}_n = \text{HMAC-SHA256}(K, \text{Seq}_n \parallel \text{SessionID} \parallel \text{Hash}_{n-1} \parallel \text{PayloadHash}_n)$$

Anyone with access to the repo can run:
```powershell
agentblackbox verify-receipt abb-rcpt-xxxxxxxxxxxx
```
The CLI traverses the hash chain backwards to genesis. If any event or receipt was modified or deleted, verification fails immediately.
