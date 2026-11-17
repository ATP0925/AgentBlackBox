# 🛒 GitHub Marketplace Listing: AgentBlackBox

### App Name
**AgentBlackBox: In-Memory PR Review & Cryptographic Flight Recorder**

### Short Description (160 characters max)
*Zero-retention PR reviews & cryptographic flight recorder for AI coding agents. 1-click remediation PRs, signed review receipts, and secret protection.*

---

## 🌟 Overview

Autonomous AI coding agents edit files, execute terminal commands, and open pull requests faster than engineering teams can manually review. But when agents have shell access, traditional static analysis tools miss unobservable agent drift, wiped test suites, and accidental credential leakage.

**AgentBlackBox** is the open-core, enterprise-ready GitHub App that combines:
1. **Autonomous In-Memory PR Reviews**: Fast, diff-bounded feedback with 1-click committable suggestion blocks.
2. **Automated 1-Click Fix PR Generation (`@agentblackbox fix`)**: Automatically branches, applies safe suggestions in memory, and opens a ready-to-merge remediation PR.
3. **Cryptographically Signed Review Receipts**: Seals commit SHAs, diff SHA-256 hashes, and finding fingerprints into an append-only Merkle ledger, verifiable offline with `abb verify-receipt <id>`.
4. **Agent-Session Linkage (`AgentBlackBox-Session: <id>`)**: Verifies what an agent did locally before pushing—flagging actions blocked by PreToolUse hooks, wiped tests, or deleted files.
5. **Provable Zero Retention**: Diffs exist strictly in transient RAM buffers and are never saved to disk, databases, or permanent queues.

---

## 🚀 Key Features

### 🛠️ 1-Click Fix PR Generator (`@agentblackbox fix`)
Comment `@agentblackbox fix` on any pull request. AgentBlackBox automatically:
- Groups safe inline suggestions and security fixes.
- Applies modifications in-memory in descending line order.
- Branches from the PR head and opens a clean remediation PR ready to merge.

### 🔒 Provable Zero-Retention Architecture
- **In-Memory Volatile Processing**: Code diffs exist solely in transient RAM and are discarded immediately upon review completion.
- **Edge Secret Neutralization**: 16+ credential and API key patterns are detected and masked (`[REDACTED:<type>]`) before reaching AI reasoning models. Leaks are reported as Critical findings without echoing sensitive tokens.
- **Canary Audited**: Continuously proven by automated canary test suites scanning disk, databases, and logs.

### 📜 Signed Review Receipts & Offline Verification
Every review seals an immutable receipt containing:
- Commit SHA & Diff SHA-256 (hash only, never code)
- Config hash & Model ID
- Finding fingerprints
- Offline CLI verification: `abb verify-receipt <receipt-id>`

### 🚨 Agent-Misbehavior Drift Detection
Targeted analyzers that detect common autonomous AI agent failure modes:
- **Test Weakening**: Removed assertions, deleted test files, or injected `skip`/`xfail` markers.
- **CI/CD Tampering**: Unauthorized changes to GitHub Actions workflows.
- **Supply Chain Risks**: Typosquatted or unpinned third-party dependencies.
- **Linter Suppressions**: Introduced `# noqa` or `# type: ignore` comments.
- **Explainable PR Risk Score**: 0.0 to 10.0 transparent risk index.

---

## 🏷️ Marketplace Categories
- **Code quality**
- **Security**
- **Code review**
- **Continuous integration**

---

## 💳 Pricing Plans

| Plan | Price | Included Features |
| :--- | :---: | :--- |
| **Open Source & Community** | **$0 / month** | • Unlimited local CLI reviews (`abb review`)<br>• Universal PreToolUse hooks (Claude Code, Cursor, Codex, Gemini)<br>• Up to 50 PR reviews/month on hosted GitHub App<br>• Offline receipt verification (`abb verify-receipt`)<br>• Standard SARIF 2.1.0 exports |
| **Team Pro** | **$49 / month** | • Unlimited GitHub PR reviews<br>• **Automated 1-Click Fix PRs (`@agentblackbox fix`)**<br>• Priority Redis async queue & 202 webhook processing<br>• Batched Check Run annotations (50/batch)<br>• Custom `.agentblackbox.yaml` repository rules<br>• Slack & Discord webhook alerts |
| **Enterprise Dedicated** | **$299 / month** | • Self-hosted Docker / Kubernetes deployment<br>• Bring-your-own LLM keys (Zero data egress)<br>• SOC2-CC6.1 & OWASP-LLM06 compliance reports<br>• Dedicated onboarding & 99.9% uptime SLA |

---

## ⚡ 1-Click Installation

1. Click **Install App** on the GitHub Marketplace.
2. Select target repositories or your entire organization.
3. Open or update any Pull Request—AgentBlackBox starts reviewing instantly in memory.
