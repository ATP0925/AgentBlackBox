# Security & Data Privacy Policy

AgentBlackBox is architected with enterprise-grade security, confidentiality, and privacy as primary design constraints.

---

## 🔒 1. Zero Code Retention Guarantee

* **No Persistent Code Storage**: Customer source code, pull request diffs, and file contents are processed **strictly in volatile memory** during active review execution.
* Diffs and file contents are never written to databases, disk logs, or external persistent stores.
* Once the review is posted to GitHub, ephemeral buffers are immediately released and garbage-collected.
* **Audit Metadata Only**: Only non-sensitive execution metadata is logged (Installation ID, Repository Name, Pull Request Number, Head Commit SHA, finding identifiers, and latency metrics).

---

## 🛡️ 2. In-Memory Secret Neutralization Prior to LLMs

* Before any diff text is passed to an AI reasoning model (Gemini, OpenAI, or Anthropic), it is scanned by `SecretDetector` for 16+ credential patterns, high-entropy tokens, private keys, and passwords.
* All matching values are redacted in memory (`[REDACTED:aws_access_key]`).
* If a secret is detected in the diff, AgentBlackBox reports it as a **Critical Finding** without echoing the raw secret value in the comment body.

---

## 🧱 3. Prompt Injection Defense

* All pull request titles, bodies, and diffs are treated as **untrusted user data**.
* Input is quarantined in `<UNTRUSTED_PR_DATA>` boundary tags.
* System prompts explicitly instruct the LLM to analyze code structure only and strictly ignore any instructions, prompts, or command overrides found inside the analyzed content.
* LLM outputs are validated against strict JSON schemas before any action is taken.

---

## 🔑 4. Least-Privilege GitHub Permissions

AgentBlackBox requests only the minimal permissions required to review code:
* `contents: read`: To inspect diff files and repository `.agentblackbox.yaml`.
* `pull_requests: write`: To post inline code comments and suggestions.
* `issues: write`: To post and update the Walkthrough overview comment.
* `checks: write`: To publish GitHub Check Runs with pass/fail status and line annotations.
* `metadata: read`: Mandatory GitHub permission.

AgentBlackBox never requests permissions for administration, organization secrets, webhooks management, or repository deletion.

---

## 🔐 5. Cryptographic Webhook Verification

Every incoming HTTP request to `/github/webhook` is verified using constant-time HMAC-SHA256 comparison against `X-Hub-Signature-256`. Requests with missing, invalid, or forged signatures are rejected immediately with HTTP 401 Unauthorized.
