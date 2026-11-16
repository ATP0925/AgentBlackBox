# AgentBlackBox Data Handling & Zero-Retention Specification

AgentBlackBox is engineered from the ground up on a **Provable Zero-Retention** architectural principle. Customer source code, pull request diffs, code comments, and proprietary intellectual property are processed exclusively in volatile memory (RAM) and are **never persisted** to disks, databases, log aggregators, or permanent queues.

---

## 1. Data Classification Matrix

| Data Element | Processed in Memory | Persisted to Database / Disk | Cryptographically Hashed |
| :--- | :---: | :---: | :---: |
| **Customer Source Code** | ✅ Yes (ephemeral) | ❌ **NEVER** | ❌ Never |
| **Pull Request Diffs / Patches** | ✅ Yes (ephemeral) | ❌ **NEVER** | ✅ SHA-256 hash in Review Receipt |
| **Code Comments & Author Notes** | ✅ Yes (ephemeral) | ❌ **NEVER** | ❌ Never |
| **Credentials & Secrets (detected in diffs)** | ✅ In-memory masked | ❌ **NEVER** | ❌ Never (redacted before analysis) |
| **PR Metadata** (Owner, Repo, PR #, Head SHA) | ✅ Yes | ✅ Yes (Installation & Review State) | N/A |
| **Rule Violations & Findings** | ✅ Yes | ✅ Rule ID, Line #, Severity | ✅ Sorted findings hash in receipt |
| **Operational Metrics** (Tokens, Latency) | ✅ Yes | ✅ Yes (Aggregated counts) | N/A |
| **Signed Review Receipts** | ✅ Yes | ✅ Stored in Merkle Flight Ledger | ✅ HMAC-SHA256 Merkle root |

---

## 2. Architectural Zero-Retention Guarantees

### A. Ephemeral In-Memory Pipeline
When a webhook delivers a pull request event, AgentBlackBox reads the unified diff from GitHub directly into an in-memory buffer:
1. The diff is parsed into AST nodes and memory data structures (`FileDiff`, `DiffHunk`).
2. Regex-based secret scanners scan and redact all high-entropy secrets in RAM before any downstream processing or model queries.
3. Analysis engines (AST scanners, Agent Misbehavior checks, AI review) execute within bounded execution contexts.
4. Once findings are produced and posted to GitHub, the diff buffer is unreferenced and reclaimed by garbage collection.

### B. Lightweight Job Descriptors (`ReviewJobDescriptor`)
Background review tasks scheduled across asynchronous workers or Redis/RQ queues contain **only** reference identifiers:
```python
@dataclass
class ReviewJobDescriptor:
    owner: str
    repo: str
    pull_number: int
    head_sha: str
    delivery_id: str
    installation_id: Optional[int] = None
```
Raw diffs, file contents, and patch hunks are strictly excluded from queue payloads.

### C. Cryptographic Review Receipts (Hash-Only Flight Ledger)
The tamper-evident flight recorder logs review events to establish non-repudiation without persisting code. Review receipts store exclusively:
- `diff_hash`: `SHA-256(raw_diff)`
- `config_hash`: `SHA-256(.agentblackbox.yaml)`
- `findings_hash`: `SHA-256(sorted_rule_ids)`
- PR and Commit identifiers

Anyone with access to the Git repository can verify the review offline using:
```powershell
agentblackbox verify-receipt abb-rcpt-xxxxxxxxxxxx
```

---

## 3. Automated Test Verification Matrix

Every zero-retention and security claim is tested continuously in the automated test suite:

| Claim & Guarantee | Verifying Automated Test | Verification Mechanism |
| :--- | :--- | :--- |
| **Provable Zero Diff Persistence** | `tests/github_app/test_zero_retention_canary.py::test_zero_retention_canary_audit` | Injects high-entropy canary tokens into PR diff; recursively scans SQLite DB tables, log files, and disk storage to verify 0 occurrences. |
| **Pre-Analysis Secret Redaction** | `tests/github_app/test_security.py::test_redact_diff_secrets_detects_and_redacts` | Scans unified diffs containing live credential formats (AWS keys, tokens); verifies secrets are redacted before model ingestion and never leak into finding titles or impact text. |
| **Queue Code Exclusion** | `tests/github_app/test_rate_limiter_and_queue.py::test_queue_dead_letter_and_descriptor` | Asserts job queue descriptors and dead-letter payloads store only repo IDs and commit SHAs with zero diff contents. |
| **Cryptographic Receipt Integrity** | `tests/github_app/test_receipts.py::test_generate_and_verify_signed_receipt` | Verifies review receipts are signed into the Merkle flight ledger and validatable offline via SHA-256 hash chaining. |
| **Untrusted PR Prompt Injection Fencing** | `tests/github_app/test_security.py::test_sanitize_prompt_input` | Verifies untrusted PR text is fenced inside `<UNTRUSTED_PR_DATA>` blocks and stripped of system override tokens. |
| **Trojan Source & Invisible Unicode Stripping** | `tests/github_app/test_rate_limiter_and_queue.py::test_security_adversarial_unicode_and_bidi` | Neutralizes zero-width characters (`\u200b`, `\ufeff`) and bidirectional overrides (`\u202a`–`\u202e`, `\u2066`–`\u2069`). |
| **Strict Model Output Schema Enforcement** | `tests/github_app/test_rate_limiter_and_queue.py::test_validate_model_output_strict_schema` | Rejects non-JSON output and tool calls; ensures model responses can only generate declarative review findings. |
