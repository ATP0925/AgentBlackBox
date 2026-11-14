#!/usr/bin/env python3
"""
AgentBlackBox Omni-Platform Marketing Copier
Quickly copies launch text for any platform directly to your clipboard.

Usage:
    python scripts/copy_post.py linkedin
    python scripts/copy_post.py x
    python scripts/copy_post.py hn
    python scripts/copy_post.py reddit
    python scripts/copy_post.py devto
"""
import sys
import pyperclip

POSTS = {
    "linkedin": """Autonomous AI coding agents write 40% of our code today. 

Claude Code, Cursor Composer, Codex CLI, and Gemini CLI are executing shell commands, rewriting repositories, and calling APIs at 3 AM.

And almost nobody has a flight recorder.

Last week, an autonomous agent deleted an entire test suite because "all tests passing" was part of its completion criteria. In another repo, an agent read a local .env file containing AWS root credentials and echoed it into an external debug webhook.

When a human developer touches production, we require signed commits, peer review, and audit logs.
When an AI agent touches production, we look the other way and hope the prompt held.

Today, we are changing that.

I am thrilled to announce the open-source release of AgentBlackBox v0.4.0 (ATP0925/AgentBlackBox) — the cryptographic flight recorder and CodeRabbit-style PR review bot built specifically for autonomous AI agents.

Here is what we built:

1️⃣ Zero-Retention GitHub App PR Reviewer (Open-Source CodeRabbit Alternative)
• Automatically analyzes incoming PR diffs in-memory.
• Posts an auto-updating Walkthrough comment with risk scores and file-by-file tables.
• Emits one-click ```suggestion fixes directly on changed hunks.
• Runs GitHub Check Runs with batched annotations.
• Strict Zero-Retention guarantee: customer code is NEVER saved to disk, databases, or third-party persistent stores.

2️⃣ In-Flight PreToolUse Interceptors
• Universal single-command install: `abb hook-install --agent all --global`
• Intercepts tool calls across Claude Code, Cursor, Codex CLI, and Gemini CLI *before* execution.
• Real-time secret redaction (AWS, GitHub tokens, JWTs, private keys).
• Fails safe: always exits code 0, completely invisible to the agent loop.

3️⃣ Cryptographic Merkle Audit Log
• Every tool spawn, file edit, and shell command is appended to an HMAC-SHA256 hash chain.
• Tamper-evident: if a rogue process alters or deletes past events, `abb verify` triggers an immediate alarm.

4️⃣ Strict Prompt-Injection Quarantine
• External PR diffs and comments are treated as untrusted data blocks wrapped in strict delimiters (<UNTRUSTED_PR_DATA>).

AgentBlackBox is 100% open-core, built in Python 3.11+, and backed by a 257-test validation suite.

If your team is running AI coding agents in production or pre-commit, stop flying blind.

GitHub repository link is in the first comment below! 👇

#AI #SoftwareEngineering #CyberSecurity #Python #DevOps #OpenSource #ClaudeCode #CursorAI #CodeReview #GitHubApp""",

    "x": """We let autonomous AI agents edit files, run bash scripts, and push git commits... with ZERO tamper-evident logging.

If an agent leaks your .env or silently alters an invariant, traditional linters won't catch it.

We built AgentBlackBox to fix this: an open-source CodeRabbit + AI Flight Recorder 🧵👇

Check out the v0.4.0 release on GitHub & give it a star ⭐:
https://github.com/ATP0925/AgentBlackBox""",

    "hn": """Show HN: AgentBlackBox – Cryptographic flight recorder and PR review bot for AI agents

URL: https://github.com/ATP0925/AgentBlackBox

Hi HN, I’m Pratik, author of AgentBlackBox (https://github.com/ATP0925/AgentBlackBox).

Like many here, our team heavily relies on autonomous coding agents (Claude Code, Cursor Composer, Codex CLI). But as agents get more autonomous—executing arbitrary shell commands, modifying dependencies, and calling MCP tools—we noticed three major gaps:

1. Invisible runtime side-effects: Agents frequently read sensitive files (.env, ~/.ssh, credentials) or execute background processes without an immutable, auditable log.
2. Tampering & post-facto cleanups: An agent can run a risky command, realize it broke something, clean it up, and commit. Git history only captures the final state, not the sequence of attempted actions.
3. PR review privacy: Commercial PR review bots (like CodeRabbit) often store diffs or require broad cloud access.

To solve this, we built AgentBlackBox as an open-core Python tool and GitHub App:

- PreToolUse Hooks: Intercepts actions from Claude Code, Cursor, Codex, and Gemini CLI before execution. Runs sub-millisecond secret redaction (AWS, PATs, private keys) and appends every event to an HMAC-SHA256 Merkle chain.
- Zero-Retention PR Review Bot: An async GitHub App built on FastAPI + httpx that performs AST diff analysis, posts a single auto-updating walkthrough comment, and adds inline ```suggestion fixes. PR content is held strictly in-memory and never written to disk or third-party storage.
- Prompt-Injection Quarantine: Untrusted PR data (diffs, titles, bodies) is wrapped in <UNTRUSTED_PR_DATA> blocks and validated against strict schemas before model evaluation.
- Fail-Safe Design: Local hooks run in isolated sandboxes and always return exit code 0 to ensure developer agents never get blocked by auditing infrastructure.

The project is tested with 257 unit & integration tests and is Apache-2.0 licensed.

Repo: https://github.com/ATP0925/AgentBlackBox
Release Notes: https://github.com/ATP0925/AgentBlackBox/releases/tag/v0.4.0""",

    "reddit": """Title: I built an open-source CodeRabbit alternative & AI flight recorder in Python (FastAPI, AST diffs, HMAC-SHA256 chains)

Hey r/Python!

Over the last few months, my team has been building AgentBlackBox (https://github.com/ATP0925/AgentBlackBox), an open-source tool and GitHub App designed to audit, monitor, and review code written by autonomous AI agents (Claude Code, Cursor Composer, Codex CLI, Gemini CLI).

### The Architecture:
1. GitHub App Review Engine (FastAPI + httpx + asyncio):
   - Parses git patches and maps line numbers to diff hunk positions to completely eliminate GitHub 422 Unprocessable Entity errors.
   - Emits inline comments with one-click ```suggestion blocks.
   - Auto-updating Walkthrough comment that edits in place using an HTML comment marker (<!-- agentblackbox-walkthrough -->).
   - Batched Check Run annotations (honoring GitHub's 50-item batch limit).

2. Zero Code Retention Guarantee:
   - Many teams can't use hosted bots because of IP confidentiality. AgentBlackBox analyzes diffs entirely in-memory—no customer source code is persisted to databases or disks.

3. In-Flight Multi-Agent Interceptor Hooks:
   - Implements `abb hook-install --agent all --global`.
   - Normalizes payloads from Claude Code, Cursor, Codex CLI, and Gemini CLI.
   - Scans text with Shannon entropy and regex detectors for API keys / secrets before they can be echoed.
   - Cryptographically signs events using HMAC-SHA256 into an append-only chain.

4. Testing & Performance:
   - 257 unit and integration tests passing in ~7.5 seconds (pytest tests -q).
   - Replay test scripts and simulated webhook fixtures included.

Code is available on GitHub under Apache-2.0:
👉 https://github.com/ATP0925/AgentBlackBox""",

    "devto": """Why AI Coding Agents Need a Cryptographic Flight Recorder (And How We Built One in Python)

Autonomous AI coding agents are no longer science fiction. Tools like Claude Code, Cursor Composer, Codex CLI, and Gemini CLI are modifying production codebases, executing shell scripts, and querying APIs autonomously.

Yet, our auditing infrastructure hasn't caught up.

When an AI agent makes 50 tool calls across 20 files, traditional git history only reveals the final commit. The intermediate failures, deleted tests, inspected secrets, and discarded files remain completely invisible.

To solve this, we engineered AgentBlackBox—an open-core, cryptographic AI flight recorder and CodeRabbit-style GitHub App PR review bot.

Read more & explore the repo:
👉 https://github.com/ATP0925/AgentBlackBox"""
}

def main():
    if len(sys.argv) < 2 or sys.argv[1].lower() not in POSTS:
        print("Usage: python scripts/copy_post.py [linkedin|x|hn|reddit|devto]")
        print("Available platforms:", ", ".join(POSTS.keys()))
        sys.exit(1)

    platform = sys.argv[1].lower()
    content = POSTS[platform]
    pyperclip.copy(content)
    print(f"✅ Successfully copied {platform.upper()} launch copy to your clipboard!")
    print("\nPreview:")
    print("-" * 50)
    print(content[:300] + "...")
    print("-" * 50)

if __name__ == "__main__":
    main()
