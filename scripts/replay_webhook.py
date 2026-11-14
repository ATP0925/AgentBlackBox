#!/usr/bin/env python3
"""Script to replay GitHub webhook payloads with valid HMAC-SHA256 signatures for local testing."""

import argparse
import hashlib
import hmac
import os
import sys
import uuid
from pathlib import Path

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a GitHub webhook payload against local AgentBlackBox server.")
    parser.add_argument("payload_file", type=Path, help="Path to JSON payload file")
    parser.add_argument("--url", default="http://localhost:8000/github/webhook", help="Webhook endpoint URL")
    parser.add_argument("--secret", default=None, help="Webhook secret (defaults to GITHUB_WEBHOOK_SECRET env var)")
    parser.add_argument("--event", default="pull_request", help="GitHub event name (default: pull_request)")

    args = parser.parse_args()

    if not args.payload_file.is_file():
        print(f"Error: Payload file not found: {args.payload_file}", file=sys.stderr)
        sys.exit(1)

    secret = args.secret or os.environ.get("GITHUB_WEBHOOK_SECRET", "dev-webhook-secret")
    payload_bytes = args.payload_file.read_bytes()

    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    signature_header = f"sha256={mac}"
    delivery_id = str(uuid.uuid4())

    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": signature_header,
        "X-GitHub-Event": args.event,
        "X-GitHub-Delivery": delivery_id,
        "User-Agent": "GitHub-Hookshot/replay",
    }

    print(f"Sending {args.event} to {args.url} (delivery: {delivery_id[:8]}...)...")
    try:
        resp = httpx.post(args.url, content=payload_bytes, headers=headers, timeout=10.0)
        print(f"Response: {resp.status_code} {resp.reason_phrase}")
        print(resp.text)
    except Exception as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
