"""GitHub App Manifest 1-Click Registration Flow.

Automates GitHub App creation via GitHub's official Manifest conversion API:
https://docs.github.com/en/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app-from-a-manifest
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
import httpx
import structlog

from agentblackbox.github_app.webhook import auth_manager

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["github-manifest"])


def get_default_manifest(base_url: str) -> dict:
    """Generate GitHub App Manifest configuration."""
    clean_url = base_url.rstrip("/")
    return {
        "name": f"AgentBlackBox-{os.environ.get('USER', 'Bot')[:8]}",
        "url": "https://github.com/ATP0925/AgentBlackBox",
        "hook_attributes": {
            "url": f"{clean_url}/github/webhook",
            "active": True,
        },
        "redirect_url": f"{clean_url}/github/manifest/callback",
        "callback_urls": [f"{clean_url}/github/manifest/callback"],
        "public": True,
        "default_permissions": {
            "contents": "read",
            "pull_requests": "write",
            "issues": "write",
            "checks": "write",
            "metadata": "read",
        },
        "default_events": [
            "pull_request",
            "issue_comment",
            "installation",
            "installation_repositories",
        ],
    }


@router.get("/manifest", response_class=HTMLResponse)
async def generate_manifest_page(request: Request) -> str:
    """Render 1-click button to register this instance as a GitHub App on GitHub."""
    base_url = str(request.base_url).rstrip("/")
    manifest = get_default_manifest(base_url)
    manifest_json = json.dumps(manifest)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AgentBlackBox — 1-Click GitHub App Setup</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2.5rem; max-width: 520px; width: 100%; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }}
            h1 {{ font-size: 1.5rem; margin-top: 0; color: #38bdf8; display: flex; align-items: center; gap: 0.5rem; }}
            p {{ line-height: 1.6; color: #94a3b8; }}
            .btn {{ display: inline-block; width: 100%; box-sizing: border-box; background: #2563eb; color: #fff; border: none; padding: 0.85rem; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; margin-top: 1.5rem; }}
            .btn:hover {{ background: #1d4ed8; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🐰 AgentBlackBox Setup</h1>
            <p>Click below to register this instance as a native GitHub App with least-privilege permissions (PR reviews, checks, read contents).</p>
            <form action="https://github.com/settings/apps/new" method="post">
                <input type="hidden" name="manifest" value='{manifest_json}'>
                <button type="submit" class="btn">🚀 Register GitHub App on GitHub</button>
            </form>
        </div>
    </body>
    </html>
    """


@router.get("/manifest/callback", response_class=HTMLResponse)
async def manifest_callback(code: str = Query(...)) -> str:
    """Exchange conversion code for GitHub App ID, private key PEM, and webhook secret."""
    conversion_url = f"https://api.github.com/app-manifests/{code}/conversions"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                conversion_url,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "AgentBlackBox-Setup"},
            )
            resp.raise_for_status()
            app_data = resp.json()
    except Exception as exc:
        logger.error("manifest_conversion_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to exchange manifest code: {exc}",
        )

    app_id = str(app_data.get("id"))
    pem = app_data.get("pem", "")
    webhook_secret = app_data.get("webhook_secret", "")

    # Save to local .env and update in-memory auth_manager
    env_path = Path(".env")
    env_lines = []
    if env_path.exists():
        env_lines = [
            line for line in env_path.read_text(encoding="utf-8").splitlines()
            if not line.startswith(("GITHUB_APP_ID=", "GITHUB_PRIVATE_KEY=", "GITHUB_WEBHOOK_SECRET="))
        ]

    # Save PEM to secure file
    pem_path = Path(".agentblackbox/github_app.pem")
    pem_path.parent.mkdir(parents=True, exist_ok=True)
    pem_path.write_text(pem, encoding="utf-8")

    # Lock permissions on POSIX
    if sys.platform != "win32":
        try:
            pem_path.chmod(0o600)
        except Exception:
            pass

    env_lines.append(f"GITHUB_APP_ID={app_id}")
    env_lines.append(f"GITHUB_PRIVATE_KEY_PATH={pem_path.as_posix()}")
    env_lines.append(f"GITHUB_WEBHOOK_SECRET={webhook_secret}")

    env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    if sys.platform != "win32":
        try:
            env_path.chmod(0o600)
        except Exception:
            pass

    # Update in-memory auth singleton
    auth_manager.app_id = app_id
    auth_manager.private_key = pem
    auth_manager.webhook_secret = webhook_secret

    logger.info("github_app_configured_successfully", app_id=app_id)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AgentBlackBox — GitHub App Configured</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .card {{ background: #1e293b; border: 1px solid #10b981; border-radius: 12px; padding: 2.5rem; max-width: 520px; width: 100%; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); text-align: center; }}
            h1 {{ color: #10b981; margin-top: 0; }}
            p {{ color: #94a3b8; line-height: 1.6; }}
            .badge {{ display: inline-block; background: #064e3b; color: #34d399; padding: 0.4rem 0.8rem; border-radius: 6px; font-weight: 600; font-family: monospace; margin: 1rem 0; }}
            a.btn {{ display: inline-block; background: #2563eb; color: #fff; padding: 0.8rem 1.5rem; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 1rem; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>✅ Setup Complete!</h1>
            <p>AgentBlackBox GitHub App has been created and credentials saved securely to <code>.env</code>.</p>
            <div class="badge">App ID: {app_id}</div>
            <br>
            <a href="https://github.com/settings/apps" class="btn" target="_blank">Install App on Your Repositories &rarr;</a>
        </div>
    </body>
    </html>
    """
