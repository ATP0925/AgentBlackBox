# Installing & Configuring the AgentBlackBox GitHub App

AgentBlackBox acts as a self-hosted or cloud-managed Autonomous AI PR Review & Security Engine that automates in-memory pull request reviews, architectural drift checks, and security audits.

---

## ⚡ Method 1: 1-Click Manifest Setup (Recommended)

GitHub Apps support automated 1-click registration via Manifests.

1. **Start the AgentBlackBox server**:
   ```bash
   python -m agentblackbox github-app --host 0.0.0.0 --port 8000
   ```
2. **Open the Manifest page in your browser**:
   Navigate to `http://localhost:8000/github/manifest` (or your public domain).
3. **Click "Register GitHub App on GitHub"**:
   - You will be redirected to GitHub with pre-filled permissions and events.
   - Click **Create GitHub App for <your-user-or-org>**.
4. **Automatic Configuration**:
   - GitHub redirects back to `/github/manifest/callback`.
   - The App ID, private key PEM (`.agentblackbox/github_app.pem`), and webhook secret are automatically saved to your `.env`.
5. **Install on Repositories**:
   Click **Install App** and select the repositories you want AgentBlackBox to guard.

---

## 🛠️ Method 2: Manual GitHub App Setup

If you prefer creating the GitHub App manually via the GitHub web UI:

1. Go to **GitHub Settings** &rarr; **Developer Settings** &rarr; **GitHub Apps** &rarr; **New GitHub App**.
2. **General**:
   - **GitHub App name**: `AgentBlackBox-Bot` (or unique name).
   - **Homepage URL**: `https://github.com/ATP0925/AgentBlackBox`
3. **Webhook**:
   - **Webhook URL**: `https://<your-domain>/github/webhook` (for local testing, use [smee.io](https://smee.io) or ngrok).
   - **Webhook secret**: Generate a secure 32-byte secret (e.g. `openssl rand -hex 20`).
4. **Repository Permissions**:
   - **Contents**: `Read-only` (to inspect file contents and `.agentblackbox.yaml`).
   - **Pull requests**: `Read and write` (to post inline review comments).
   - **Issues**: `Read and write` (to post and update Walkthrough comments).
   - **Checks**: `Read and write` (to publish Check Runs and annotations).
   - **Metadata**: `Read-only`.
5. **Subscribe to Events**:
   - Check `Pull request`
   - Check `Issue comment`
   - Check `Installation`
   - Check `Installation repositories`
6. **Generate Private Key**:
   - Click **Generate a private key** and download the `.pem` file to `.agentblackbox/github_app.pem`.
7. **Configure `.env`**:
   ```env
   GITHUB_APP_ID=123456
   GITHUB_PRIVATE_KEY_PATH=.agentblackbox/github_app.pem
   GITHUB_WEBHOOK_SECRET=your-webhook-secret
   GEMINI_API_KEY=your-gemini-key
   ```

---

## 🌐 Local Development with Smee.io

When testing locally without a public IP:
1. Go to [smee.io](https://smee.io) and click **Start a new channel**. Copy the URL.
2. In your GitHub App settings, set the Webhook URL to your Smee channel URL.
3. Run the Smee client in a terminal:
   ```bash
   npx smee-client -u https://smee.io/<channel> --target http://localhost:8000/github/webhook
   ```
4. Test by opening or updating a PR on any repository where the app is installed!
