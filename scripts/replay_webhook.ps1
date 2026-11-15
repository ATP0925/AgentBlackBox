<#
.SYNOPSIS
Replay a GitHub webhook payload with a valid HMAC-SHA256 signature against local AgentBlackBox server.

.EXAMPLE
.\scripts\replay_webhook.ps1 -PayloadFile tests\fixtures\pr_opened.json -Event pull_request
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadFile,

    [string]$Url = "http://localhost:8000/github/webhook",
    [string]$Secret = $env:GITHUB_WEBHOOK_SECRET,
    [string]$Event = "pull_request"
)

if (-not (Test-Path $PayloadFile)) {
    Write-Error "Payload file not found: $PayloadFile"
    exit 1
}

if (-not $Secret) {
    $Secret = "dev-webhook-secret"
}

$payloadBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $PayloadFile))
$secretBytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)

$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $secretBytes
$hashBytes = $hmac.ComputeHash($payloadBytes)
$hashHex = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
$sigHeader = "sha256=$hashHex"
$deliveryId = [System.Guid]::NewGuid().ToString()

$headers = @{
    "Content-Type" = "application/json"
    "X-Hub-Signature-256" = $sigHeader
    "X-GitHub-Event" = $Event
    "X-GitHub-Delivery" = $deliveryId
    "User-Agent" = "GitHub-Hookshot/replay-powershell"
}

Write-Host "Sending $Event to $Url (delivery: $($deliveryId.Substring(0,8))...)..." -ForegroundColor Cyan

try {
    $response = Invoke-WebRequest -Uri $Url -Method Post -Headers $headers -Body $payloadBytes -TimeoutSec 10
    Write-Host "Status: $($response.StatusCode) $($response.StatusDescription)" -ForegroundColor Green
    Write-Host $response.Content
} catch {
    if ($_.Exception.Response) {
        Write-Host "Response: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    } else {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
