# AgentBlackBox One-Click Setup Script for Windows
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   AgentBlackBox - Autonomous AI Flight Recorder & Review  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    Write-Host "`n❌ Error: Python is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://python.org or the Microsoft Store." -ForegroundColor Yellow
    exit 1
}

# 2. Check if we are already inside an AgentBlackBox repository
$repoDir = "AgentBlackBox"
if (Test-Path "pyproject.toml") {
    Write-Host "Detected AgentBlackBox project directory." -ForegroundColor Cyan
} else {
    # Check if Git is available
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Host "Cloning AgentBlackBox repository with Git..." -ForegroundColor Cyan
        git clone https://github.com/ATP0925/AgentBlackBox.git
        Set-Location $repoDir
    } else {
        Write-Host "⚠️ Git is not installed on this PC. Downloading repository ZIP directly..." -ForegroundColor Yellow
        $zipFile = "$env:TEMP\AgentBlackBox.zip"
        Invoke-WebRequest -Uri "https://github.com/ATP0925/AgentBlackBox/archive/refs/heads/main.zip" -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath "." -Force
        Remove-Item -Force $zipFile -ErrorAction SilentlyContinue
        if (Test-Path "AgentBlackBox-main") {
            if (Test-Path $repoDir) { Remove-Item -Recurse -Force $repoDir }
            Rename-Item -Path "AgentBlackBox-main" -NewName $repoDir
            Set-Location $repoDir
        }
    }
}

# 3. Install Package and Dependencies
Write-Host "⚡ Installing AgentBlackBox in editable mode via $pythonCmd -m pip..." -ForegroundColor Cyan
& $pythonCmd -m pip install -e ".[dev]"

# 4. Add Scripts directory to session PATH
try {
    $pyPath = (Get-Command $pythonCmd).Source
    $scriptsDir = Join-Path (Split-Path $pyPath) "Scripts"
    if (Test-Path $scriptsDir) {
        if ($env:PATH -notlike "*$scriptsDir*") {
            $env:PATH = "$scriptsDir;$env:PATH"
        }
    }
} catch {
    # Non-critical if PATH update fails
}

# 5. Run Verification Review
Write-Host "`n✅ AgentBlackBox installed successfully!" -ForegroundColor Green
Write-Host "Running initial code review..." -ForegroundColor Cyan
& $pythonCmd -m agentblackbox.cli.main review --exit-zero

Write-Host "`n🎉 Setup complete! You can now run:" -ForegroundColor Green
Write-Host "   abb review" -ForegroundColor Yellow
Write-Host "   abb analyze . --min-severity medium" -ForegroundColor Yellow
Write-Host "   abb hook-install --agent all`n" -ForegroundColor Yellow
