$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   AgentBlackBox - Autonomous AI Flight Recorder & Review  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Determine Python command
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

# 2. Check if already inside an AgentBlackBox repository
if (-not (Test-Path "pyproject.toml")) {
    if (Test-Path "AgentBlackBox\pyproject.toml") {
        Set-Location "AgentBlackBox"
    } elseif (Test-Path "AgentBlackBox-main\pyproject.toml") {
        Set-Location "AgentBlackBox-main"
    } else {
        # Check if Git is available
        if (Get-Command git -ErrorAction SilentlyContinue) {
            Write-Host "Cloning AgentBlackBox repository with Git..." -ForegroundColor Cyan
            git clone https://github.com/ATP0925/AgentBlackBox.git
            if (Test-Path "AgentBlackBox") { Set-Location "AgentBlackBox" }
        } else {
            Write-Host "⚠️ Git is not installed on this PC. Downloading repository ZIP directly..." -ForegroundColor Yellow
            $zipFile = "$env:TEMP\AgentBlackBox.zip"
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri "https://github.com/ATP0925/AgentBlackBox/archive/refs/heads/main.zip" -OutFile $zipFile
                Expand-Archive -Path $zipFile -DestinationPath "." -Force
                Remove-Item -Force $zipFile -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Download error: $_" -ForegroundColor Red
            }
            if (Test-Path "AgentBlackBox-main") {
                Set-Location "AgentBlackBox-main"
            } elseif (Test-Path "AgentBlackBox") {
                Set-Location "AgentBlackBox"
            }
        }
    }
}

Write-Host "Active project folder: $(Get-Location)" -ForegroundColor Green

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
    $userScripts = "$env:APPDATA\Python\Python311\Scripts"
    if (Test-Path $userScripts) {
        if ($env:PATH -notlike "*$userScripts*") {
            $env:PATH = "$userScripts;$env:PATH"
        }
    }
} catch {}

# 5. Run Verification Review
Write-Host "`n✅ AgentBlackBox installed successfully!" -ForegroundColor Green
Write-Host "Running initial code review..." -ForegroundColor Cyan
& $pythonCmd -m agentblackbox.cli.main review --exit-zero

Write-Host "`n🎉 Setup complete! You can now run:" -ForegroundColor Green
Write-Host "   abb review" -ForegroundColor Yellow
Write-Host "   abb analyze . --min-severity medium" -ForegroundColor Yellow
Write-Host "   abb hook-install --agent all`n" -ForegroundColor Yellow
