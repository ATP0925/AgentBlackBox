$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   AgentBlackBox - Autonomous AI Flight Recorder & Review  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Detect Python command
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

# 2. Acquire or update repository files
$hasGit = [bool](Get-Command git -ErrorAction SilentlyContinue)

if (Test-Path "pyproject.toml") {
    # Already inside an AgentBlackBox repository
    if ($hasGit -and (Test-Path ".git")) {
        Write-Host "Updating local repository via git pull..." -ForegroundColor Cyan
        git pull --quiet
    }
} else {
    # We are outside the repository (e.g. C:\Users\<Username>)
    if ($hasGit) {
        if (Test-Path "AgentBlackBox\.git") {
            Set-Location "AgentBlackBox"
            Write-Host "Updating existing AgentBlackBox via git pull..." -ForegroundColor Cyan
            git pull --quiet
        } else {
            Write-Host "Cloning AgentBlackBox repository via Git..." -ForegroundColor Cyan
            git clone https://github.com/ATP0925/AgentBlackBox.git
            if (Test-Path "AgentBlackBox") { Set-Location "AgentBlackBox" }
        }
    } else {
        # Git is not installed: download repository ZIP archive
        Write-Host "Downloading latest AgentBlackBox repository archive..." -ForegroundColor Yellow
        $zipFile = Join-Path $env:TEMP "AgentBlackBox-latest.zip"
        $tempExtract = Join-Path $env:TEMP "AgentBlackBox-extract"

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri "https://github.com/ATP0925/AgentBlackBox/archive/refs/heads/main.zip" -OutFile $zipFile
            if (Test-Path $tempExtract) { Remove-Item -Recurse -Force $tempExtract -ErrorAction SilentlyContinue }
            Expand-Archive -Path $zipFile -DestinationPath $tempExtract -Force

            # If user already has AgentBlackBox-main or AgentBlackBox, update it
            $destDir = "AgentBlackBox"
            if (Test-Path "AgentBlackBox-main") {
                $destDir = "AgentBlackBox-main"
            }
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir | Out-Null
            }
            Copy-Item -Path "$tempExtract\AgentBlackBox-main\*" -Destination $destDir -Recurse -Force
            Set-Location $destDir

            Remove-Item -Recurse -Force $tempExtract -ErrorAction SilentlyContinue
            Remove-Item -Force $zipFile -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Archive extraction error: $_" -ForegroundColor Red
            if (Test-Path "AgentBlackBox-main\pyproject.toml") {
                Set-Location "AgentBlackBox-main"
            } elseif (Test-Path "AgentBlackBox\pyproject.toml") {
                Set-Location "AgentBlackBox"
            }
        }
    }
}

Write-Host "Active project folder: $(Get-Location)" -ForegroundColor Green

# 3. Install Package and Dependencies
Write-Host "⚡ Installing AgentBlackBox in editable mode..." -ForegroundColor Cyan
& $pythonCmd -m pip install --no-warn-script-location -e ".[dev]"

# 4. Configure PATH and define PowerShell function
try {
    $pyScripts = (& $pythonCmd -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null).Trim()
    $userScripts = (& $pythonCmd -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))" 2>$null).Trim()

    foreach ($sDir in @($pyScripts, $userScripts)) {
        if ($sDir -and (Test-Path $sDir)) {
            if ($env:PATH -notlike "*$sDir*") {
                $env:PATH = "$sDir;$env:PATH"
            }
            try {
                $userEnvPath = [Environment]::GetEnvironmentVariable("Path", "User")
                if ($userEnvPath -notlike "*$sDir*") {
                    [Environment]::SetEnvironmentVariable("Path", "$sDir;$userEnvPath", "User")
                }
            } catch {}
        }
    }
} catch {}

# Create abb function in current session so it works immediately even if Application Control blocks abb.exe
function global:abb { & $pythonCmd -m agentblackbox @args }

# Also create abb.cmd in current directory as fallback for CMD and scripts
try {
    $cmdWrapper = "@echo off`r`n`"$pythonCmd`" -m agentblackbox %*`r`n"
    Set-Content -Path "abb.cmd" -Value $cmdWrapper -Encoding ASCII -Force
} catch {}

# 5. Run Verification Review
Write-Host "`n✅ AgentBlackBox installed successfully!" -ForegroundColor Green
Write-Host "Running initial code review..." -ForegroundColor Cyan
& $pythonCmd -m agentblackbox review --exit-zero

Write-Host "`n🎉 Setup complete! You can now run:" -ForegroundColor Green
Write-Host "   abb review" -ForegroundColor Yellow
Write-Host "   abb analyze . --min-severity medium" -ForegroundColor Yellow
Write-Host "   abb hook-install --agent all`n" -ForegroundColor Yellow
