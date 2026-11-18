$ErrorActionPreference = "Stop"

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectDir

$MainPy = Join-Path $ProjectDir "main.py"
$ReqFile = Join-Path $ProjectDir "requirements.txt"

if (-not (Test-Path -LiteralPath $MainPy)) {
    Write-Host "==================================================================" -ForegroundColor Red
    Write-Host "[ERROR] main.py was not found in: $ProjectDir" -ForegroundColor Red
    Write-Host "Please extract (unzip) the entire ZIP archive to a folder first," -ForegroundColor Yellow
    Write-Host "then double-click run_windows.bat inside the extracted folder." -ForegroundColor Yellow
    Write-Host "==================================================================" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$PortableDir = Join-Path $ProjectDir ".python"
$PortablePy  = Join-Path $PortableDir "python\python.exe"
$PortablePyw = Join-Path $PortableDir "python\pythonw.exe"
$VenvDir     = Join-Path $ProjectDir ".venv"
$VenvPy      = Join-Path $VenvDir "Scripts\python.exe"
$VenvPyw     = Join-Path $VenvDir "Scripts\pythonw.exe"

function Set-TclTkEnv([string]$PyExe) {
    $pyRoot = Split-Path -Parent $PyExe
    $tclDir = Join-Path $pyRoot "tcl\tcl8.6"
    $tkDir  = Join-Path $pyRoot "tcl\tk8.6"
    if (Test-Path -LiteralPath $tclDir) { $env:TCL_LIBRARY = $tclDir }
    if (Test-Path -LiteralPath $tkDir)  { $env:TK_LIBRARY  = $tkDir }
}

function Test-PythonTk([string]$PyExe) {
    if (-not $PyExe -or -not (Test-Path -LiteralPath $PyExe)) { return $false }
    if ($PyExe -match "WindowsApps") { return $false }
    try {
        Set-TclTkEnv $PyExe
        $proc = Start-Process -FilePath $PyExe -ArgumentList '-c "import sys, tkinter; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"' -NoNewWindow -Wait -PassThru -ErrorAction Stop
        return ($proc.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Test-PythonReady([string]$PyExe) {
    if (-not (Test-PythonTk $PyExe)) { return $false }
    try {
        $proc = Start-Process -FilePath $PyExe -ArgumentList '-c "import tkinter, customtkinter"' -NoNewWindow -Wait -PassThru -ErrorAction Stop
        return ($proc.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Find-SystemPython {
    if (Test-PythonTk $PortablePy) { return $PortablePy }
    if (Test-PythonTk $VenvPy)     { return $VenvPy }

    $searchRoots = @(
        "$env:LOCALAPPDATA\Programs\Python\Python3*",
        "$env:ProgramFiles\Python3*",
        "${env:ProgramFiles(x86)}\Python3*",
        "C:\Python3*"
    )
    foreach ($pattern in $searchRoots) {
        $dirs = Get-Item -Path $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
        foreach ($d in $dirs) {
            $candidate = Join-Path $d.FullName "python.exe"
            if (Test-PythonTk $candidate) {
                return $candidate
            }
        }
    }

    $cmdPy = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmdPy -and (Test-PythonTk $cmdPy.Source)) {
        return $cmdPy.Source
    }
    return $null
}

function Install-PortablePython {
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "[INFO] Setting up standalone Python 3.12 (with Tkinter GUI)..." -ForegroundColor Cyan
    Write-Host "       No system-wide installation required." -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan

    $url = "https://github.com/astral-sh/python-build-standalone/releases/download/20241219/cpython-3.12.8%2B20241219-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
    if (Test-Path -LiteralPath $PortableDir) {
        Remove-Item -LiteralPath $PortableDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $PortableDir -Force | Out-Null
    $archive = Join-Path $PortableDir "python-win.tar.gz"

    Write-Host "1/2. Downloading portable Python 3.12 (~19MB)..." -ForegroundColor Yellow
    $curlCmd = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlCmd) {
        & $curlCmd.Source -fL --retry 2 "$url" -o "$archive"
    }
    if (-not (Test-Path -LiteralPath $archive)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
    }

    if (-not (Test-Path -LiteralPath $archive)) {
        return $false
    }

    Write-Host "2/2. Extracting portable Python 3.12..." -ForegroundColor Yellow
    $tarCmd = Get-Command tar.exe -ErrorAction SilentlyContinue
    if ($tarCmd) {
        & $tarCmd.Source -xzf "$archive" -C "$PortableDir"
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        return (Test-PythonTk $PortablePy)
    }

    Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    return $false
}

function Install-OfficialPython {
    Write-Host "[INFO] Downloading official Python 3.12 installer from python.org..." -ForegroundColor Yellow
    $installer = Join-Path $env:TEMP "python-3.12.8-amd64.exe"
    $url = "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    if (Test-Path -LiteralPath $installer) {
        Write-Host "[INFO] Installing Python 3.12 silently (please wait 30-60s)..." -ForegroundColor Yellow
        $proc = Start-Process -FilePath $installer -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1 Include_pip=1 Include_test=0" -Wait -PassThru
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
    }
}

try {
    # 1. Fast path if portable Python or .venv is already ready
    $RunPy = $null
    if (Test-PythonReady $PortablePy) {
        $RunPy = $PortablePy
    } elseif (Test-PythonReady $VenvPy) {
        $RunPy = $VenvPy
    }

    if (-not $RunPy) {
        $BasePy = Find-SystemPython
        if (-not $BasePy) {
            $ok = Install-PortablePython
            if ($ok) {
                $BasePy = $PortablePy
            } else {
                Install-OfficialPython
                $BasePy = Find-SystemPython
            }
        }

        if (-not $BasePy) {
            throw "Could not find or install Python 3.9+ with Tkinter. Please check your internet connection."
        }

        Write-Host "[OK] Using Python: $BasePy" -ForegroundColor Green
        Set-TclTkEnv $BasePy

        # If using Portable Python, install directly into Portable Python to avoid venv Tcl/Tk path issues on Windows
        if ($BasePy -eq $PortablePy) {
            $RunPy = $PortablePy
        } else {
            if (-not (Test-PythonTk $VenvPy)) {
                Write-Host "[INFO] Creating local virtual environment (.venv)..." -ForegroundColor Cyan
                & $BasePy -m venv "$VenvDir"
            }
            if (Test-PythonTk $VenvPy) {
                $RunPy = $VenvPy
            } else {
                $RunPy = $BasePy
            }
        }

        # Ensure pip is available
        & $RunPy -m pip --version >$null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[INFO] Enabling pip (ensurepip)..." -ForegroundColor Cyan
            & $RunPy -m ensurepip --upgrade
        }
        & $RunPy -m pip --version >$null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[INFO] Bootstrapping pip via get-pip.py..." -ForegroundColor Cyan
            $getPip = Join-Path $env:TEMP "get-pip.py"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getPip -UseBasicParsing
            & $RunPy $getPip
        }

        # Install requirements (customtkinter)
        if (-not (Test-PythonReady $RunPy)) {
            Write-Host "[INFO] Installing required UI packages (customtkinter)..." -ForegroundColor Cyan
            & $RunPy -m pip install --disable-pip-version-check -r "$ReqFile"
            if ($LASTEXITCODE -ne 0) {
                & $RunPy -m pip install --disable-pip-version-check --user --break-system-packages -r "$ReqFile"
            }
        }
    }

    Set-TclTkEnv $RunPy
    Write-Host "[OK] Launching D410/D420 Connect Installer GUI..." -ForegroundColor Green
    & $RunPy "$MainPy"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Application exited with code $LASTEXITCODE" -ForegroundColor Red
        Read-Host "Press Enter to close"
        exit $LASTEXITCODE
    }
} catch {
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Red
    Write-Host "[ERROR] Failed to launch installer:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host "==================================================================" -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}
