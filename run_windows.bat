@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title D410/D420 Connect Installer

cd /d "%~dp0"
set "PROJECT_DIR=%~dp0"
set "PORTABLE_PY=%PROJECT_DIR%.python\python\python.exe"
set "PORTABLE_PYW=%PROJECT_DIR%.python\python\pythonw.exe"
set "VENV_DIR=%PROJECT_DIR%.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "VENV_PYW=%VENV_DIR%\Scripts\pythonw.exe"

:: 1. Request Administrator privileges for PnPUtil / Add-PrinterPort / Firewall setup
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [안내] 프린터 포트 및 드라이버 설치를 위해 관리자 권한을 요청합니다...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0.' -Verb RunAs"
    exit /b
)

:: 2. Fast Path: If .venv or .python already has working tkinter + customtkinter
if exist "%VENV_PY%" (
    "%VENV_PY%" -c "import tkinter, customtkinter" >nul 2>&1
    if !errorlevel! equ 0 (
        set "RUN_PY=%VENV_PY%"
        set "RUN_PYW=%VENV_PYW%"
        goto :LAUNCH_APP
    )
)
if exist "%PORTABLE_PY%" (
    "%PORTABLE_PY%" -c "import tkinter, customtkinter" >nul 2>&1
    if !errorlevel! equ 0 (
        set "RUN_PY=%PORTABLE_PY%"
        set "RUN_PYW=%PORTABLE_PYW%"
        goto :LAUNCH_APP
    )
)

:: 3. Locate usable Python 3.9+ with tkinter (ignores Microsoft Store WindowsApps stub)
set "PY_CMD="
call :FIND_PYTHON

if not defined PY_CMD (
    echo ==================================================================
    echo [안내] 이 PC에 Python 환경이 설치되어 있지 않습니다.
    echo        시스템에 영향을 주지 않는 무설치 독립형 Python 3.12 ^(Tkinter 포함^)를
    echo        폴더 내부^(.python^)에 자동으로 다운로드합니다...
    echo ==================================================================
    call :INSTALL_PORTABLE_PYTHON
    call :FIND_PYTHON
)

if not defined PY_CMD (
    echo [안내] 공식 Python 3.12 설치 프로그램으로 전환하여 자동 설치를 진행합니다...
    call :INSTALL_OFFICIAL_PYTHON
    call :FIND_PYTHON
)

if not defined PY_CMD (
    echo [오류] Python 환경을 준비하지 못했습니다. 인터넷 연결을 확인해 주세요.
    pause
    exit /b 1
)

echo 사용할 Python 환경: !PY_CMD!

:: 4. Create .venv (or use portable Python directly)
if not exist "%VENV_PY%" (
    echo 독립 실행용 가상환경^(.venv^)을 준비하고 있습니다...
    !PY_CMD! -m venv "%VENV_DIR%" >nul 2>&1
)

if exist "%VENV_PY%" (
    set "RUN_PY=%VENV_PY%"
    set "RUN_PYW=%VENV_PYW%"
) else (
    if exist "%PORTABLE_PY%" (
        set "RUN_PY=%PORTABLE_PY%"
        set "RUN_PYW=%PORTABLE_PYW%"
    ) else (
        set "RUN_PY=!PY_CMD!"
        set "RUN_PYW=!PY_CMD!"
    )
)

:: 5. Ensure pip exists
"!RUN_PY!" -m pip --version >nul 2>&1
if !errorlevel! neq 0 (
    echo pip 모듈을 활성화하고 있습니다...
    "!RUN_PY!" -m ensurepip --upgrade >nul 2>&1
)
"!RUN_PY!" -m pip --version >nul 2>&1
if !errorlevel! neq 0 (
    echo get-pip.py를 통해 pip를 설치하고 있습니다...
    curl.exe -fsSL "https://bootstrap.pypa.io/get-pip.py" -o "%TEMP%\get-pip.py" 2>nul
    if not exist "%TEMP%\get-pip.py" (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '$env:TEMP\get-pip.py'"
    )
    "!RUN_PY!" "%TEMP%\get-pip.py"
)

:: 6. Install UI Requirements (customtkinter)
"!RUN_PY!" -c "import customtkinter" >nul 2>&1
if !errorlevel! neq 0 (
    echo 필요한 UI 패키지^(customtkinter^)를 설치하고 있습니다...
    "!RUN_PY!" -m pip install --disable-pip-version-check -r "%PROJECT_DIR%requirements.txt"
    if !errorlevel! neq 0 (
        "!RUN_PY!" -m pip install --disable-pip-version-check --user --break-system-packages -r "%PROJECT_DIR%requirements.txt" 2>nul || "!RUN_PY!" -m pip install --disable-pip-version-check --user -r "%PROJECT_DIR%requirements.txt"
    )
)

:LAUNCH_APP
if exist "!RUN_PYW!" (
    start "" "!RUN_PYW!" "%PROJECT_DIR%main.py"
    if !errorlevel! equ 0 exit /b 0
)
"!RUN_PY!" "%PROJECT_DIR%main.py"
exit /b !errorlevel!

:: ─────────────────────────────────────────────────────────────────────────────
:: Subroutines
:: ─────────────────────────────────────────────────────────────────────────────
:FIND_PYTHON
if exist "%PORTABLE_PY%" (
    "%PORTABLE_PY%" -c "import sys, tkinter; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY_CMD=\"%PORTABLE_PY%\""
        exit /b 0
    )
)
for %%C in ("python" "py -3") do (
    %%~C -c "import sys, tkinter; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY_CMD=%%~C"
        exit /b 0
    )
)
for /d %%D in ("%LocalAppData%\Programs\Python\Python3*" "%ProgramFiles%\Python3*") do (
    if exist "%%~fD\python.exe" (
        "%%~fD\python.exe" -c "import sys, tkinter; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
        if !errorlevel! equ 0 (
            set "PY_CMD=\"%%~fD\python.exe\""
            exit /b 0
        )
    )
)
exit /b 1

:INSTALL_PORTABLE_PYTHON
set "PY_URL=https://github.com/astral-sh/python-build-standalone/releases/download/20241219/cpython-3.12.8%%2B20241219-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
set "PORTABLE_DIR=%PROJECT_DIR%.python"
set "ARCHIVE=%PORTABLE_DIR%\python-win.tar.gz"

if exist "%PORTABLE_DIR%" rmdir /s /q "%PORTABLE_DIR%" >nul 2>&1
mkdir "%PORTABLE_DIR%" >nul 2>&1

echo 1/2. 독립형 Python 3.12 패키지 다운로드 중...
where curl.exe >nul 2>&1
if !errorlevel! equ 0 (
    curl.exe -fL --progress-bar "%PY_URL%" -o "%ARCHIVE%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%ARCHIVE%'"
)

if not exist "%ARCHIVE%" exit /b 1

echo 2/2. 압축 해제 중...
where tar.exe >nul 2>&1
if !errorlevel! equ 0 (
    tar.exe -xzf "%ARCHIVE%" -C "%PORTABLE_DIR%"
    del /q "%ARCHIVE%" >nul 2>&1
    exit /b 0
)
del /q "%ARCHIVE%" >nul 2>&1
exit /b 1

:INSTALL_OFFICIAL_PYTHON
set "PY_INSTALLER=%TEMP%\python-3.12.8-amd64.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe' -OutFile '%PY_INSTALLER%'"
if exist "%PY_INSTALLER%" (
    "%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1 Include_pip=1 Include_test=0
    del /q "%PY_INSTALLER%" >nul 2>&1
)
exit /b 0
