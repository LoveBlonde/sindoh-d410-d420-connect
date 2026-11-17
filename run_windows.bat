@echo off
chcp 65001 >nul
title D410/D420 Connect Installer

:: Request Administrator privileges for PnPUtil / Add-PrinterPort / SMB Share setup
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 관리자 권한으로 실행 중...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

python -c "import customtkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo 필요한 UI 패키지(customtkinter)를 설치하고 있습니다...
    python -m pip install -r requirements.txt
)

start "" pythonw main.py
if %errorlevel% neq 0 (
    python main.py
)
