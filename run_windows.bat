@echo off
title D410/D420 Connect Installer
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

if not exist "%~dp0core\windows_launcher.ps1" (
    echo [ERROR] core\windows_launcher.ps1 not found in: %~dp0
    echo Please extract the entire ZIP archive to a folder before running run_windows.bat.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\windows_launcher.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Launcher exited with error code %errorlevel%.
    pause
)
