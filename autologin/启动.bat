@echo off
setlocal
title Captive Auto Login
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0CaptiveAutoLogin.ps1"

if errorlevel 1 (
    echo.
    echo Something went wrong. Press any key to close.
    pause >nul
)

endlocal
