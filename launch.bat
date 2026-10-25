@echo off
:: HydraX — Production Launch Script (Windows)
:: Authorized security testing only.

title HydraX — Threat Intelligence Platform

:: Change to the script's own directory so relative paths work regardless
:: of where the user double-clicks the file from.
cd /d "%~dp0"

:: Prefer a local .venv if present
if exist ".venv\Scripts\python.exe" (
    set PYTHON=".venv\Scripts\python.exe"
) else (
    set PYTHON=python
)

:: Redirect stderr to a log file; keep stdout visible in the console
if not exist "runtime" mkdir runtime

%PYTHON% main.py 2>>"runtime\hydrax.log"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] HydraX exited with code %ERRORLEVEL%.
    echo Check runtime\hydrax.log for details.
    pause
)
