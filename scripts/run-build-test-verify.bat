@echo off
rem Elevates itself (UAC prompt) if not already running as Administrator,
rem then runs Build-Test-Verify.ps1 next to this file: builds the project,
rem runs its ctest suite, and wraps a random 32-byte DEK with the CLI and
rem unwraps it through HkdfGuard.dll. Elevation is required because creating
rem the machine-wide KEK needs Administrator rights - see README.md.

setlocal
set "SCRIPT_DIR=%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Not running elevated - requesting Administrator rights...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Build-Test-Verify.ps1" %*
set "EXITCODE=%errorlevel%"

echo.
pause
exit /b %EXITCODE%
