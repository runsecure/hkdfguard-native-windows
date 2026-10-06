@echo off
rem Elevates itself (UAC prompt) if not already running as Administrator,
rem then runs Build-Test-Verify.ps1 next to this file: configures + builds
rem HkdfGuardWin, runs its ctest suite, and does an end-to-end check that
rem wraps a random 32-byte DEK with the CLI and independently unwraps it via
rem hkdfguard.dll. Elevation is required because creating the machine-wide
rem KEK on first use needs Administrator rights - see README.md.

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
