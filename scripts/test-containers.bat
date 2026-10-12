@echo off
rem Runs Test-Containers.ps1 next to this file: builds x64 Release and an
rem unsigned MSI, then installs and tests them in clean Windows Server 2022
rem and 2025 containers (Hyper-V isolation). Needs Docker switched to Windows
rem containers. Arguments are forwarded, e.g.:
rem   test-containers.bat -Image ltsc2025 -SkipBuild

setlocal
set "SCRIPT_DIR=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Test-Containers.ps1" %*
set "EXITCODE=%errorlevel%"

echo.
pause
exit /b %EXITCODE%
