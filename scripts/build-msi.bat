@echo off
rem Runs Build-Msi.ps1 next to this file: clean Release build (via
rem Build-Dist.ps1), optional Authenticode signing, then the machine-wide
rem MSI in dist\. Building does not need elevation; installing the MSI does.
rem Arguments are forwarded, e.g.:
rem   build-msi.bat -Arch x64 -Version 1.0.0 -SignCertThumbprint <thumbprint>

setlocal
set "SCRIPT_DIR=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Build-Msi.ps1" %*
set "EXITCODE=%errorlevel%"

echo.
pause
exit /b %EXITCODE%
