@echo off
rem Runs Build-Dist-Signed.ps1 next to this file: the complete signed
rem distribution build - clean Release builds for x64 and ARM64, staged into
rem dist\win-<arch> and Authenticode-signed through Azure Artifact Signing.
rem Needs no elevation, but does need an Azure sign-in (az login) for an
rem account with the Artifact Signing Certificate Profile Signer role.
rem Arguments are forwarded, e.g.:
rem   build-dist-signed.bat
rem   build-dist-signed.bat -Msi -Version 1.0.0
rem   build-dist-signed.bat -Arch x64

setlocal
set "SCRIPT_DIR=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Build-Dist-Signed.ps1" %*
set "EXITCODE=%errorlevel%"

echo.
pause
exit /b %EXITCODE%
