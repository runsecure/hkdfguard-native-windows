@echo off
rem Runs Build-Dist.ps1 next to this file: clean-builds Release and stages
rem HkdfGuard.dll and hkdfguard.exe into dist\win-x64. Needs no elevation:
rem building doesn't touch the machine-wide KEK. Pass -Sign to
rem Authenticode-sign the staged binaries through Azure Artifact Signing;
rem build-dist-signed.bat builds both architectures, signed.

setlocal
set "SCRIPT_DIR=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Build-Dist.ps1" %*
set "EXITCODE=%errorlevel%"

echo.
pause
exit /b %EXITCODE%
