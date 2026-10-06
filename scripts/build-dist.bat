@echo off
rem Runs Build-Dist.ps1 next to this file: clean-builds the Release
rem configuration and stages HkdfGuard.Kms.Windows.v1.dll and
rem hkdfguard-v1-initialize.exe into dist\win-x64. Unlike
rem run-build-test-verify.bat, this does not need to run elevated - building
rem Release doesn't touch the machine-wide KEK, only actually wrapping a DEK
rem does.

setlocal
set "SCRIPT_DIR=%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Build-Dist.ps1" %*
set "EXITCODE=%errorlevel%"

echo.
pause
exit /b %EXITCODE%
