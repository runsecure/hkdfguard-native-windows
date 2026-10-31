<#
.SYNOPSIS
    Installs and tests hkdfguard-native-windows inside clean Windows Server
    2022 and 2025 containers, from a Windows 10/11 or Windows Server host.

.DESCRIPTION
    1. Builds the x64 Release binaries (Build-Dist.ps1) and an unsigned MSI
       (Build-Msi.ps1 -SkipBuild) on this host, unless -SkipBuild is given.
       The binaries link the C/C++ runtime statically, so nothing else has to
       be installed in the container.
    2. Stages the MSI, test_roundtrip.exe, tests\test_cli.ps1 and
       tests\container\Test-InContainer.ps1 into build-containers\payload.
    3. For each -Image, starts a fresh mcr.microsoft.com/windows/servercore
       container with Hyper-V isolation and runs Test-InContainer.ps1 in it:
       install the MSI, run both test suites against the installed binaries,
       uninstall. The container is removed afterwards (--rm), so every run
       starts from a clean OS.

    Hyper-V isolation is used because process isolation needs the container
    image's Windows build to match the host's, which a Windows 11 host never
    does for Server images. It needs the Hyper-V and Containers Windows
    features. Containers have no TPM, so this covers the Software Key Storage
    Provider path (as on a server or VM without a vTPM) - not the TPM path.

    Requirements: Docker Desktop switched to Windows containers (or the
    Docker engine on Windows Server), and on first use about 3 GB of image
    download per server version. Does not need elevation itself.

.PARAMETER Image
    Server Core tags to test: ltsc2022, ltsc2025, or both (default).

.PARAMETER Version
    MSI version to build and install. Default: 0.9.1.

.PARAMETER SkipBuild
    Reuse build-release-x64\ and the MSI already in dist\ instead of
    rebuilding them.

.PARAMETER MemoryGB
    Memory for each Hyper-V isolated container. Default: 2.
#>
param(
    [ValidateSet("ltsc2022", "ltsc2025")]
    [string[]]$Image = @("ltsc2022", "ltsc2025"),
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,5}$')]
    [string]$Version = "0.9.1",
    [switch]$SkipBuild,
    [int]$MemoryGB = 2
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Write-Section($title) {
    Write-Host ""
    Write-Host "==== $title ====" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }

# ---- Docker preflight ---------------------------------------------------------
# Native stderr under ErrorActionPreference=Stop throws in Windows PowerShell
# 5.1, so docker's own error text is read with Continue.
Write-Section "Checking Docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker is not on PATH. Install Docker Desktop (or the Docker engine on Windows Server)."
}
$ErrorActionPreference = "Continue"
$serverOs = & docker version --format "{{.Server.Os}}" 2>&1
$dockerExit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($dockerExit -ne 0) {
    throw "The Docker engine is not reachable: $serverOs"
}
if ("$serverOs".Trim() -ne "windows") {
    throw "Docker is running $serverOs containers. Switch Docker Desktop to Windows containers (tray icon > 'Switch to Windows containers...', or `"$env:ProgramFiles\Docker\Docker\DockerCli.exe`" -SwitchWindowsEngine) and retry."
}
Write-Ok "Docker engine is running Windows containers"

# ---- 1. Build ------------------------------------------------------------------
$msiPath = Join-Path $RepoRoot "dist\hkdfguard-native-windows-$Version-win-x64.msi"
$testExe = Join-Path $RepoRoot "build-release-x64\tests\test_roundtrip.exe"
if (-not $SkipBuild) {
    Write-Section "Building x64 Release and the MSI (unsigned)"
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Build-Dist.ps1") -Arch x64
    if ($LASTEXITCODE -ne 0) { throw "Build-Dist.ps1 failed (exit $LASTEXITCODE)" }
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Build-Msi.ps1") -Arch x64 -Version $Version -SkipBuild
    if ($LASTEXITCODE -ne 0) { throw "Build-Msi.ps1 failed (exit $LASTEXITCODE)" }
}
foreach ($p in $msiPath, $testExe) {
    if (-not (Test-Path $p)) { throw "missing $p (run without -SkipBuild)" }
}

# ---- 2. Stage ------------------------------------------------------------------
Write-Section "Staging the test payload"
$workRoot = Join-Path $RepoRoot "build-containers"
$payload = Join-Path $workRoot "payload"
if (Test-Path $payload) { Remove-Item -Recurse -Force $payload }
New-Item -ItemType Directory -Force -Path $payload | Out-Null
Copy-Item $msiPath, $testExe, (Join-Path $RepoRoot "tests\test_cli.ps1"), (Join-Path $RepoRoot "tests\container\Test-InContainer.ps1") $payload
Get-ChildItem $payload | ForEach-Object { Write-Host "  $($_.Name)" }

# ---- 3. Run each server version ----------------------------------------------------
$results = [ordered]@{}
foreach ($tag in $Image) {
    $ref = "mcr.microsoft.com/windows/servercore:$tag"
    $out = Join-Path $workRoot "out-$tag"
    if (Test-Path $out) { Remove-Item -Recurse -Force $out }
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    Write-Section "Pulling $ref"
    & docker pull $ref
    if ($LASTEXITCODE -ne 0) { throw "docker pull $ref failed (exit $LASTEXITCODE)" }

    Write-Section "Testing on $ref (Hyper-V isolation)"
    & docker run --rm --isolation=hyperv --memory "$($MemoryGB)g" `
        -v "${payload}:C:\payload:ro" -v "${out}:C:\out" `
        $ref powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\payload\Test-InContainer.ps1
    $results[$tag] = $LASTEXITCODE
    Write-Host "logs: $out"
}

Write-Section "Summary"
$failed = 0
foreach ($tag in $results.Keys) {
    if ($results[$tag] -eq 0) {
        Write-Ok "servercore:$tag passed"
    } else {
        Write-Host "[FAIL] servercore:$tag failed (exit $($results[$tag])) - logs in build-containers\out-$tag" -ForegroundColor Red
        $failed++
    }
}
if ($failed -gt 0) { exit 1 }
