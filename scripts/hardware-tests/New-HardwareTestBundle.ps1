<#
.SYNOPSIS
    Copies the built HkdfGuard binaries, test suites and provider probe into
    one self-contained folder, to run on a machine being qualified - a laptop
    with a different TPM, a Hyper-V guest with a virtual TPM.

.DESCRIPTION
    The binaries link the C/C++ runtime statically, so the target needs
    nothing installed. Copy the folder to the target and run
    Run-HardwareTests.ps1 from it, elevated, at the target's own console
    (README.md in this folder says why, and what counts as a pass).

    Each run overwrites the files it stages and leaves everything else in
    the folder - the logs earlier runs brought back - alone.

.PARAMETER BuildDir
    The CMake build tree to take the binaries from, relative to the repository
    root or absolute. Build it first, in Release (cmake --build <dir>).
    Default: build-ninja.

.PARAMETER OutDir
    Where to create the bundle. Default: build-hardware-tests\bundle under the
    repository root.
#>
param(
    [string]$BuildDir = "build-ninja",
    [string]$OutDir
)
$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$build = if ([IO.Path]::IsPathRooted($BuildDir)) { $BuildDir } else { Join-Path $repo $BuildDir }
if (-not $OutDir) { $OutDir = Join-Path $repo "build-hardware-tests\bundle" }

$cache = Join-Path $build "CMakeCache.txt"
if (Test-Path -LiteralPath $cache) {
    $type = (Select-String -LiteralPath $cache -Pattern '^CMAKE_BUILD_TYPE:STRING=(.*)$').Matches.Groups[1].Value
    if ($type -ne "Release") { Write-Warning "$build is a '$type' build; the documented results are from Release builds." }
}

$files = @(
    "$build\HkdfGuard.dll",
    "$build\tools\hkdfguard.exe",
    "$build\tests\v2_provider_probe.exe",
    "$build\tests\test_v2_kek.exe",
    "$build\tests\test_roundtrip.exe",
    "$build\tests\test_harden_process.exe",
    "$build\tests\role_probe.exe",
    "$repo\tests\test_cli.ps1",
    "$repo\tests\test_cli_v2.ps1",
    "$repo\tests\test_roles.ps1",
    "$PSScriptRoot\Run-HardwareTests.ps1",
    "$PSScriptRoot\README.md"
)
foreach ($f in $files) {
    if (-not (Test-Path -LiteralPath $f)) { throw "missing $f - build $build first" }
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
foreach ($f in $files) { Copy-Item -LiteralPath $f -Destination $OutDir -Force }
Write-Host "Staged $($files.Count) files in $OutDir"
