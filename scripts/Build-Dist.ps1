<#
.SYNOPSIS
    Clean-builds the Release configuration for one target architecture and
    stages the two artifacts other tooling actually needs - the DLL and the
    CLI - into dist\win-<arch>.

.DESCRIPTION
    1. Locates the MSVC/CMake/Ninja toolchain from the Visual Studio Build
       Tools install and puts them on PATH for this process, targeting
       -Arch (x64 or ARM64) - cross-compiling if the host architecture
       differs from -Arch, native otherwise. Requires that VS install to
       have the matching C++ build tools component: VC.Tools.x86.x64 for
       x64, VC.Tools.ARM64 for ARM64 - these are separate, independently
       installed workload components.
    2. Deletes any existing build-release-<arch>\ and dist\win-<arch>\
       directories, then configures and builds Release from scratch
       (cmake -G Ninja -DCMAKE_BUILD_TYPE=Release) - "clean" specifically
       because a stale build directory left over from before a
       CMakeLists.txt change (e.g. the static-runtime-linking flag) can
       silently keep old settings baked into an incrementally-reused build
       directory. Each architecture gets its own build directory so
       building both doesn't clobber the other's cached CMake config.
    3. Copies HkdfGuard.Kms.Windows.v1.dll and hkdfguard-v1-initialize.exe
       (which needs that DLL sitting next to it - Windows won't find it
       across directories) into dist\win-<arch>\, ready to hand to a C#
       wrapper or copy to another machine.
    4. Reports each binary's DLL dependencies (dumpbin /dependents) as a
       sanity check that the static-runtime-linking CMakeLists.txt setting
       actually took effect - neither should depend on MSVCP140.dll/
       VCRUNTIME140*.dll/the api-ms-win-crt-*.dll forwarders, only core
       Windows system DLLs.

    Does not run the test suite (that needs an elevated shell - see
    run-build-test-verify.bat/Build-Test-Verify.ps1 for that) and does not
    itself require elevation: building Release doesn't touch the
    machine-wide KEK, only actually wrapping a DEK does. Note that when
    cross-compiling (-Arch differs from the host architecture), nothing
    this script produces has actually been *run* on that architecture -
    only compiled for it. Validate a cross-compiled ARM64 build by actually
    running scripts/Build-Test-Verify.ps1 on real (or emulated) ARM64
    Windows before trusting it in production.

.PARAMETER Arch
    Target architecture: x64 or ARM64. Default: x64.

.PARAMETER DistDir
    Where the two artifacts are staged, relative to the repo root.
    Default: dist\win-<arch lowercased>.
#>
param(
    [ValidateSet("x64", "ARM64")]
    [string]$Arch = "x64",
    [string]$DistDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$ArchLower = $Arch.ToLower()
if (-not $DistDir) { $DistDir = "dist\win-$ArchLower" }
$BuildDirName = "build-release-$ArchLower"

function Write-Section($title) {
    Write-Host ""
    Write-Host "==== $title ====" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }

# ---- Locate and enter the VS Build Tools developer environment --------
Write-Section "Locating MSVC / CMake / Ninja (target: $Arch)"
$installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$vswhere = Join-Path $installerDir "vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere - is Visual Studio / Build Tools installed?"
}
$env:PATH = "$env:PATH;$installerDir"

# The C++ build tools component is architecture-specific: VC.Tools.x86.x64
# and VC.Tools.ARM64 are separate, independently installed components, so
# requiring the wrong one here would let vswhere find a VS install that
# actually can't compile for -Arch at all, and fail later with a much less
# clear "cl.exe not found" error instead of this one.
$requiredComponent = if ($Arch -eq "ARM64") {
    "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
} else {
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
}
$vsInstallPath = & $vswhere -latest -products * -requires $requiredComponent -property installationPath
if (-not $vsInstallPath) {
    throw "No Visual Studio / Build Tools install with the C++ $Arch build tools component ($requiredComponent) was found."
}
Write-Host "Using VS install: $vsInstallPath"

$devShell = Join-Path $vsInstallPath "Common7\Tools\Launch-VsDevShell.ps1"
if (-not (Test-Path $devShell)) {
    throw "Launch-VsDevShell.ps1 not found under $vsInstallPath"
}

# Launch-VsDevShell.ps1's own -Arch/-HostArch naming (amd64/arm64/x86/arm)
# differs from this script's -Arch (x64/ARM64, matching common Windows
# architecture naming and the eventual win-x64/win-arm64 dist folder names).
$vsArchMap = @{ "x64" = "amd64"; "ARM64" = "arm64" }
$vsTargetArch = $vsArchMap[$Arch]

# Detects the *host's* architecture so a build run on an ARM64 machine
# targeting ARM64 (or an x64 machine targeting x64) correctly sets up a
# native toolchain rather than an unnecessary cross-compiler - and so
# targeting the other architecture correctly cross-compiles instead of
# silently trying to run a mismatched-architecture cl.exe.
$hostArchMap = @{ "AMD64" = "amd64"; "ARM64" = "arm64"; "x86" = "x86" }
$vsHostArch = $hostArchMap[$env:PROCESSOR_ARCHITECTURE]
if (-not $vsHostArch) { $vsHostArch = "amd64" } # unrecognized value - amd64 is by far the common case
if ($vsHostArch -ne $vsTargetArch) {
    Write-Host "Cross-compiling: host is $vsHostArch, target is $vsTargetArch"
}

& $devShell -Arch $vsTargetArch -HostArch $vsHostArch -SkipAutomaticLocation | Out-Null

foreach ($tool in "cl", "cmake", "ninja", "dumpbin") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found on PATH after entering the VS dev shell."
    }
}
Write-Ok "cl, cmake, ninja, dumpbin resolved"

# ---- Clean ----------------------------------------------------------------
Write-Section "Cleaning previous outputs"
$buildDir = Join-Path $RepoRoot $BuildDirName
$distPath = Join-Path $RepoRoot $DistDir
foreach ($dir in $buildDir, $distPath) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
        Write-Host "removed $dir"
    }
}

# ---- Configure + build Release ---------------------------------------------
Write-Section "Configuring (cmake -G Ninja -DCMAKE_BUILD_TYPE=Release)"
cmake -S . -B $BuildDirName -G Ninja -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }
Write-Ok "configure succeeded"

Write-Section "Building"
cmake --build $BuildDirName --config Release
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }
Write-Ok "build succeeded"

$dllPath = Join-Path $RepoRoot "$BuildDirName\HkdfGuard.Kms.Windows.v1.dll"
$cliPath = Join-Path $RepoRoot "$BuildDirName\tools\hkdfguard-v1-initialize.exe"
foreach ($p in $dllPath, $cliPath) {
    if (-not (Test-Path $p)) { throw "expected Release build output missing: $p" }
}

# ---- Verify the build actually produced the target architecture -----------
# A misconfigured toolchain (e.g. -HostArch/-Arch resolved to the same
# native compiler despite -Arch ARM64 being requested) would otherwise
# silently produce an x64 binary in an "ARM64" dist folder. dumpbin
# /headers' "machine type" line reports what the linker actually targeted,
# independent of anything this script assumed going in.
Write-Section "Verifying target architecture"
$expectedMachine = if ($Arch -eq "ARM64") { "ARM64" } else { "x64" }
foreach ($bin in $dllPath, $cliPath) {
    $name = Split-Path -Leaf $bin
    $machineLine = dumpbin /headers $bin | Select-String -Pattern "machine \("
    if ($machineLine -notmatch [regex]::Escape($expectedMachine)) {
        throw "$name was not built for $Arch - dumpbin reports: $($machineLine.ToString().Trim())"
    }
    Write-Ok "$name is $Arch ($($machineLine.ToString().Trim()))"
}

# ---- Stage the dist folder --------------------------------------------------
Write-Section "Staging $DistDir"
New-Item -ItemType Directory -Force -Path $distPath | Out-Null
Copy-Item -Path $dllPath -Destination $distPath -Force
Copy-Item -Path $cliPath -Destination $distPath -Force
Write-Ok "copied $(Split-Path -Leaf $dllPath) and $(Split-Path -Leaf $cliPath) to $DistDir"

# ---- Dependency sanity check ------------------------------------------------
Write-Section "Runtime dependency check"
$offendingDeps = @()
foreach ($bin in $dllPath, $cliPath) {
    $name = Split-Path -Leaf $bin
    $deps = dumpbin /dependents $bin | Select-String -Pattern "\.dll$" | ForEach-Object { $_.ToString().Trim() }
    Write-Host "${name}:"
    $deps | ForEach-Object { Write-Host "    $_" }
    $badOnes = $deps | Where-Object { $_ -match "^(MSVCP|VCRUNTIME|api-ms-win-crt-)" }
    if ($badOnes) {
        $offendingDeps += $badOnes | ForEach-Object { "$name -> $_" }
    }
}
if ($offendingDeps) {
    Write-Host "[WARN] found redistributable-dependent DLL(s); CMAKE_MSVC_RUNTIME_LIBRARY may not have taken effect:" -ForegroundColor Yellow
    $offendingDeps | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
} else {
    Write-Ok "no MSVC/UCRT redistributable dependencies - both binaries are self-contained"
}

Write-Section "Done"
Write-Host "Artifacts staged in: $distPath"
