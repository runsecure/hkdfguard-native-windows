<#
.SYNOPSIS
    Clean-builds the Release configuration for one target architecture and
    stages the two artifacts other tooling actually needs - the DLL and the
    CLI - into dist\win-<arch>.

.DESCRIPTION
    1. Enters the Visual Studio Build Tools developer environment for -Arch
       (x64 or ARM64), cross-compiling when the host architecture differs.
       The VS install needs the matching C++ build tools component:
       VC.Tools.x86.x64 for x64, VC.Tools.ARM64 for ARM64.
    2. Deletes any existing build-release-<arch>\ and dist\win-<arch>\
       directories, then configures and builds Release from scratch
       (cmake -G Ninja -DCMAKE_BUILD_TYPE=Release), so no setting cached in
       a reused build directory can outlive a CMakeLists.txt change. Each
       architecture has its own build directory.
    3. Checks each binary's target architecture and exploit mitigations.
    4. Copies HkdfGuard.dll and hkdfguard.exe (which needs the DLL next to
       it) into dist\win-<arch>\.
    5. Reports each binary's DLL dependencies (dumpbin /dependents) to
       confirm the static runtime linking took effect: neither should
       depend on MSVCP140.dll, VCRUNTIME140*.dll or the api-ms-win-crt-*.dll
       forwarders, only core Windows system DLLs.

    Does not run the test suite (that needs an elevated shell - see
    Build-Test-Verify.ps1) and does not need elevation itself: building
    doesn't touch the machine-wide KEK. A cross-compiled build has only been
    compiled, not run, for its architecture; run Build-Test-Verify.ps1 on
    real or emulated ARM64 Windows before trusting an ARM64 build.

.PARAMETER Arch
    Target architecture: x64 or ARM64. Default: x64.

.PARAMETER DistDir
    Where the two artifacts are staged, relative to the repo root.
    Default: dist\win-<arch lowercased>.

.PARAMETER Sign
    Authenticode-sign the two staged binaries through Azure Artifact Signing
    (scripts\ArtifactSigning.ps1), then verify each has a valid, timestamped
    signature. The signing setup - signtool, the Artifact Signing plugin,
    the metadata file and the Azure sign-in - is checked before the build
    starts, so a misconfiguration fails in seconds rather than after it.
    Without -Sign the binaries are unsigned (local testing only).

.PARAMETER SigningMetadata
    Artifact Signing metadata JSON. Default: scripts\signing\metadata.json
    (or the HKDFGUARD_SIGNING_METADATA environment variable).

.PARAMETER SigningDlib
    Path to a Microsoft-signed x64 Azure.CodeSigning.Dlib.dll. Default:
    HKDFGUARD_SIGNING_DLIB, else the pinned NuGet plugin ArtifactSigning.ps1
    fetches and verifies.
#>
param(
    [ValidateSet("x64", "ARM64")]
    [string]$Arch = "x64",
    [string]$DistDir,
    [switch]$Sign,
    [string]$SigningMetadata,
    [string]$SigningDlib
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

# ---- Signing preflight (only with -Sign) ----------------------------------
if ($Sign) {
    Write-Section "Checking the Artifact Signing setup"
    . (Join-Path $PSScriptRoot "ArtifactSigning.ps1")
    $signingConfig = Initialize-ArtifactSigning -MetadataPath $SigningMetadata -DlibPath $SigningDlib
    Write-Ok "signing setup is ready"
}

# ---- Locate and enter the VS Build Tools developer environment --------
Write-Section "Locating MSVC / CMake / Ninja (target: $Arch)"
$installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$vswhere = Join-Path $installerDir "vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere - is Visual Studio / Build Tools installed?"
}
$env:PATH = "$env:PATH;$installerDir"

# The C++ build tools component is architecture-specific. Requiring the one
# for -Arch makes vswhere skip installs that can't compile for it, so the
# failure is this clear error rather than a later "cl.exe not found".
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

# Launch-VsDevShell.ps1 names architectures amd64/arm64; this script uses
# x64/ARM64, matching the win-x64/win-arm64 dist folder names.
$vsArchMap = @{ "x64" = "amd64"; "ARM64" = "arm64" }
$vsTargetArch = $vsArchMap[$Arch]

# The host architecture decides between a native toolchain and a
# cross-compiler, so cl.exe always runs on the host it was built for.
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

$dllPath = Join-Path $RepoRoot "$BuildDirName\HkdfGuard.dll"
$cliPath = Join-Path $RepoRoot "$BuildDirName\tools\hkdfguard.exe"
foreach ($p in $dllPath, $cliPath) {
    if (-not (Test-Path $p)) { throw "expected Release build output missing: $p" }
}

# ---- Verify the build actually produced the target architecture -----------
# A misconfigured toolchain could put an x64 binary in an "ARM64" dist
# folder. dumpbin /headers' "machine" line reports what the linker actually
# targeted.
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

# ---- Verify the exploit mitigations made it into the binaries -------------
# The flags are set by hkdfguard_apply_hardening in CMakeLists.txt; this
# checks what the linker actually produced, so a dropped flag fails the
# release build instead of shipping silently. /CETCOMPAT and /guard:ehcont
# are x64-only (see CMakeLists.txt), so ARM64 is checked for the rest.
# /sdl and /Qspectre leave no marker in the PE headers and can't be checked
# here.
Write-Section "Verifying exploit mitigations"
$requiredHeaderMarks = @("Dynamic base", "High Entropy Virtual Addresses", "NX compatible", "Control Flow Guard")
if ($Arch -eq "x64") { $requiredHeaderMarks += "CET compatible" }
foreach ($bin in $dllPath, $cliPath) {
    $name = Split-Path -Leaf $bin
    $headers = (dumpbin /headers $bin) -join "`n"
    $missing = @($requiredHeaderMarks | Where-Object { $headers -notmatch [regex]::Escape($_) })
    if ($Arch -eq "x64") {
        $loadConfig = (dumpbin /loadconfig $bin) -join "`n"
        if ($loadConfig -notmatch "EH Continuation table present") { $missing += "EH continuation table (/guard:ehcont)" }
    }
    if ($missing.Count -gt 0) {
        throw "$name is missing exploit mitigations: $($missing -join ', ')"
    }
    Write-Ok "$name has: $($requiredHeaderMarks -join ', ')$(if ($Arch -eq 'x64') { ', EH continuation table' })"
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

# ---- Sign the staged binaries (only with -Sign) ---------------------------
# Signs the copies in the dist folder - the files that ship - after every
# check above has passed on them, so nothing modifies them afterwards.
$stagedBinaries = @(
    (Join-Path $distPath (Split-Path -Leaf $dllPath)),
    (Join-Path $distPath (Split-Path -Leaf $cliPath)))
if ($Sign) {
    Write-Section "Signing with Azure Artifact Signing"
    Invoke-ArtifactSigning -Files $stagedBinaries -Config $signingConfig
} else {
    Write-Host "[WARN] -Sign not given: the staged binaries are UNSIGNED (local testing only)" -ForegroundColor Yellow
}

Write-Section "Done"
Write-Host "Artifacts staged in: $distPath$(if ($Sign) { ' (signed)' })"
