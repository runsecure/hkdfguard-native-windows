<#
.SYNOPSIS
    The complete signed distribution build: clean Release builds for x64 and
    ARM64, staged into dist\win-<arch>, Authenticode-signed through Azure
    Artifact Signing - and, with -Msi, the signed MSI installers too.

.DESCRIPTION
    1. Checks the Artifact Signing setup once, up front (signtool, the
       Artifact Signing plugin, scripts\signing\metadata.json, the Azure
       sign-in), so a misconfiguration fails before minutes of building.
    2. For each architecture, in its own PowerShell process (each enters a
       different Visual Studio developer environment):
         - without -Msi: Build-Dist.ps1 -Sign
           (clean build, exploit-mitigation checks, stage, sign, verify);
         - with -Msi:    Build-Msi.ps1 -Sign
           (all of the above, then the MSI, signed, with its content checks).
    3. Re-verifies every produced file has a valid, timestamped signature and
       prints a summary with each file's SHA-256.

    Needs no elevation. Stops at the first failure.

.PARAMETER Arch
    x64, ARM64, or All (default) for both.

.PARAMETER Msi
    Also build the signed MSI installer for each architecture.

.PARAMETER Version
    MSI ProductVersion (major.minor.build). Required with -Msi; must be
    higher than any version already deployed, or the upgrade won't replace it.

.PARAMETER SigningMetadata
    Artifact Signing metadata JSON. Default: scripts\signing\metadata.json.

.PARAMETER SigningDlib
    Path to the x64 Azure.CodeSigning.Dlib.dll. Default: the Artifact Signing
    client tools' install location.

.EXAMPLE
    scripts\build-dist-signed.bat
    scripts\build-dist-signed.bat -Msi -Version 1.0.0
    powershell -File scripts\Build-Dist-Signed.ps1 -Arch x64
#>
param(
    [ValidateSet("x64", "ARM64", "All")]
    [string]$Arch = "All",
    [switch]$Msi,
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,5}$')]
    [string]$Version,
    [string]$SigningMetadata,
    [string]$SigningDlib
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Write-Section($title) {
    Write-Host ""
    Write-Host "==== $title ====" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }

if ($Msi -and -not $Version) {
    throw "-Msi needs -Version (major.minor.build), higher than any version already deployed."
}
$archs = if ($Arch -eq "All") { @("x64", "ARM64") } else { @($Arch) }

# ---- 1. Signing preflight ---------------------------------------------------
Write-Section "Checking the Artifact Signing setup"
. (Join-Path $PSScriptRoot "ArtifactSigning.ps1")
$signingConfig = Initialize-ArtifactSigning -MetadataPath $SigningMetadata -DlibPath $SigningDlib
Write-Ok "signing setup is ready"

# The child processes get the already-resolved paths, so every build signs
# with exactly what was checked here.
$signingArgs = @("-Sign", "-SigningMetadata", $signingConfig.Metadata.Path, "-SigningDlib", $signingConfig.Dlib)

# ---- 2. Build, sign (and package) each architecture -------------------------
$started = Get-Date
foreach ($a in $archs) {
    if ($Msi) {
        Write-Section "Signed build + MSI: $a"
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Build-Msi.ps1") `
            -Arch $a -Version $Version @signingArgs
        if ($LASTEXITCODE -ne 0) { throw "Build-Msi.ps1 -Arch $a failed (exit $LASTEXITCODE)" }
    } else {
        Write-Section "Signed build: $a"
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Build-Dist.ps1") `
            -Arch $a @signingArgs
        if ($LASTEXITCODE -ne 0) { throw "Build-Dist.ps1 -Arch $a failed (exit $LASTEXITCODE)" }
    }
}

# ---- 3. Final verification of everything produced ---------------------------
Write-Section "Verifying every signed artifact"
$artifacts = @()
foreach ($a in $archs) {
    $lower = $a.ToLower()
    $artifacts += Join-Path $RepoRoot "dist\win-$lower\HkdfGuardV1.dll"
    $artifacts += Join-Path $RepoRoot "dist\win-$lower\hkdfguard-v1-initialize.exe"
    if ($Msi) { $artifacts += Join-Path $RepoRoot "dist\hkdfguard-native-windows-$Version-win-$lower.msi" }
}
foreach ($file in $artifacts) {
    if (-not (Test-Path $file)) { throw "expected artifact missing: $file" }
    if ((Get-Item $file).LastWriteTime -lt $started) { throw "$file was not rebuilt by this run" }
}
Assert-ArtifactSignature -Files $artifacts -Config $signingConfig

Write-Section "Done"
foreach ($file in $artifacts) {
    $hash = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
    Write-Host ("{0}  {1}" -f $hash, $file.Substring($RepoRoot.Length + 1))
}
Write-Host ""
Write-Host "All $($artifacts.Count) artifacts are built, signed and timestamped." -ForegroundColor Green
