<#
.SYNOPSIS
    Builds the machine-wide MSI installer for hkdfguard-native-windows.

.DESCRIPTION
    1. Runs Build-Dist.ps1 for -Arch (clean Release build, staged into
       dist\win-<arch>) unless -SkipBuild is passed.
    2. With -Sign, the staged DLL and CLI are Authenticode-signed through
       Azure Artifact Signing (scripts\ArtifactSigning.ps1) *before*
       packaging, so the files the MSI installs are the signed ones. Build-Dist
       does that signing when it runs; with -SkipBuild, staged binaries that
       aren't already validly signed and timestamped are signed here.
    3. Restores the repo-pinned WiX toolset (dotnet-tools.json, WiX 5.0.2)
       and its Util extension, then builds installer\hkdfguard-native-windows.wxs
       into dist\hkdfguard-native-windows-<version>-win-<arch>.msi.
    4. With -Sign, signs the MSI itself too.
    5. Reads the built MSI's own tables back (File, Directory, Registry,
       CustomAction) and checks they contain exactly what the installer is
       supposed to install, so a packaging mistake fails here rather than on
       a target machine.

    Building does not need elevation. *Installing* the MSI does (it writes to
    Program Files and HKLM, and creates a local group); see README.md.

    WiX 5.0.2 is pinned deliberately: later major versions require accepting
    a separate maintenance-fee EULA before they will build.

.PARAMETER Arch
    x64 or ARM64. Default: x64.

.PARAMETER Version
    MSI ProductVersion, major.minor.build (major and minor at most 255, build
    at most 65535). Must increase for every release, or the major upgrade
    will not replace the installed version. Default: 1.0.0.

.PARAMETER Manufacturer
    Manufacturer shown in Apps & Features. Default: HkdfGuard.

.PARAMETER Sign
    Sign the binaries and the MSI through Azure Artifact Signing, and verify
    every signature is valid and timestamped. The signing setup is checked
    before anything is built. When omitted, nothing is signed and a warning
    is printed - fine for local testing, not for deployment.

.PARAMETER SigningMetadata
    Artifact Signing metadata JSON. Default: scripts\signing\metadata.json
    (or the HKDFGUARD_SIGNING_METADATA environment variable).

.PARAMETER SigningDlib
    Path to the x64 Azure.CodeSigning.Dlib.dll. Default: the Artifact Signing
    client tools' install location (or HKDFGUARD_SIGNING_DLIB).

.PARAMETER SkipBuild
    Package whatever is already staged in dist\win-<arch> instead of
    rebuilding it first.
#>
param(
    [ValidateSet("x64", "ARM64")]
    [string]$Arch = "x64",
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,5}$')]
    [string]$Version = "1.0.0",
    [string]$Manufacturer = "HkdfGuard",
    [switch]$Sign,
    [string]$SigningMetadata,
    [string]$SigningDlib,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$parts = $Version.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
    throw "-Version $Version is outside MSI limits (major.minor <= 255, build <= 65535)."
}

$ArchLower = $Arch.ToLower()
$StageDir = Join-Path $RepoRoot "dist\win-$ArchLower"
$WixArch = if ($Arch -eq "ARM64") { "arm64" } else { "x64" }
$MsiPath = Join-Path $RepoRoot "dist\hkdfguard-native-windows-$Version-win-$ArchLower.msi"
$WxsPath = Join-Path $RepoRoot "installer\hkdfguard-native-windows.wxs"
$Binaries = "HkdfGuardV1.dll", "hkdfguard-v1-initialize.exe"

function Write-Section($title) {
    Write-Host ""
    Write-Host "==== $title ====" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }

# ---- Signing preflight (only with -Sign) ----------------------------------
# Checked before the build, so a signing misconfiguration fails in seconds.
if ($Sign) {
    Write-Section "Checking the Artifact Signing setup"
    . (Join-Path $PSScriptRoot "ArtifactSigning.ps1")
    $signingConfig = Initialize-ArtifactSigning -MetadataPath $SigningMetadata -DlibPath $SigningDlib
    Write-Ok "signing setup is ready"
}

# ---- 1. Release build -------------------------------------------------------
if (-not $SkipBuild) {
    Write-Section "Release build ($Arch) via Build-Dist.ps1"
    $distArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "Build-Dist.ps1"), "-Arch", $Arch)
    if ($Sign) {
        $distArgs += "-Sign"
        if ($signingConfig) { $distArgs += @("-SigningMetadata", $signingConfig.Metadata.Path, "-SigningDlib", $signingConfig.Dlib) }
    }
    & powershell @distArgs
    if ($LASTEXITCODE -ne 0) { throw "Build-Dist.ps1 failed (exit $LASTEXITCODE)" }
}
foreach ($b in $Binaries) {
    if (-not (Test-Path (Join-Path $StageDir $b))) { throw "staged binary missing: $StageDir\$b (run without -SkipBuild)" }
}
Write-Ok "staged binaries present in $StageDir"

# ---- 2. The binaries must be signed before packaging ---------------------------
$stagedFiles = @($Binaries | ForEach-Object { Join-Path $StageDir $_ })
if ($Sign) {
    Write-Section "Checking the staged binaries' signatures"
    $unsigned = @($stagedFiles | Where-Object { -not (Test-ArtifactSignature -File $_) })
    if ($unsigned.Count -gt 0) {
        Write-Host "Signing $($unsigned.Count) staged binary(ies) that aren't validly signed yet..."
        Invoke-ArtifactSigning -Files $unsigned -Config $signingConfig
    }
    Assert-ArtifactSignature -Files $stagedFiles -Config $signingConfig
} else {
    Write-Host "[WARN] -Sign not given: binaries and MSI will be UNSIGNED (local testing only)" -ForegroundColor Yellow
}

# ---- 3. Build the MSI ------------------------------------------------------------
Write-Section "Restoring WiX (pinned in dotnet-tools.json)"
dotnet tool restore
if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed" }
dotnet tool run wix extension add WixToolset.Util.wixext/5.0.2
if ($LASTEXITCODE -ne 0) { throw "adding WixToolset.Util.wixext failed" }

Write-Section "Building $(Split-Path -Leaf $MsiPath)"
if (Test-Path $MsiPath) { Remove-Item -Force $MsiPath }
dotnet tool run wix build $WxsPath `
    -arch $WixArch `
    -ext WixToolset.Util.wixext `
    -d "SourceDir=$StageDir" `
    -d "ProductVersion=$Version" `
    -d "Manufacturer=$Manufacturer" `
    -o $MsiPath
if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }
# wix writes a .wixpdb debug file next to the MSI; it isn't shipped.
Remove-Item -Force -ErrorAction SilentlyContinue ([IO.Path]::ChangeExtension($MsiPath, ".wixpdb"))
Write-Ok "built $MsiPath"

# ---- 4. Sign the MSI ---------------------------------------------------------------
if ($Sign) {
    Write-Section "Signing the MSI"
    Invoke-ArtifactSigning -Files @($MsiPath) -Config $signingConfig
}

# ---- 5. Verify what the MSI actually contains --------------------------------------
Write-Section "Verifying MSI contents"
$installer = New-Object -ComObject WindowsInstaller.Installer
# 0 = msiOpenDatabaseModeReadOnly.
$db = $installer.OpenDatabase([string]$MsiPath, 0)
# Returns each row as a string array of `$columns` fields. Fields are read
# with a plain for-loop and an explicit [int]: piping indexes through
# ForEach-Object hands COM a wrapped object, and the Windows Installer
# automation interface rejects that (DISP_E_TYPEMISMATCH) or misreads it.
#
# The [void] casts matter: these automation methods return nothing, but
# PowerShell still emits a $null into the function's output for each call,
# which would otherwise arrive ahead of the real rows.
function Get-Rows([string]$sql, [int]$columns) {
    $view = $db.OpenView($sql)
    [void]$view.Execute()
    $rows = New-Object System.Collections.Generic.List[object]
    while ($true) {
        $rec = $view.Fetch()
        if ($null -eq $rec) { break }
        $fields = New-Object string[] $columns
        for ($c = 1; $c -le $columns; $c++) {
            $fields[$c - 1] = $rec.StringData([int]$c)
        }
        [void]$rows.Add($fields)
    }
    [void]$view.Close()
    return , $rows.ToArray()
}
$failures = 0
function Expect($cond, $what) {
    if ($cond) { Write-Ok $what } else { Write-Host "[FAIL] $what" -ForegroundColor Red; $script:failures++ }
}

# File.FileName is "SHORTNAME|LongName"; the long name is what lands on disk.
$files = (Get-Rows "SELECT ``FileName`` FROM ``File``" 1) | ForEach-Object { ($_[0] -split '\|')[-1] }
Expect ((($files | Sort-Object) -join ',') -eq (($Binaries | Sort-Object) -join ',')) "installs exactly: $($Binaries -join ', ')"

$dirs = Get-Rows "SELECT ``Directory``, ``Directory_Parent``, ``DefaultDir`` FROM ``Directory``" 3
$installDir = $dirs | Where-Object { $_[0] -eq 'HkdfGuardInstallDir' }
$rootDir = $dirs | Where-Object { $_[0] -eq 'HkdfGuardRootDir' }
# DefaultDir is either "LongName" or "SHORT~1|LongName"; match the long name.
Expect ($installDir -and $installDir[1] -eq 'HkdfGuardRootDir' -and $installDir[2] -match '(^|\|)v1$') "install folder is ...\HkdfGuard\v1"
Expect ($rootDir -and $rootDir[1] -eq 'ProgramFiles64Folder' -and $rootDir[2] -match '(^|\|)HkdfGuard$') "under the native Program Files folder, in HkdfGuard"
# A public (all-uppercase) directory id could be redirected from the
# msiexec command line into a user-writable folder, undoing the ACL
# protection the install location exists for.
Expect (-not ($dirs | Where-Object { $_[0] -like 'HkdfGuard*' -and $_[0] -ceq $_[0].ToUpperInvariant() })) "install location is not overridable from the msiexec command line"

$reg = Get-Rows "SELECT ``Root``, ``Key``, ``Name``, ``Value`` FROM ``Registry``" 4
$installPathRow = $reg | Where-Object { $_[0] -eq '2' -and $_[1] -eq 'Software\hkdfguard-native-windows' -and $_[2] -eq 'InstallPath' -and $_[3] -eq '[HkdfGuardInstallDir]' }
Expect ($null -ne $installPathRow) "writes HKLM\Software\hkdfguard-native-windows\InstallPath"
$eventSourceKey = 'SYSTEM\CurrentControlSet\Services\EventLog\Application\hkdfguard-native-windows'
# Registry.Value encodes the type in a prefix: "#%" = REG_EXPAND_SZ, "#" = REG_DWORD.
$msgFileRow = $reg | Where-Object { $_[0] -eq '2' -and $_[1] -eq $eventSourceKey -and $_[2] -eq 'EventMessageFile' -and $_[3] -eq '#%[#HkdfGuardDllFile]' }
$typesRow = $reg | Where-Object { $_[0] -eq '2' -and $_[1] -eq $eventSourceKey -and $_[2] -eq 'TypesSupported' -and $_[3] -eq '#7' }
Expect ($null -ne $msgFileRow -and $null -ne $typesRow) "registers the hkdfguard-native-windows event source with the DLL as its message file"

$ca = Get-Rows "SELECT ``Action``, ``Type`` FROM ``CustomAction`` WHERE ``Action``='CreateHkdfGuardUsersGroup'" 2
# msidbCustomActionTypeInScript (0x400) + NoImpersonate (0x800) = deferred,
# as LocalSystem; ContinueOnReturn (0x40) must be clear so a failure fails
# the install.
$caType = if ($ca.Count -eq 1) { [int]$ca[0][1] } else { 0 }
Expect ($ca.Count -eq 1 -and ($caType -band 0xC00) -eq 0xC00 -and ($caType -band 0x40) -eq 0) "creates HkdfGuardUsers in a deferred, non-impersonated, checked custom action"

$seq = @{}
foreach ($row in (Get-Rows "SELECT ``Action``, ``Sequence`` FROM ``InstallExecuteSequence``" 2)) { $seq[$row[0]] = [int]$row[1] }
Expect ($seq['RemoveExistingProducts'] -gt $seq['InstallInitialize'] -and $seq['RemoveExistingProducts'] -lt $seq['InstallFiles']) "upgrades remove the previous version before installing files"

$tables = (Get-Rows "SELECT ``Name`` FROM ``_Tables``" 1) | ForEach-Object { $_[0] }
Expect (-not ($tables -contains 'LockPermissions') -and -not ($tables -contains 'MsiLockPermissionsEx')) "sets no custom permissions (install folder keeps the Program Files ACL)"

[System.Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null

Write-Section "Done"
if ($failures -gt 0) {
    Write-Host "$failures MSI content check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "MSI: $MsiPath"
Write-Host "Install (elevated):   msiexec /i `"$MsiPath`" /qn /l*v install.log"
