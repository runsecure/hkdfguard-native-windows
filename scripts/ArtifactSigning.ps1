<#
.SYNOPSIS
    Shared Authenticode signing helpers for Azure Artifact Signing. Dot-source
    this file; it defines functions and does nothing on its own:

        . (Join-Path $PSScriptRoot "ArtifactSigning.ps1")

.DESCRIPTION
    Signs with the Windows SDK signtool.exe plus the Artifact Signing
    signtool plugin ("dlib"), which sends each file's digest to the Artifact
    Signing account named in a metadata JSON file and receives the signature
    back. The private key never leaves Microsoft's HSMs, so there is no
    certificate file or thumbprint involved.

    What the signing machine needs (see README.md, "Signing"):
      - Windows SDK signtool.exe 10.0.22621 or newer (x64). The 20348 SDK's
        signtool is not supported by the plugin.
      - The x64 signtool plugin. Fetched automatically on first use from
        Microsoft's NuGet package (Microsoft.ArtifactSigning.Client, pinned by
        version and SHA-256, the same one CI uses) into
        %LOCALAPPDATA%\HkdfGuard\signing, and checked against its pinned
        hash and Microsoft's signature on every run.
      - .NET 8 or newer (the plugin rolls forward to newer major versions).
      - A metadata JSON file naming the account endpoint, account and
        certificate profile - scripts\signing\metadata.json by default.
      - An Azure sign-in the plugin can use - by default `az login` - for an
        identity holding the "Artifact Signing Certificate Profile Signer"
        role on the account or profile.

    Artifact Signing certificates are valid for three days, so every
    signature is RFC 3161 timestamped; an untimestamped signature would stop
    validating after that. Assert-ArtifactSignature checks for it.

    Overrides, in order of precedence: the function parameters, then the
    environment variables HKDFGUARD_SIGNING_METADATA, HKDFGUARD_SIGNING_DLIB
    and HKDFGUARD_SIGNTOOL, then the defaults above.
#>

$script:ArtifactSigningTimestampUrl = "http://timestamp.acs.microsoft.com"

# Newest x64 signtool.exe from Windows SDK 10.0.22621 or later.
function Get-ArtifactSigningSignTool {
    param([string]$Path)
    if (-not $Path) { $Path = $env:HKDFGUARD_SIGNTOOL }
    if ($Path) {
        if (-not (Test-Path $Path)) { throw "signtool.exe not found at $Path" }
        return (Resolve-Path $Path).Path
    }
    $candidates = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Where-Object {
            $version = $null
            [version]::TryParse($_.Directory.Parent.Name, [ref]$version) -and
                $version -ge [version]"10.0.22621.0" -and $version.Build -ne 20348
        } |
        Sort-Object { [version]$_.Directory.Parent.Name } -Descending
    if (-not $candidates) {
        throw "No x64 signtool.exe from Windows SDK 10.0.22621 or newer was found under Windows Kits\10\bin. Install the Windows SDK signing tools."
    }
    return $candidates[0].FullName
}

# The signtool plugin, from Microsoft's NuGet package - the same one the
# release workflow uses (keep the two pins in step with
# .github/workflows/release.yml). Not the winget client tools: that
# installer ships the plugin unsigned, so nothing could tell it from a
# replacement planted in the user-writable folder it lives in. The plugin
# runs inside signtool with the signer's Azure sign-in and chooses the digest
# that gets signed, so it is verified on every run, not just when fetched.
$script:ArtifactSigningClientVersion = "1.0.146"
$script:ArtifactSigningClientSha256 = "7761E5D8F31E54B764DA21D33CD8B0A2940E1B05526C7DFCB5E94B0431426F70" # the .nupkg
$script:ArtifactSigningDlibSha256 = "123FA0C50341777D8E5B1414DF52F39A1F2C7AB4A9F716ABF6310069A6CB8A19"   # bin\x64\Azure.CodeSigning.Dlib.dll in it

# Refuses a plugin without a valid Authenticode signature from Microsoft.
function Assert-ArtifactSigningDlibSignature {
    param([Parameter(Mandatory)][string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "(^|, )O=Microsoft Corporation(,|$)") {
        throw "The Artifact Signing plugin $Path is not validly signed by Microsoft ($($sig.Status): $($sig.SignerCertificate.Subject)); refusing to sign with it."
    }
}

# The pinned NuGet package's x64 plugin, downloaded into a per-user cache on
# first use. Every call re-checks the cached plugin's SHA-256 and signature,
# so a cache someone has since changed is refused rather than used.
function Get-PinnedArtifactSigningDlib {
    $version = $script:ArtifactSigningClientVersion
    $cache = Join-Path $env:LOCALAPPDATA "HkdfGuard\signing\microsoft.artifactsigning.client.$version"
    $dlib = Join-Path $cache "bin\x64\Azure.CodeSigning.Dlib.dll"
    if (-not (Test-Path $dlib)) {
        $parent = Split-Path -Parent $cache
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
        $pkg = Join-Path $parent "microsoft.artifactsigning.client.$version.zip" # .zip: Expand-Archive insists on it
        $staging = "$cache.partial"
        Write-Host "Downloading Microsoft.ArtifactSigning.Client $version (the signtool plugin) into $parent"
        $savedProgress = $ProgressPreference
        $ProgressPreference = "SilentlyContinue" # Windows PowerShell's progress bar slows Invoke-WebRequest badly
        try {
            Invoke-WebRequest -UseBasicParsing -TimeoutSec 300 -OutFile $pkg `
                -Uri "https://api.nuget.org/v3-flatcontainer/microsoft.artifactsigning.client/$version/microsoft.artifactsigning.client.$version.nupkg"
        } finally {
            $ProgressPreference = $savedProgress
        }
        $actual = (Get-FileHash -Path $pkg -Algorithm SHA256).Hash
        if ($actual -ne $script:ArtifactSigningClientSha256) {
            Remove-Item -Force $pkg
            throw "Microsoft.ArtifactSigning.Client $version has SHA-256 $actual, not the pinned $($script:ArtifactSigningClientSha256)."
        }
        if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
        Expand-Archive -Path $pkg -DestinationPath $staging
        Remove-Item -Force $pkg
        Rename-Item -Path $staging -NewName (Split-Path -Leaf $cache) # only a complete extraction becomes the cache
    }
    $actual = (Get-FileHash -Path $dlib -Algorithm SHA256).Hash
    if ($actual -ne $script:ArtifactSigningDlibSha256) {
        throw "The cached Artifact Signing plugin $dlib has SHA-256 $actual, not the pinned $($script:ArtifactSigningDlibSha256). Delete $cache to download it again."
    }
    Assert-ArtifactSigningDlibSignature -Path $dlib
    return $dlib
}

# The x64 Artifact Signing plugin (Azure.CodeSigning.Dlib.dll): the pinned
# NuGet copy by default, or one given by parameter / HKDFGUARD_SIGNING_DLIB,
# which must also carry Microsoft's signature. Must match signtool's
# architecture, which is x64 here.
function Get-ArtifactSigningDlib {
    param([string]$Path)
    if (-not $Path) { $Path = $env:HKDFGUARD_SIGNING_DLIB }
    if (-not $Path) { return Get-PinnedArtifactSigningDlib }
    if (-not (Test-Path $Path)) {
        throw "Artifact Signing plugin not found at $Path."
    }
    Assert-ArtifactSigningDlibSignature -Path (Resolve-Path $Path).Path
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path $Path).Path)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0x8664) {
        throw ("{0} is not the x64 plugin (machine type 0x{1:X4}); the x64 signtool needs the x64 plugin." -f $Path, $machine)
    }
    return (Resolve-Path $Path).Path
}

# Loads and checks the metadata JSON. Returns its full path and parsed form.
function Get-ArtifactSigningMetadata {
    param([string]$Path)
    if (-not $Path) { $Path = $env:HKDFGUARD_SIGNING_METADATA }
    if (-not $Path) { $Path = Join-Path $PSScriptRoot "signing\metadata.json" }
    if (-not (Test-Path $Path)) {
        throw "Signing metadata not found at $Path. Create it from scripts\signing\metadata.json's format, or pass -SigningMetadata."
    }
    $fullPath = (Resolve-Path $Path).Path
    try {
        $metadata = Get-Content -Raw $fullPath | ConvertFrom-Json
    } catch {
        throw "Signing metadata $fullPath is not valid JSON: $($_.Exception.Message)"
    }
    foreach ($field in "Endpoint", "CodeSigningAccountName", "CertificateProfileName") {
        if ([string]::IsNullOrWhiteSpace($metadata.$field) -or $metadata.$field -match '^<.*>$') {
            throw "Signing metadata $fullPath has no real value for '$field'."
        }
    }
    if ($metadata.Endpoint -notmatch '^https://[a-z0-9]+\.codesigning\.azure\.net/?$') {
        throw "Signing metadata Endpoint '$($metadata.Endpoint)' is not an Artifact Signing regional endpoint (https://<region>.codesigning.azure.net). It must match the account's region."
    }
    return [PSCustomObject]@{ Path = $fullPath; Data = $metadata }
}

# When the plugin is allowed to use the Azure CLI sign-in (the default),
# makes sure `az` is reachable from this process - a terminal opened before
# the CLI was installed doesn't see it on PATH, and neither would the plugin
# signtool loads - and that it is signed in.
function Assert-ArtifactSigningAuth {
    param([Parameter(Mandatory)] $Metadata)
    $excluded = @($Metadata.Data.ExcludeCredentials)
    if ($excluded -contains "AzureCliCredential") {
        Write-Host "Azure CLI credential excluded by the metadata; relying on the remaining sign-in methods."
        return
    }
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        $cliBin = Join-Path $env:ProgramFiles "Microsoft SDKs\Azure\CLI2\wbin"
        if (Test-Path (Join-Path $cliBin "az.cmd")) {
            $env:PATH = "$cliBin;$env:PATH"
        } else {
            throw "The Azure CLI (az) is not installed or not on PATH, and the signing metadata relies on its sign-in. Install it, or sign in another way and exclude AzureCliCredential."
        }
    }
    # Native stderr under ErrorActionPreference=Stop throws in Windows
    # PowerShell 5.1, so the check runs with Continue and reads the exit code.
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $account = & az account show --query "user.name" -o tsv 2>$null
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($exit -ne 0 -or -not $account) {
        throw "The Azure CLI is not signed in. Run 'az login' with an account that holds the Artifact Signing Certificate Profile Signer role, then retry."
    }
    Write-Host "Signing as Azure CLI account: $account"
}

# Checks everything signing needs before any build work starts. Returns the
# resolved configuration for Invoke-ArtifactSigning.
function Initialize-ArtifactSigning {
    param([string]$MetadataPath, [string]$DlibPath, [string]$SignToolPath)
    $config = [PSCustomObject]@{
        SignTool = Get-ArtifactSigningSignTool -Path $SignToolPath
        Dlib     = Get-ArtifactSigningDlib -Path $DlibPath
        Metadata = Get-ArtifactSigningMetadata -Path $MetadataPath
    }
    Write-Host "signtool:  $($config.SignTool)"
    Write-Host "plugin:    $($config.Dlib)"
    Write-Host "metadata:  $($config.Metadata.Path)"
    Write-Host ("account:   {0} / profile {1} at {2}" -f $config.Metadata.Data.CodeSigningAccountName,
        $config.Metadata.Data.CertificateProfileName, $config.Metadata.Data.Endpoint)
    Assert-ArtifactSigningAuth -Metadata $config.Metadata
    return $config
}

# True when a file carries a valid, timestamped Authenticode signature.
function Test-ArtifactSignature {
    param([Parameter(Mandatory)][string]$File)
    $signature = Get-AuthenticodeSignature -FilePath $File
    return ($signature.Status -eq "Valid" -and $null -ne $signature.TimeStamperCertificate)
}

# Fails unless every file has a valid, timestamped signature, and reports
# who signed each one.
function Assert-ArtifactSignature {
    param([Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)] $Config)
    & $Config.SignTool verify /pa /tw $Files | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signtool verify /pa failed (exit $LASTEXITCODE)" }
    foreach ($file in $Files) {
        $signature = Get-AuthenticodeSignature -FilePath $file
        if ($signature.Status -ne "Valid") {
            throw "$file signature status is $($signature.Status): $($signature.StatusMessage)"
        }
        if ($null -eq $signature.TimeStamperCertificate) {
            throw "$file is signed but not timestamped; it would stop validating when the 3-day certificate expires."
        }
        Write-Host ("[OK]   {0}: signed by {1}, timestamped" -f (Split-Path -Leaf $file),
            $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)) -ForegroundColor Green
    }
}

# Signs files (any mix of .dll, .exe, .msi) through Artifact Signing, then
# verifies them.
function Invoke-ArtifactSigning {
    param([Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)] $Config)
    foreach ($file in $Files) {
        if (-not (Test-Path $file)) { throw "file to sign not found: $file" }
    }
    Write-Host "Signing $($Files.Count) file(s)..."
    & $Config.SignTool sign /v /fd SHA256 /tr $script:ArtifactSigningTimestampUrl /td SHA256 `
        /dlib $Config.Dlib /dmdf $Config.Metadata.Path $Files
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed (exit $LASTEXITCODE). A 403 usually means the metadata Endpoint doesn't match the account's region, or the signing identity lacks the Certificate Profile Signer role. Re-run signtool with /debug for details."
    }
    Assert-ArtifactSignature -Files $Files -Config $Config
}
