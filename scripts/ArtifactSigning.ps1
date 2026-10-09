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
      - The Artifact Signing client tools (winget install -e --id
        Microsoft.Azure.ArtifactSigningClientTools), which install the x64
        plugin under %LOCALAPPDATA%\Microsoft\MicrosoftArtifactSigningClientTools.
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

# The x64 Artifact Signing plugin (Azure.CodeSigning.Dlib.dll). Must match
# signtool's architecture, which is x64 here.
function Get-ArtifactSigningDlib {
    param([string]$Path)
    if (-not $Path) { $Path = $env:HKDFGUARD_SIGNING_DLIB }
    if (-not $Path) { $Path = Join-Path $env:LOCALAPPDATA "Microsoft\MicrosoftArtifactSigningClientTools\Azure.CodeSigning.Dlib.dll" }
    if (-not (Test-Path $Path)) {
        throw "Artifact Signing plugin not found at $Path. Install the client tools: winget install -e --id Microsoft.Azure.ArtifactSigningClientTools"
    }
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
