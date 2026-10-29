<#
.SYNOPSIS
    hkdfguard.exe's provision, status and retire for payload version 2 KEKs.

.DESCRIPTION
    test_cli.ps1 covers the CLI thoroughly under payload version 1 (it pins
    ClassicalMode to 1). This covers what version 2 adds: provision, status
    and retire of a version 2 KEK on the software key store and - when this
    machine's TPM can do version 2 - the TPM; retire's refusals (a valid KEK
    as --corrupt, a wrong fingerprint, the other version); a corrupted TPM
    key file found by status and removed by retire --corrupt; and a version 1
    KEK shown as the other version, retired with --version 1.

    Needs elevation (it provisions machine keys and sets ClassicalMode and
    KeyStoragePolicy, restored afterwards); skipped otherwise. Exit code 0
    means every check passed.
#>
param(
    [Parameter(Mandatory = $true)][string]$CliExePath
)

$ErrorActionPreference = "Stop"
$failures = 0
function Check([bool]$Condition, [string]$What) {
    if ($Condition) { Write-Host "[PASS] $What" } else { Write-Host "[FAIL] $What"; $script:failures++ }
}

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[SKIP] version 2 CLI checks: not elevated (they provision machine keys)"
    exit 0
}

function Run-Cli([string[]]$Arguments) {
    # Not "Stop" here: in Windows PowerShell a native command's stderr - every
    # refusal checked below writes there - would become a terminating error.
    $ErrorActionPreference = "Continue"
    $output = & $CliExePath @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Out = $output }
}

$policyKey = "HKLM:\Software\Policies\HkdfGuard"
$saved = @{}
foreach ($name in "ClassicalMode", "KeyStoragePolicy") {
    try { $saved[$name] = (Get-ItemProperty -Path $policyKey -Name $name -ErrorAction Stop).$name } catch { $saved[$name] = $null }
}
function Set-Policy([string]$Name, [int]$Value) {
    if (-not (Test-Path $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
    Set-ItemProperty -Path $policyKey -Name $Name -Type DWord -Value $Value
}

$tag = [Guid]::NewGuid().ToString("N").Substring(0, 6)
$services = @()

try {
    Set-Policy ClassicalMode 0

    # ---- Each provider in turn: the whole lifecycle. ----
    foreach ($case in @(@{ Policy = 2; Flag = "software"; Label = "Software Key Storage Provider" },
                        @{ Policy = 1; Flag = "tpm"; Label = "TPM" })) {
        Set-Policy KeyStoragePolicy $case.Policy
        $service = "hkdfguardcliv2$($case.Flag)$tag"
        $services += $service
        $prefix = "$($case.Flag):"

        $r = Run-Cli @("provision", "-sn", $service)
        if ($case.Flag -eq "tpm" -and $r.ExitCode -ne 0 -and $r.Out -match "version 2 is unavailable") {
            Write-Host "[SKIP] $prefix this machine's TPM can't do payload version 2: $($r.Out.Trim())"
            continue
        }
        $fp = $null
        if ($r.Out -match "fingerprint: ([0-9a-f]{64})") { $fp = $Matches[1] }
        Check (($r.ExitCode -eq 0) -and $fp -and ($r.Out -match "record this") -and ($r.Out -match "payload version: 2")) "$prefix provision creates a version 2 KEK and prints its fingerprint and version"
        if ($r.ExitCode -ne 0) { Write-Host "    $($r.Out)" }

        $r = Run-Cli @("provision", "-sn", $service)
        Check (($r.ExitCode -eq 0) -and ($r.Out -match "fingerprint: $fp") -and ($r.Out -match "confirm it matches")) "$prefix provision again verifies the same KEK"

        $r = Run-Cli @("status", "-sn", $service)
        Check (($r.ExitCode -eq 0) -and ($r.Out -match "payload version: 2") -and ($r.Out -match "kek: present") -and
               ($r.Out -match "provider: .*$($case.Label)") -and ($r.Out -match "fingerprint: $fp")) "$prefix status: version 2, present, on the expected provider, with its fingerprint"
        if ($r.Out -notmatch "kek: present") { Write-Host "    $($r.Out)" }

        $r = Run-Cli @("retire", "-sn", $service, "--corrupt")
        Check (($r.ExitCode -eq 1) -and ($r.Out -match "is a valid KEK")) "$prefix retire --corrupt refuses a valid KEK"
        $wrong = "00" * 32
        $r = Run-Cli @("retire", "-sn", $service, "-fp", $wrong)
        Check (($r.ExitCode -eq 1) -and ($r.Out -match "fingerprint mismatch")) "$prefix retire refuses a wrong fingerprint"
        $r = Run-Cli @("retire", "-sn", $service, "-fp", $fp, "--version", "1")
        Check (($r.ExitCode -eq 1) -and ($r.Out -match "no KEK exists")) "$prefix retire --version 1 doesn't touch the version 2 KEK"
        $r = Run-Cli @("status", "-sn", $service)
        Check ($r.Out -match "kek: present") "$prefix ...which is still there after all three refusals"

        $r = Run-Cli @("retire", "-sn", $service, "-fp", $fp)
        Check (($r.ExitCode -eq 0) -and ($r.Out -match "retired KEK") -and ($r.Out -match "payload version 2")) "$prefix retire with its fingerprint deletes it"
        if ($r.ExitCode -ne 0) { Write-Host "    $($r.Out)" }
        $r = Run-Cli @("status", "-sn", $service)
        Check (($r.ExitCode -eq 0) -and ($r.Out -match "kek: absent")) "$prefix status: absent after retire"

        if ($case.Flag -eq "tpm") {
            # ---- A corrupted TPM key file: found, and removed by --corrupt. ----
            $r = Run-Cli @("provision", "-sn", $service)
            $keyFile = Join-Path $env:ProgramData "HkdfGuard\TpmKeys\hkdfguardwin_$($service)_v1.tpmkey"
            Check (($r.ExitCode -eq 0) -and (Test-Path -LiteralPath $keyFile)) "tpm: a fresh KEK's key file is in the ProgramData store"
            $bytes = [System.IO.File]::ReadAllBytes($keyFile)
            $bytes[0] = $bytes[0] -bxor 0x01
            [System.IO.File]::WriteAllBytes($keyFile, $bytes)
            $r = Run-Cli @("status", "-sn", $service)
            Check (($r.ExitCode -eq 0) -and ($r.Out -match "kek: corrupt") -and ($r.Out -match "tpm: invalid")) "tpm: status reports a corrupted key file as corrupt"
            if ($r.Out -notmatch "kek: corrupt") { Write-Host "    $($r.Out)" }
            $r = Run-Cli @("retire", "-sn", $service, "-fp", $wrong)
            Check (($r.ExitCode -eq 1) -and ($r.Out -match "fails its KEK checks")) "tpm: retire by fingerprint refuses it (it has no fingerprint)"
            $r = Run-Cli @("retire", "-sn", $service, "--corrupt")
            Check (($r.ExitCode -eq 0) -and -not (Test-Path -LiteralPath $keyFile)) "tpm: retire --corrupt removes the corrupted key file"
        }
    }

    # ---- A version 1 KEK beside a version 2 host: shown, and retired with --version 1. ----
    Set-Policy KeyStoragePolicy 2
    $service = "hkdfguardcliv2v1$tag"
    $services += $service
    Set-Policy ClassicalMode 1
    $r = Run-Cli @("provision", "-sn", $service)
    $v1fp = $null
    if ($r.Out -match "fingerprint: ([0-9a-f]{64})") { $v1fp = $Matches[1] }
    Check (($r.ExitCode -eq 0) -and $v1fp -and ($r.Out -match "payload version: 1")) "ClassicalMode 1: provision creates a version 1 KEK"
    Set-Policy ClassicalMode 0
    $r = Run-Cli @("status", "-sn", $service)
    Check (($r.Out -match "kek: absent") -and ($r.Out -match "payload version 1, unused") -and ($r.Out -match $v1fp)) "ClassicalMode 0: status shows no version 2 KEK, and the version 1 KEK as unused"
    if ($r.Out -notmatch "payload version 1, unused") { Write-Host "    $($r.Out)" }
    $r = Run-Cli @("retire", "-sn", $service, "-fp", $v1fp)
    Check (($r.ExitCode -eq 1) -and ($r.Out -match "no payload version 2 KEK")) "retire without --version looks for this host's version (2) only"
    $r = Run-Cli @("retire", "-sn", $service, "-fp", $v1fp, "--version", "1")
    Check ($r.ExitCode -eq 0) "retire --version 1 retires the version 1 KEK"
    $r = Run-Cli @("status", "-sn", $service)
    Check (($r.Out -match "kek: absent") -and ($r.Out -notmatch "payload version 1, unused")) "...and status shows nothing left"
}
catch {
    Check $false "version 2 CLI checks: $($_.Exception.Message)"
}
finally {
    $ErrorActionPreference = "Continue"
    # Anything left behind, of either version, by fingerprint where it can be read.
    foreach ($service in $services) {
        foreach ($version in "2", "1") {
            Set-Policy ClassicalMode ([int]($version -eq "1"))
            $st = & $CliExePath status -sn $service 2>&1 | Out-String
            foreach ($m in [regex]::Matches($st, "(tpm|software): fingerprint ([0-9a-f]{64})")) {
                & $CliExePath retire -sn $service -fp $m.Groups[2].Value --provider $m.Groups[1].Value --version $version 2>&1 | Out-Null
            }
            if ($st -match "fingerprint: ([0-9a-f]{64})") {
                & $CliExePath retire -sn $service -fp $Matches[1] --version $version 2>&1 | Out-Null
            }
        }
    }
    foreach ($name in "ClassicalMode", "KeyStoragePolicy") {
        if ($null -eq $saved[$name]) {
            Remove-ItemProperty -Path $policyKey -Name $name -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $policyKey -Name $name -Type DWord -Value $saved[$name]
        }
    }
}

if ($failures -eq 0) { Write-Host "`nAll checks passed."; exit 0 }
Write-Host "`n$failures check(s) failed."
exit 1
