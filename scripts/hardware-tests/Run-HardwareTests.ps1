<#
.SYNOPSIS
    Runs the provider probe and the HkdfGuard test suites on the machine being
    qualified, from the folder New-HardwareTestBundle.ps1 made, the same way
    ctest runs them on a development machine.

.DESCRIPTION
    Must run elevated, at the machine's own console - not over PowerShell
    remoting or PowerShell Direct, where the processes test_roles.ps1 starts
    as its test accounts have no desktop and die (README.md).

    Records the host - Windows build, and the TPM's manufacturer, firmware
    and spec version - then removes the host's ClassicalMode policy value
    (payload version 2, the default; the suites pin and restore it
    themselves) and runs, in order: v2_provider_probe, test_v2_kek,
    test_roundtrip, test_cli.ps1, test_cli_v2.ps1, test_harden_process and
    test_roles.ps1. Ends with a summary and every [SKIP] line.

    Writes the whole run to hardware-tests-<computer name>.log next to
    itself. Exits 1 if any suite failed.
#>
$ErrorActionPreference = "Continue"
$here = $PSScriptRoot
$log = Join-Path $here "hardware-tests-$env:COMPUTERNAME.log"
$env:PATH = "$here;$env:PATH"
Start-Transcript -LiteralPath $log -Force | Out-Null

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not elevated: the TPM and KEK tests would all be skipped. Rerun as administrator."
    Stop-Transcript | Out-Null
    exit 1
}

if ($PSSenderInfo) {
    Write-Host "[WARN] running in a remote session: expect 'roles' to fail for that reason alone. Run this from the machine's console for a real roles result." -ForegroundColor Yellow
}

# What this host is, for the record.
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "== Host: $($os.Caption) build $($os.BuildNumber).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)"
try {
    Get-Tpm | Format-List TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManufacturerIdTxt, ManufacturerVersion | Out-Host
} catch { Write-Host "Get-Tpm failed: $($_.Exception.Message)" }
tpmtool getdeviceinformation | Out-Host

$policyKey = "HKLM:\Software\Policies\HkdfGuard"
if ((Test-Path $policyKey) -and ((Get-Item $policyKey).GetValueNames() -contains "ClassicalMode")) {
    Remove-ItemProperty -Path $policyKey -Name ClassicalMode
    Write-Host "removed ClassicalMode from $policyKey"
}

$ps = @("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File")
$tests = [ordered]@{
    provider_probe  = @("$here\v2_provider_probe.exe")
    v2_kek          = @("$here\test_v2_kek.exe")
    roundtrip       = @("$here\test_roundtrip.exe")
    cli             = $ps + @("$here\test_cli.ps1", "-CliExePath", "$here\hkdfguard.exe")
    cli_v2          = $ps + @("$here\test_cli_v2.ps1", "-CliExePath", "$here\hkdfguard.exe")
    harden_process  = @("$here\test_harden_process.exe")
    roles           = $ps + @("$here\test_roles.ps1", "-CliExePath", "$here\hkdfguard.exe",
                              "-ProbeExePath", "$here\role_probe.exe", "-DllPath", "$here\HkdfGuard.dll")
}

$results = [ordered]@{}
foreach ($name in $tests.Keys) {
    $cmd = $tests[$name]
    Write-Host "`n== $name"
    if ($cmd.Count -gt 1) { & $cmd[0] $cmd[1..($cmd.Count - 1)] 2>&1 | Out-Host } else { & $cmd[0] 2>&1 | Out-Host }
    $code = $LASTEXITCODE
    $results[$name] = if ($code -eq 0) { "passed" } elseif ($name -eq "harden_process" -and $code -eq 77) { "skipped (SYSTEM)" } else { "FAILED (exit $code)" }
}

Write-Host "`n== Summary"
foreach ($name in $results.Keys) { Write-Host ("{0,-16} {1}" -f $name, $results[$name]) }
$skips = Select-String -LiteralPath $log -Pattern "\[SKIP\]"
if ($skips) {
    Write-Host "`nSkipped checks (any TPM one means the TPM was not qualified):"
    $skips | ForEach-Object { Write-Host "  $($_.Line.Trim())" }
}
Stop-Transcript | Out-Null
Write-Host "Log written to $log"
if ($results.Values | Where-Object { $_ -like "FAILED*" }) { exit 1 }
