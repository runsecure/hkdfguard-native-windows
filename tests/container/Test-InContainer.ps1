<#
.SYNOPSIS
    Runs inside a clean Windows Server container: installs the MSI, runs the
    test suites against the INSTALLED binaries, then uninstalls. Started by
    scripts\Test-Containers.ps1 - not meant to be run on a developer machine
    (it installs and uninstalls the product machine-wide).

.DESCRIPTION
    What a fresh server deployment would actually go through:
      1. msiexec /i the MSI; check the files, the InstallPath value, the event
         log source registration and the HkdfGuardUsers group it creates.
      2. Run test_roundtrip.exe with only the installed folder on the DLL
         search path, so it exercises the installed HkdfGuardV1.dll.
      3. Run tests\test_cli.ps1 against the installed CLI.
      4. Check the audit events render through the registered event source.
      5. msiexec /x; check the files and InstallPath are gone and the
         HkdfGuardUsers group is kept, as documented.

    Containers have no TPM, so every KEK lands on the Software Key Storage
    Provider - the same as a VM or server without a vTPM.

.PARAMETER Payload
    Read-only folder holding the MSI, test_roundtrip.exe and test_cli.ps1.

.PARAMETER Out
    Writable folder for logs (install/uninstall logs, test output).
#>
param(
    [string]$Payload = "C:\payload",
    [string]$Out = "C:\out"
)

$ErrorActionPreference = "Stop"
$failures = 0
function Write-Section($title) { Write-Host ""; Write-Host "==== $title ====" -ForegroundColor Cyan }
function Check($condition, $what) {
    if ($condition) { Write-Host "[PASS] $what" -ForegroundColor Green }
    else { Write-Host "[FAIL] $what" -ForegroundColor Red; $script:failures++ }
}

$InstallDir = Join-Path $env:ProgramFiles "HkdfGuard\v1"
$InstallKey = "HKLM:\Software\hkdfguard-native-windows"
$EventSourceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\hkdfguard-native-windows"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Write-Section "Container"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS:       $($os.Caption) (build $($os.BuildNumber))"
Write-Host "User:     $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Elevated: $elevated"
Check $elevated "running elevated (needed to install and to create machine-wide KEKs)"

$msi = @(Get-ChildItem -Path $Payload -Filter *.msi)
if ($msi.Count -ne 1) { throw "expected exactly one .msi in $Payload, found $($msi.Count)" }
$msi = $msi[0].FullName

# ---- 1. Install --------------------------------------------------------------
Write-Section "Installing $(Split-Path -Leaf $msi)"
$proc = Start-Process msiexec.exe -ArgumentList @("/i", "`"$msi`"", "/qn", "/norestart", "/l*v", "`"$Out\install.log`"") -Wait -PassThru
Check ($proc.ExitCode -eq 0) "msiexec /i exits 0 (got $($proc.ExitCode))"

foreach ($f in "HkdfGuardV1.dll", "hkdfguard-v1-initialize.exe") {
    Check (Test-Path (Join-Path $InstallDir $f)) "installed $InstallDir\$f"
}
$installPath = (Get-ItemProperty -Path $InstallKey -Name InstallPath -ErrorAction SilentlyContinue).InstallPath
Check ($installPath -and ($installPath.TrimEnd('\') -eq $InstallDir)) "InstallPath registry value points at $InstallDir (got '$installPath')"
$msgFile = (Get-ItemProperty -Path $EventSourceKey -Name EventMessageFile -ErrorAction SilentlyContinue).EventMessageFile
Check ($msgFile -and ([Environment]::ExpandEnvironmentVariables($msgFile) -eq (Join-Path $InstallDir "HkdfGuardV1.dll"))) "event source registered with the installed DLL as its message file"
& net.exe localgroup HkdfGuardUsers *> $null
Check ($LASTEXITCODE -eq 0) "local group HkdfGuardUsers exists"

$testStart = Get-Date

# ---- 2. test_roundtrip against the installed DLL -------------------------------
# Copied to its own folder with no DLL beside it, and only the install folder
# added to PATH, so the loader can only find the installed HkdfGuardV1.dll.
Write-Section "test_roundtrip.exe (installed DLL)"
$work = "C:\work"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item (Join-Path $Payload "test_roundtrip.exe") $work -Force
$savedPath = $env:PATH
$env:PATH = "$InstallDir;$env:PATH"
try {
    & (Join-Path $work "test_roundtrip.exe") 2>&1 | Tee-Object -FilePath "$Out\test_roundtrip.log" | Out-Host
    $roundtripExit = $LASTEXITCODE
} finally {
    $env:PATH = $savedPath
}
$roundtripFails = @(Select-String -Path "$Out\test_roundtrip.log" -Pattern '^\[FAIL\] (.*)$' | ForEach-Object { $_.Matches[0].Groups[1].Value })
foreach ($f in $roundtripFails) { Write-Host "  failed check: $f" -ForegroundColor Red }
Check ($roundtripExit -eq 0) "test_roundtrip.exe exits 0 (got $roundtripExit, $($roundtripFails.Count) failed check(s))"

# ---- 3. test_cli.ps1 against the installed CLI ----------------------------------
Write-Section "test_cli.ps1 (installed CLI)"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Payload "test_cli.ps1") `
    -CliExePath (Join-Path $InstallDir "hkdfguard-v1-initialize.exe") 2>&1 |
    Tee-Object -FilePath "$Out\test_cli.log" | Out-Host
$cliExit = $LASTEXITCODE
Check ($cliExit -eq 0) "test_cli.ps1 exits 0 (got $cliExit)"

# ---- 3b. Installed CLI wrap -> installed DLL open_file -> unwrap ----------------
# The consumer's path end to end: the installed CLI writes a wrapped-key
# file, and code loading the installed DLL by full path reads it back with
# hkdfguard_open_file (still wrapped) and unwraps it in a separate call.
Write-Section "CLI wrap -> hkdfguard_open_file -> hkdfguard_unwrap_dek (installed binaries)"
$cli = Join-Path $InstallDir "hkdfguard-v1-initialize.exe"
$dll = Join-Path $InstallDir "HkdfGuardV1.dll"
$chainService = "hkdfguardcontainerchain"
$keyFile = Join-Path $work "chain.key"
& $cli provision --service-name $chainService *> "$Out\chain-provision.log"
Check ($LASTEXITCODE -eq 0) "installed CLI provisions a KEK"
$dek = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dek)
[Convert]::ToBase64String($dek) | & $cli wrap --key-file-path $keyFile --service-name $chainService `
    --dek-stdin --group Administrators --force *> "$Out\chain-wrap.log"
Check ($LASTEXITCODE -eq 0) "installed CLI wraps a DEK to a file"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class InstalledHkdfGuard {
    [DllImport(@"$dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int hkdfguard_open_file(byte[] path, byte[] out_buf, ref int out_len);
    [DllImport(@"$dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int hkdfguard_unwrap_dek(
        [MarshalAs(UnmanagedType.LPStr)] string service, byte[] wrapped, int wrapped_len, byte[] out_buf, ref int out_len);
}
"@
function Open-WrappedFile([string]$path) {
    $buf = New-Object byte[] 164
    $len = 164
    $rc = [InstalledHkdfGuard]::hkdfguard_open_file([Text.Encoding]::UTF8.GetBytes($path + [char]0), $buf, [ref]$len)
    return [PSCustomObject]@{ Rc = $rc; Len = $len; Bytes = $buf }
}

$opened = Open-WrappedFile $keyFile
$onDisk = [IO.File]::ReadAllBytes($keyFile)
Check ($opened.Rc -eq 0 -and $opened.Len -eq 164) "hkdfguard_open_file reads the CLI's file (rc $($opened.Rc), $($opened.Len) bytes)"
Check ([Convert]::ToBase64String($opened.Bytes) -eq [Convert]::ToBase64String($onDisk)) "hkdfguard_open_file returns the file's wrapped bytes unchanged"
$plain = New-Object byte[] 32
$plainLen = 32
$rc = [InstalledHkdfGuard]::hkdfguard_unwrap_dek($chainService, $opened.Bytes, $opened.Len, $plain, [ref]$plainLen)
Check ($rc -eq 0 -and [Convert]::ToBase64String($plain) -eq [Convert]::ToBase64String($dek)) "a separate hkdfguard_unwrap_dek call recovers the original DEK"
[Array]::Clear($plain, 0, $plain.Length)
[Array]::Clear($dek, 0, $dek.Length)

# A 32-byte file - the size of a plaintext DEK - is flagged, not read.
$plainFile = Join-Path $work "plain.key"
[IO.File]::WriteAllBytes($plainFile, (New-Object byte[] 32))
$opened = Open-WrappedFile $plainFile
Check ($opened.Rc -eq -20 -and $opened.Len -eq 0) "hkdfguard_open_file reports a 32-byte file as HKDFGUARD_ERR_FILE_PLAINTEXT_KEY (rc $($opened.Rc))"

Remove-Item -Force $keyFile, $plainFile -ErrorAction SilentlyContinue

# ---- 4. Audit events render through the registered source -------------------------
Write-Section "Event log"
$events = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; ProviderName = "hkdfguard-native-windows"; StartTime = $testStart } -ErrorAction SilentlyContinue)
Write-Host "events written during the tests: $($events.Count)"
Check (@($events | Where-Object Id -eq 1000).Count -gt 0) "KEK-created events (1000) were logged"
Check (@($events | Where-Object Id -eq 1002).Count -gt 0) "DEK-wrapped events (1002) were logged"
$unrendered = @($events | Where-Object { [string]::IsNullOrEmpty($_.Message) })
Check ($events.Count -gt 0 -and $unrendered.Count -eq 0) "every event's message renders through the installed message table"

# ---- 5. Uninstall ----------------------------------------------------------------
Write-Section "Uninstalling"
$proc = Start-Process msiexec.exe -ArgumentList @("/x", "`"$msi`"", "/qn", "/norestart", "/l*v", "`"$Out\uninstall.log`"") -Wait -PassThru
Check ($proc.ExitCode -eq 0) "msiexec /x exits 0 (got $($proc.ExitCode))"
Check (-not (Test-Path (Join-Path $InstallDir "HkdfGuardV1.dll"))) "installed DLL removed"
Check (-not (Test-Path (Join-Path $InstallDir "hkdfguard-v1-initialize.exe"))) "installed CLI removed"
$afterInstallPath = (Get-ItemProperty -Path $InstallKey -Name InstallPath -ErrorAction SilentlyContinue).InstallPath
Check (-not $afterInstallPath) "InstallPath registry value removed"
Check (-not (Test-Path $EventSourceKey)) "event source registration removed"
& net.exe localgroup HkdfGuardUsers *> $null
Check ($LASTEXITCODE -eq 0) "HkdfGuardUsers group kept after uninstall (by design)"

Write-Section "Summary"
if ($failures -gt 0) {
    Write-Host "$failures check(s) failed on $($os.Caption) (build $($os.BuildNumber))." -ForegroundColor Red
    exit 1
}
Write-Host "All checks passed on $($os.Caption) (build $($os.BuildNumber))." -ForegroundColor Green
exit 0
