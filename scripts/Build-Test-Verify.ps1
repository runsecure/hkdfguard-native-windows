<#
.SYNOPSIS
    Configures, builds, tests, and does an end-to-end CLI+DLL verification
    of hkdfguard-native-windows.

.DESCRIPTION
    1. Enters the Visual Studio Build Tools developer environment with the
       native toolchain for this process's architecture (x64 or ARM64),
       since everything built here is also run here.
    2. Configures and builds the project (cmake -G Ninja).
    3. Runs the project's ctest suite (roundtrip).
    4. Wraps a random 32-byte DEK with the CLI (tools/hkdfguard.exe), then
       reads and unwraps the resulting file through HkdfGuard.dll's public
       hkdfguard_open_file and hkdfguard_unwrap_dek via P/Invoke and checks
       the recovered bytes match - so the CLI's output is proven unwrappable
       by the DLL, not just by the CLI.

    Must be run elevated: creating the machine-wide KEK
    (NCRYPT_MACHINE_KEY_FLAG) on first use requires Administrator rights.
    Use run-build-test-verify.bat alongside this script to auto-elevate.

.PARAMETER Configuration
    CMake build configuration (Debug or Release). Default: Debug.

.PARAMETER Group
    Local or domain group name passed to the CLI's --group flag (read-only
    ACE on the wrapped-key file). Must not be an over-broad group such as
    Users or Everyone, which the CLI refuses. Default: Administrators.

.PARAMETER NoCleanup
    Skip deleting the verification KEK and wrapped-key file afterward. Without
    it, the KEK is retired with the CLI just built (status for the fingerprint,
    then retire --fingerprint), which is checked like every other step: the
    service must then be absent and the retirement logged as event 1004.
#>
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$Group = "Administrators",
    [switch]$NoCleanup
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$FailureCount = 0
function Write-Section($title) {
    Write-Host ""
    Write-Host "==== $title ====" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Bad($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:FailureCount++ }

# ---- Elevation check --------------------------------------------------
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must run elevated (Administrator) - the machine-wide KEK" -ForegroundColor Red
    Write-Host "cannot be created otherwise. Re-run from an elevated shell, or use" -ForegroundColor Red
    Write-Host "run-build-test-verify.bat, which elevates automatically." -ForegroundColor Red
    exit 1
}

# ---- Run in a child process --------------------------------------------
# The end-to-end check below loads build\HkdfGuard.dll into this process
# through Add-Type/[DllImport], and it stays loaded until the process exits.
# In the caller's own window, a second run would then fail to relink the DLL
# (LNK1168) and to Add-Type HkdfGuardNative again. So the work runs in a
# child of the same PowerShell executable (same edition, architecture and
# elevated token), which exits when it's done.
if ($env:HKDFGUARD_BTV_CHILD -ne "1") {
    $childArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Configuration", $Configuration, "-Group", $Group)
    if ($NoCleanup) { $childArgs += "-NoCleanup" }
    $env:HKDFGUARD_BTV_CHILD = "1"
    try {
        & (Get-Process -Id $PID).Path @childArgs
        $childExit = $LASTEXITCODE
    } finally {
        Remove-Item Env:HKDFGUARD_BTV_CHILD -ErrorAction SilentlyContinue
    }
    exit $childExit
}

# ---- Locate and enter the VS Build Tools developer environment --------
Write-Section "Locating MSVC / CMake / Ninja"
$installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$vswhere = Join-Path $installerDir "vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere - is Visual Studio / Build Tools installed?"
}
$env:PATH = "$env:PATH;$installerDir"

# Builds natively for the architecture of this PowerShell process: the tests
# run what was built, and the P/Invoke check loads HkdfGuard.dll into this
# process, which needs matching architectures. An x64 powershell.exe under
# emulation on ARM64 reports AMD64 and gets x64 binaries, which it can load.
$hostArchMap = @{ "AMD64" = "amd64"; "ARM64" = "arm64" }
$vsArch = $hostArchMap[$env:PROCESSOR_ARCHITECTURE]
if (-not $vsArch) { throw "Unsupported process architecture '$env:PROCESSOR_ARCHITECTURE' (expected AMD64 or ARM64)." }
$requiredComponent = if ($vsArch -eq "arm64") {
    "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
} else {
    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
}
$vsInstallPath = & $vswhere -latest -products * -requires $requiredComponent -property installationPath
if (-not $vsInstallPath) {
    throw "No Visual Studio / Build Tools install with the C++ $vsArch build tools component ($requiredComponent) was found."
}
Write-Host "Using VS install: $vsInstallPath (native $vsArch toolchain)"

$devShell = Join-Path $vsInstallPath "Common7\Tools\Launch-VsDevShell.ps1"
if (-not (Test-Path $devShell)) {
    throw "Launch-VsDevShell.ps1 not found under $vsInstallPath"
}
& $devShell -Arch $vsArch -HostArch $vsArch -SkipAutomaticLocation | Out-Null

foreach ($tool in "cl", "cmake", "ninja", "dumpbin") {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $found) { throw "$tool not found on PATH after entering the VS dev shell." }
}
Write-Ok "cl, cmake, ninja, dumpbin resolved"

# ---- Configure + build --------------------------------------------------
Write-Section "Configuring (cmake -G Ninja)"
# CMake refuses a cache generated for a different source directory (a moved
# or copied checkout), so such a cache is dropped and the folder configured
# afresh.
$cache = Join-Path $RepoRoot "build\CMakeCache.txt"
if (Test-Path -LiteralPath $cache) {
    $cacheSource = (Select-String -LiteralPath $cache -Pattern '^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$' |
        Select-Object -First 1).Matches.Groups[1].Value
    if ($cacheSource -and ([IO.Path]::GetFullPath($cacheSource).TrimEnd('\') -ne [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\'))) {
        Write-Host "build\ was configured for '$cacheSource'; removing its stale CMake cache." -ForegroundColor Yellow
        Remove-Item -LiteralPath $cache -Force
        Remove-Item -LiteralPath (Join-Path $RepoRoot "build\CMakeFiles") -Recurse -Force -ErrorAction SilentlyContinue
    }
}
cmake -S . -B build -G Ninja "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }
Write-Ok "configure succeeded"

Write-Section "Building"
cmake --build build --config $Configuration
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }
Write-Ok "build succeeded"

$dllPath = Join-Path $RepoRoot "build\HkdfGuard.dll"
$cliPath = Join-Path $RepoRoot "build\tools\hkdfguard.exe"
foreach ($p in $dllPath, $cliPath) {
    if (-not (Test-Path $p)) { throw "expected build output missing: $p" }
}

# What the linker actually targeted, so a CI leg can't report a pass for an
# architecture it never ran.
$expectedMachine = if ($vsArch -eq "arm64") { "ARM64" } else { "x64" }
foreach ($bin in $dllPath, $cliPath) {
    $machineLine = dumpbin /headers $bin | Select-String -Pattern "machine \("
    if ($machineLine -notmatch [regex]::Escape($expectedMachine)) {
        throw "$(Split-Path -Leaf $bin) was not built for $expectedMachine - dumpbin reports: $($machineLine.ToString().Trim())"
    }
    Write-Ok "$(Split-Path -Leaf $bin) is $expectedMachine, running natively"
}

# ---- ctest --------------------------------------------------------------
Write-Section "Running ctest (roundtrip)"
ctest --test-dir build -C $Configuration --output-on-failure
if ($LASTEXITCODE -eq 0) {
    Write-Ok "ctest: all tests passed"
} else {
    Write-Bad "ctest: one or more tests failed (exit $LASTEXITCODE) - see output above"
    # Lists every "[FAIL] <what>" line from ctest's full log in one place,
    # and under GitHub Actions raises each as an error annotation.
    $ctestLog = Join-Path $RepoRoot "build\Testing\Temporary\LastTest.log"
    if (Test-Path $ctestLog) {
        $failedChecks = @(Select-String -Path $ctestLog -Pattern '^\[FAIL\] (.*)$' |
            ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
        Write-Host "Failed checks reported by the tests ($($failedChecks.Count)):"
        foreach ($check in $failedChecks) {
            Write-Host "  [FAIL] $check" -ForegroundColor Red
            if ($env:GITHUB_ACTIONS -eq "true") {
                Write-Host "::error title=ctest check failed ($env:PROCESSOR_ARCHITECTURE)::$check"
            }
        }
    }
}

# ---- CLI provision + wrap + independent DLL unwrap verification ----------
Write-Section "CLI provision + wrap + DLL unwrap round-trip verification"

# The key file goes in an administrator-owned folder under C:\, the key
# folder layout docs/admin-guide.md describes. hkdfguard_open_file refuses a
# file when any folder above it is owned by, or below the drive root lets
# create, delete or replace entries, an account it doesn't trust - under the
# default production security model, everyone but SYSTEM, Administrators,
# TrustedInstaller and the deployer groups. That rules out %TEMP% (in the
# user's profile), a checkout under C:\a\... (Authenticated Users: Modify
# inherited from C:\) and C:\ProgramData.
$verifyDir = Join-Path $env:SystemDrive ("\hkdfguard-verify-" + [Guid]::NewGuid().ToString("N"))
$verifyDirInfo = New-Item -ItemType Directory -Force -Path $verifyDir
# The whole security descriptor is replaced in one step - owner
# Administrators, a protected DACL of exactly SYSTEM and Administrators full
# control and Users read - rather than edited with icacls, which can leave an
# Authenticated Users entry on a folder under C:\ (GitHub's hosted runners
# do). It is then read back and checked, so a difference fails here with the
# SDDL rather than in the wrap below. PowerShell 7 exposes the ACL calls as
# FileSystemAclExtensions, Windows PowerShell as DirectoryInfo methods. Only
# the owner and DACL sections are set: a whole SDDL would mark the SACL for
# writing too, which needs SeSecurityPrivilege.
$verifySddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
$verifySecurity = New-Object System.Security.AccessControl.DirectorySecurity
$verifySecurity.SetSecurityDescriptorSddlForm($verifySddl, [System.Security.AccessControl.AccessControlSections]::Access)
$verifySecurity.SetOwner((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")))
$aclExtensions = [Type]::GetType("System.IO.FileSystemAclExtensions, System.IO.FileSystem.AccessControl", $false)
if ($aclExtensions) {
    $aclExtensions::SetAccessControl($verifyDirInfo, $verifySecurity)
    $appliedSddl = $aclExtensions::GetAccessControl($verifyDirInfo).GetSecurityDescriptorSddlForm("Owner, Access")
} else {
    $verifyDirInfo.SetAccessControl($verifySecurity)
    $appliedSddl = $verifyDirInfo.GetAccessControl().GetSecurityDescriptorSddlForm("Owner, Access")
}
# Windows may normalize the flags it reads back (D:P as D:PAI), so the check
# is on what matters: owned by Administrators, protected, and every entry for
# SYSTEM, Administrators or Users.
$appliedAceSids = @([regex]::Matches($appliedSddl, '\(([^;]*;){5}([^)]*)\)') | ForEach-Object { $_.Groups[2].Value })
if ($appliedSddl -notmatch '^O:BAD:P' -or $appliedAceSids.Count -eq 0 -or
    @($appliedAceSids | Where-Object { $_ -notin 'SY', 'BA', 'BU' }).Count -gt 0) {
    throw "the verification key folder $verifyDir didn't get the intended permissions: wanted '$verifySddl', got '$appliedSddl'"
}
$keyFile = Join-Path $verifyDir "verify.key"
# Alphanumeric only - hkdfguard.exe's ValidateServiceCharset
# rejects anything else (including hyphens) in --service-name.
$serviceName = "hkdfguardverifyscript"
$service = $serviceName

# 32 cryptographically random bytes, base64-encoded for "wrap --dek-stdin".
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$dekBytes = New-Object byte[] 32
$rng.GetBytes($dekBytes)
$dekBase64 = [Convert]::ToBase64String($dekBytes)
# Start of this verification's window in the Application event log (a
# couple of seconds early, to absorb clock granularity).
$auditStart = (Get-Date).AddSeconds(-2)

if (Test-Path $keyFile) { Remove-Item -Force $keyFile }

# hkdfguard.exe (build\tools\) needs HkdfGuard.dll (build\), so the DLL's
# directory goes on PATH for the calls below, as tests/CMakeLists.txt does
# for ctest.
$dllDir = Split-Path -Parent $dllPath
$oldPath = $env:PATH
$env:PATH = "$dllDir;$env:PATH"
try {
    Write-Host "Provisioning the KEK for service '$service'..."
    & $cliPath provision --service-name $serviceName
    $provisionExit = $LASTEXITCODE
    if ($provisionExit -ne 0) {
        Write-Bad "hkdfguard.exe provision exited $provisionExit"
    } else {
        Write-Ok "KEK provisioned for service '$service'"
    }

    if ($provisionExit -eq 0) {
        Write-Host "Wrapping a random 32-byte DEK via the CLI (service '$service')..."
        # The DEK is fed to "wrap" as base64 text on stdin (--dek-stdin), not
        # as a command-line argument - see hkdfguard_cli.cpp's
        # header comment on why.
        $dekBase64 | & $cliPath wrap --key-file-path $keyFile --service-name $serviceName `
            --dek-stdin --group $Group --force
        $cliExit = $LASTEXITCODE
    } else {
        $cliExit = $provisionExit
    }
} finally {
    $env:PATH = $oldPath
}
if ($provisionExit -eq 0) {
    if ($cliExit -ne 0) {
        Write-Bad "hkdfguard.exe wrap exited $cliExit"
    } else {
        Write-Ok "CLI wrapped the DEK to $keyFile"
    }
}

if ($cliExit -eq 0) {
    $wrapped = [System.IO.File]::ReadAllBytes($keyFile)
    if ($wrapped.Length -ne 132) {
        Write-Bad "wrapped file is $($wrapped.Length) bytes, expected 132"
    } else {
        Write-Ok "wrapped file is the expected 132 bytes"
    }

    $providerType = $wrapped[1]
    $providerName = switch ($providerType) {
        1 { "Microsoft Platform Crypto Provider" }
        2 { "Microsoft Software Key Storage Provider" }
        default { $null }
    }
    if ($providerName) {
        Write-Ok "KEK provider: $providerName (provider_type=$providerType)"
    } else {
        Write-Bad "unrecognized provider_type byte: $providerType"
    }

    # P/Invoke into the exact HkdfGuard.dll the CLI just used, loaded
    # dynamically the way an external consumer (see README.md) loads it.
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class HkdfGuardNative {
    [DllImport(@"$dllPath", CallingConvention = CallingConvention.Cdecl)]
    public static extern int hkdfguard_unwrap_dek(
        [MarshalAs(UnmanagedType.LPStr)] string service,
        byte[] wrapped, int wrapped_len,
        byte[] out_buf, ref int out_len);

    // path is passed as null-terminated UTF-8 bytes: UnmanagedType.LPUTF8Str
    // isn't available to Windows PowerShell 5.1 on every .NET Framework.
    [DllImport(@"$dllPath", CallingConvention = CallingConvention.Cdecl)]
    public static extern int hkdfguard_open_file(
        byte[] path,
        byte[] out_buf, ref int out_len);
}
"@

    # Read the CLI's file back through the DLL's own hkdfguard_open_file, the
    # way a consumer would, and unwrap *those* bytes: CLI wrap -> file ->
    # open_file -> unwrap, end to end.
    $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($keyFile + [char]0)
    $fromFile = New-Object byte[] 132
    $fromFileLen = 132
    $rc = [HkdfGuardNative]::hkdfguard_open_file($pathBytes, $fromFile, [ref]$fromFileLen)
    if ($rc -ne 0) {
        Write-Bad "hkdfguard_open_file returned status $rc (expected 0/HKDFGUARD_OK)"
    } elseif ($fromFileLen -ne 132) {
        Write-Bad "hkdfguard_open_file reported $fromFileLen bytes, expected 132"
    } elseif ([Convert]::ToBase64String($fromFile) -ne [Convert]::ToBase64String($wrapped)) {
        Write-Bad "hkdfguard_open_file returned different bytes than the file holds"
    } else {
        Write-Ok "hkdfguard_open_file read the CLI's wrapped file: 132 bytes, still wrapped, identical to the file"
    }

    $outBuf = New-Object byte[] 32
    $outLen = 32
    $rc = [HkdfGuardNative]::hkdfguard_unwrap_dek($service, $fromFile, $fromFileLen, $outBuf, [ref]$outLen)

    if ($rc -ne 0) {
        Write-Bad "hkdfguard_unwrap_dek returned status $rc (expected 0/HKDFGUARD_OK)"
    } elseif ($outLen -ne 32) {
        Write-Bad "hkdfguard_unwrap_dek reported out_len=$outLen, expected 32"
    } else {
        $recoveredBase64 = [Convert]::ToBase64String($outBuf)
        if ($recoveredBase64 -eq $dekBase64) {
            Write-Ok "unwrapped DEK matches the original 32-byte DEK exactly"
        } else {
            Write-Bad "unwrapped DEK does NOT match the original DEK"
        }
    }

    [Array]::Clear($outBuf, 0, $outBuf.Length)

    # ---- Audit trail: the CLI's wrap and this script's unwrap of the ----
    #      same payload should each be in the Application event log, under
    #      this account, carrying the same payload SHA-256 - which is what
    #      lets an operator tie every unwrap back to the wrap that produced
    #      it. XPath, not -FilterHashtable, so this works whether or not the
    #      MSI has registered the event source on this machine.
    $payloadHash = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($wrapped) |
        ForEach-Object { $_.ToString("x2") })
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sinceUtc = $auditStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    foreach ($check in @(@{ Id = 1002; What = "wrap" }, @{ Id = 1003; What = "unwrap" })) {
        $xpath = "*[System[Provider[@Name='hkdfguard-native-windows'] and EventID=$($check.Id) and TimeCreated[@SystemTime>='$sinceUtc']]]"
        $events = @()
        try { $events = @(Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction Stop) } catch { }
        $match = @($events | Where-Object {
            ([string]$_.Properties[0].Value).Contains($payloadHash) -and
            ([string]$_.Properties[0].Value).Contains("'$service'") -and
            $_.UserId.Value -eq $me })
        if ($match.Count -ge 1) {
            Write-Ok "$($check.What) recorded in the event log (event $($check.Id)) with this payload's SHA-256 and this account"
        } else {
            Write-Bad "no $($check.What) event $($check.Id) found for service '$service' with payload SHA-256 $payloadHash"
        }
    }
}

[Array]::Clear($dekBytes, 0, $dekBytes.Length)
$dekBase64 = $null

# ---- Cleanup --------------------------------------------------------------
if (-not $NoCleanup) {
    Write-Section "Cleanup"
    if (Test-Path $keyFile) {
        Remove-Item -Force $keyFile
        Write-Host "removed $keyFile"
    }
    if (Test-Path $verifyDir) {
        Remove-Item -Recurse -Force $verifyDir
    }
    if ($provisionExit -eq 0) {
        # Retire the verification KEK with the CLI this run built - the only
        # supported way to delete a KEK - which also verifies `status` and
        # `retire` end to end: status reports the fingerprint, retire deletes
        # only the key carrying it, logs event 1004, and status then reports
        # the service absent. Runs whenever provision succeeded, so a failed
        # wrap or unwrap doesn't leave the key behind either.
        $env:PATH = "$dllDir;$env:PATH"
        try {
            $statusOutput = @(& $cliPath status --service-name $serviceName 2>&1 | ForEach-Object { "$_" })
            $fingerprint = ($statusOutput | Where-Object { $_ -match '^fingerprint:\s*[0-9a-f]{64}\s*$' } |
                Select-Object -First 1) -replace '^fingerprint:\s*', ''
            if (-not $fingerprint) {
                Write-Bad "hkdfguard.exe status reported no fingerprint for '$service':`n$($statusOutput -join "`n")"
            } else {
                $retireStart = (Get-Date).AddSeconds(-2)
                & $cliPath retire --service-name $serviceName --fingerprint $fingerprint.Trim()
                if ($LASTEXITCODE -ne 0) {
                    Write-Bad "hkdfguard.exe retire exited $LASTEXITCODE; the KEK for '$service' was left in place"
                } else {
                    Write-Ok "retired the verification KEK for '$service' (fingerprint $($fingerprint.Trim()))"

                    $after = @(& $cliPath status --service-name $serviceName 2>&1 | ForEach-Object { "$_" })
                    if ($after -contains 'kek: absent') {
                        Write-Ok "status reports '$service' absent after retire"
                    } else {
                        Write-Bad "status still reports a KEK for '$service' after retire:`n$($after -join "`n")"
                    }

                    $sinceUtc = $retireStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    $xpath = "*[System[Provider[@Name='hkdfguard-native-windows'] and EventID=1004 and TimeCreated[@SystemTime>='$sinceUtc']]]"
                    $events = @()
                    try { $events = @(Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction Stop) } catch { }
                    $retired = @($events | Where-Object {
                        ([string]$_.Properties[0].Value).Contains($service) -and
                        ([string]$_.Properties[0].Value).Contains($fingerprint.Trim()) })
                    if ($retired.Count -ge 1) {
                        Write-Ok "retire recorded in the event log (event 1004) with this KEK's fingerprint"
                    } else {
                        Write-Bad "no retire event 1004 found for service '$service' with fingerprint $($fingerprint.Trim())"
                    }
                }
            }
        } finally {
            $env:PATH = $oldPath
        }
    }
}

# ---- Summary ----------------------------------------------------------
Write-Section "Summary"
if ($FailureCount -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "$FailureCount check(s) failed - see [FAIL] lines above." -ForegroundColor Red
    exit 1
}
