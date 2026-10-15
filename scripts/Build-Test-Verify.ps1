<#
.SYNOPSIS
    Configures, builds, tests, and does an end-to-end CLI+DLL verification
    of hkdfguard-native-windows.

.DESCRIPTION
    1. Locates the MSVC/CMake/Ninja toolchain from the Visual Studio Build
       Tools install and puts them on PATH for this process - the native
       toolchain for this process's architecture (x64 or ARM64), since
       everything built here is also run here.
    2. Configures and builds the project (cmake -G Ninja).
    3. Runs the project's own ctest suite (roundtrip).
    4. Generates a random 32-byte DEK, wraps it with the CLI tool
       (tools/hkdfguard.exe), then independently unwraps the
       resulting file via a direct P/Invoke call into HkdfGuardV1.dll's public
       hkdfguard_unwrap_dek and confirms the recovered bytes match the
       original DEK - i.e. verifies the CLI's wrap output is unwrappable by
       the DLL, not just by the CLI itself.

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
    Skip deleting the verification KEK and wrapped-key file afterward.
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

# ---- Locate and enter the VS Build Tools developer environment --------
Write-Section "Locating MSVC / CMake / Ninja"
$installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$vswhere = Join-Path $installerDir "vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere - is Visual Studio / Build Tools installed?"
}
$env:PATH = "$env:PATH;$installerDir"

# Builds for the architecture of *this PowerShell process*, natively: the
# tests below have to run what was built, and the DLL unwrap check loads
# HkdfGuardV1.dll into this very process via P/Invoke, which only works when
# the two architectures match. On ARM64 Windows that means ARM64 binaries
# from a native ARM64 powershell.exe (an x64 powershell.exe running under
# emulation reports AMD64 and gets x64 binaries, which it can load).
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
cmake -S . -B build -G Ninja "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }
Write-Ok "configure succeeded"

Write-Section "Building"
cmake --build build --config $Configuration
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }
Write-Ok "build succeeded"

$dllPath = Join-Path $RepoRoot "build\HkdfGuardV1.dll"
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
    # Each failed check prints "[FAIL] <what>" somewhere in hundreds of lines
    # of test output; collect them from ctest's full log so they are listed
    # together here - and, under GitHub Actions, raised as error annotations
    # on the run's summary page.
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

$verifyDir = Join-Path $RepoRoot "build\verify"
New-Item -ItemType Directory -Force -Path $verifyDir | Out-Null
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

# hkdfguard.exe (build\tools\) links against HkdfGuardV1.dll
# (build\), a different directory - Windows won't find the DLL by default,
# so prepend its directory to PATH for both calls below, same as
# tests/CMakeLists.txt already does for ctest via ENVIRONMENT PATH.
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

    # P/Invoke straight into the built DLL's public hkdfguard_unwrap_dek -
    # deliberately not reusing the CLI (which only wraps) or ctest (which
    # links the DLL at build time) - this calls the *exact* HkdfGuardV1.dll
    # the CLI just used, dynamically, the same way any external consumer
    # (C#, Python, etc. - see README.md) would.
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
    if ($providerName) {
        # Matches kek_store.cpp's KeyName(): every piece of the persisted
        # name is lowercase, and $service is already lowercase.
        $keyName = "hkdfguardwin_${service}_v1"
        & certutil -csp $providerName -delkey $keyName | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "removed persisted KEK '$keyName' from $providerName"
        } else {
            Write-Host "note: could not remove persisted KEK '$keyName' (certutil exit $LASTEXITCODE) - harmless, just left behind in key storage" -ForegroundColor Yellow
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
