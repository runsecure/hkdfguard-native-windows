<#
.SYNOPSIS
    Builds every target with clang-tidy and AddressSanitizer and runs the
    ctest suite against the instrumented binaries.

.DESCRIPTION
    The analysis counterpart of Build-Test-Verify.ps1, in its own folder
    (build-analysis\) so it never mixes with the shipped build:

    1. Enters the Visual Studio developer environment (x64 - MSVC has no
       ARM64 AddressSanitizer runtime).
    2. Configures a Debug build (cmake -G Ninja) with
         HKDFGUARD_CLANG_TIDY=ON     clang-tidy on every source, with the
                                     checks in .clang-tidy, findings as errors
         HKDFGUARD_ENABLE_ASAN=ON    /fsanitize=address on every target
         HKDFGUARD_BUILD_FUZZERS=ON  the libFuzzer targets and their smoke runs
         HKDFGUARD_BUILD_BENCHMARKS=ON
       on top of the flags every build has (/W4 /permissive- /WX /analyze).
    3. Builds; any clang-tidy finding or compiler warning fails the build.
    4. Runs ctest, so every memory access the tests drive is checked by ASan.

    Run it elevated for the full suite (as Build-Test-Verify.ps1 explains,
    the machine-wide KEK tests need it); non-elevated, those checks skip.
    The binaries it builds are for testing only - never ship them.
#>
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "Build-Analysis.ps1 needs an x64 PowerShell: MSVC's AddressSanitizer runtime is x86/x64 only."
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not elevated: the machine-wide KEK tests will skip." -ForegroundColor Yellow
}

# ---- Enter the VS developer environment (as Build-Test-Verify.ps1) ------
$installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$vswhere = Join-Path $installerDir "vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found at $vswhere" }
$env:PATH = "$env:PATH;$installerDir"
$vsInstallPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstallPath) { throw "No Visual Studio / Build Tools install with the x64 C++ build tools was found." }
& (Join-Path $vsInstallPath "Common7\Tools\Launch-VsDevShell.ps1") -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
foreach ($tool in "cl", "cmake", "ninja") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool not found after entering the VS dev shell." }
}

# ---- Configure, build, test ---------------------------------------------
$buildDir = Join-Path $RepoRoot "build-analysis"
cmake -S . -B $buildDir -G Ninja -DCMAKE_BUILD_TYPE=Debug `
    -DHKDFGUARD_CLANG_TIDY=ON -DHKDFGUARD_ENABLE_ASAN=ON `
    -DHKDFGUARD_BUILD_FUZZERS=ON -DHKDFGUARD_BUILD_BENCHMARKS=ON
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }

# -k 0: report every failing source, not just the first.
cmake --build $buildDir -- -k 0
if ($LASTEXITCODE -ne 0) { throw "analysis build failed (exit $LASTEXITCODE): see the clang-tidy / compiler errors above" }

ctest --test-dir $buildDir --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "ctest failed under AddressSanitizer (exit $LASTEXITCODE)" }

Write-Host "clang-tidy, /analyze and AddressSanitizer: all clean." -ForegroundColor Green
