<#
.SYNOPSIS
    One fuzzing campaign: builds <Target>, runs it for <Seconds>, and
    reports the result as Markdown.

.DESCRIPTION
        .\tests\fuzz\Run-Campaign.ps1 -Target fuzz_unwrap_dek -Seconds 900

    Starts from the target's corpus (build-fuzz\campaign-corpus\<Target>,
    kept between runs where the caller keeps it) and its seeds
    (Make-AbiSeeds.ps1, or the checked-in corpus\ of the two older
    targets). Exits 0 with no findings, 1 on a finding, 2 if the target
    doesn't build or the arguments are wrong.

    By hand, the report goes to the console and says what was found. In CI
    (.github/workflows/fuzz.yml) it goes to the run's summary page, which on
    a public repository anyone can read - so there it says only *that*
    there was a finding, and the finding itself goes into
    build-fuzz\campaign-<Target>.sarif, which the workflow uploads to code
    scanning: the Security tab, shown to maintainers only. The SARIF carries
    what failed, the input (base64, with the commands that replay it) and
    the end of the fuzzer's log.

    The fuzzer's own output goes to build-fuzz\campaign-<Target>.log; a
    finding's input is under build-fuzz\campaign-artifacts\<Target>\.

    Run it elevated for the full harness (a KEK can only be created
    elevated - see README.md); GitHub's hosted Windows runners are. x64
    only: MSVC has no ARM64 AddressSanitizer runtime. The counterpart of
    hkdfguard-native-linux's fuzz/campaign.sh and fuzz/finding_sarif.py.
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][int]$Seconds,
    # Further libFuzzer options, e.g. -FuzzerOptions '-rss_limit_mb=4096'.
    [string[]]$FuzzerOptions = @()
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot

if ($Target -notmatch '^fuzz_[a-z0-9_]+$' -or -not (Test-Path (Join-Path $PSScriptRoot "$Target.cpp"))) {
    Write-Host "campaign: no fuzz target `"$Target`"" -ForegroundColor Red
    exit 2
}
if ($Seconds -le 0) {
    Write-Host "campaign: -Seconds must be positive" -ForegroundColor Red
    exit 2
}
if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    Write-Host "campaign: needs an x64 PowerShell (MSVC's AddressSanitizer runtime is x86/x64 only)" -ForegroundColor Red
    exit 2
}

# Set where what this prints is public (GitHub Actions): a finding's details
# then go to the SARIF file only.
$public = [bool]$env:GITHUB_ACTIONS
$buildDir = Join-Path $RepoRoot "build-fuzz"
$log = Join-Path $buildDir "campaign-$Target.log"
$sarif = Join-Path $buildDir "campaign-$Target.sarif"
$artifacts = Join-Path $buildDir "campaign-artifacts\$Target"
$corpus = Join-Path $buildDir "campaign-corpus\$Target"

function Add-Summary([string]$Markdown) {
    if ($env:GITHUB_STEP_SUMMARY) {
        # UTF-8 without a byte order mark, which Add-Content would write.
        [IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, "$Markdown`n")
    } else {
        Write-Host $Markdown
    }
}

# ---- Build ---------------------------------------------------------------
# The configuration Build-Analysis.ps1 tests - Debug, AddressSanitizer -
# without clang-tidy, and only this target.
function Invoke-Build {
    $installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
    $vswhere = Join-Path $installerDir "vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found at $vswhere" }
    $env:PATH = "$env:PATH;$installerDir"
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw "no Visual Studio / Build Tools install with the x64 C++ build tools was found" }
    & (Join-Path $vs "Common7\Tools\Launch-VsDevShell.ps1") -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null

    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    $buildLog = Join-Path $buildDir "campaign-$Target.build.log"
    # Through cmd so that the tools' stderr is text in the log, not
    # PowerShell error records.
    cmd /c "cmake -S . -B `"$buildDir`" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DHKDFGUARD_ENABLE_ASAN=ON -DHKDFGUARD_BUILD_FUZZERS=ON > `"$buildLog`" 2>&1"
    if ($LASTEXITCODE -eq 0) {
        cmd /c "cmake --build `"$buildDir`" --target $Target >> `"$buildLog`" 2>&1"
    }
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog -Tail 60 | ForEach-Object { Write-Host $_ }
        throw "the build failed (exit $LASTEXITCODE)"
    }
}

try {
    Invoke-Build
} catch {
    Write-Host "campaign: $Target did not build: $_" -ForegroundColor Red
    Add-Summary "### :x: ``$Target``: did not build`n`nThe harness no longer compiles against the library; see the job log.`n"
    exit 2
}

# ---- Run -----------------------------------------------------------------
$exe = Join-Path $buildDir "tests\$Target.exe"
$abiSeeds = Join-Path $buildDir "tests\fuzz-seeds\$Target"
$checkedInSeeds = Join-Path $PSScriptRoot "corpus\$Target"
New-Item -ItemType Directory -Path $corpus -Force | Out-Null
# Findings from an earlier run are not this run's.
foreach ($stale in $artifacts, $sarif) {
    if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Recurse -Force }
}
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null

$folders = @($corpus)  # the first folder is the one libFuzzer adds to
$maxLen = 1025        # the two older targets' ctest runs use this
if (Test-Path -LiteralPath $abiSeeds) {
    $folders += $abiSeeds
    $maxLen = 4096
} elseif (Test-Path -LiteralPath $checkedInSeeds) {
    $folders += $checkedInSeeds
}
$options = $FuzzerOptions + @("-max_total_time=$Seconds", "-timeout=60", "-max_len=$maxLen", "-print_final_stats=1",
    "-artifact_prefix=$($artifacts.Replace('\', '/'))/")
$arguments = ($options + $folders | ForEach-Object { "`"$_`"" }) -join " "

$process = Start-Process -FilePath $exe -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
    -RedirectStandardError $log -RedirectStandardOutput "$log.out"
$status = $process.ExitCode
$lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)

# ---- Report --------------------------------------------------------------
$executions = "unknown"
foreach ($line in $lines) {
    if ($line -match '^stat::number_of_executed_units:\s*(\d+)') { $executions = $Matches[1] }
}
$entries = @(Get-ChildItem -LiteralPath $corpus -File).Count
# libFuzzer also saves inputs that were merely slow ("slow-unit-"); those
# are not findings.
$findings = @(Get-ChildItem -LiteralPath $artifacts -File | Where-Object { $_.Name -notmatch '^slow-unit-' } | Sort-Object Name)

# The line that says what went wrong: a harness property, a sanitizer's
# verdict, or libFuzzer's own.
$reason = "the fuzzer stopped without a sanitizer report or a violated property (exit code $status)"
foreach ($line in $lines) {
    if ($line -match '^(fuzz property violated: |harness: |SUMMARY: |==\d+== ?ERROR: |.*ERROR: libFuzzer: )') {
        $reason = $line.Trim()
        break
    }
}

$summary = if ($status -eq 0) { "### :white_check_mark: ``$Target``: no findings`n`n" } else { "### :x: ``$Target``: FINDING`n`n" }
$summary += "| executions | time budget | corpus entries | findings |`n|---|---|---|---|`n"
$summary += "| $executions | ${Seconds}s | $entries | $($findings.Count) |`n"
if ($status -ne 0 -and $public) {
    $summary += "`nThe details - what failed, the input, the log - are in the Security tab, under code scanning (tool ``hkdfguard-fuzz``). They are not in this run.`n"
} elseif ($status -ne 0) {
    $summary += "`n$reason`n"
    foreach ($f in $findings) { $summary += "`nReplay: ``$exe $($f.FullName)```n" }
}
Add-Summary $summary

if ($status -eq 0) { exit 0 }

# ---- A finding: SARIF for code scanning -----------------------------------
# `Reason` without what changes from run to run: addresses, process ids,
# paths up to the repository, long numbers.
function Get-Stable([string]$Reason) {
    $Reason = $Reason -replace '0x[0-9a-fA-F]+', '0x?'
    $Reason = $Reason -replace '==\d+==', ''
    $Reason = $Reason -replace '\S*[\\/](tests[\\/]fuzz[\\/]|src[\\/])', '$1'
    $Reason = $Reason -replace '\bT?\d{3,}\b', 'N'
    return (($Reason -split '\s+') | Where-Object { $_ }) -join ' '
}

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$digest = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Target`n$(Get-Stable $reason)"))
$fingerprint = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
$commit = (& git rev-parse HEAD 2>$null)
if (-not $commit) { $commit = "unknown" }

# A finding's input is at most -max_len bytes.
$encodedInputs = @()
foreach ($f in $findings) {
    if ($f.Length -le 65536) {
        $encodedInputs += , @($f.Name, [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName)))
    }
}

$fence = '```'
$replay = ""
foreach ($pair in $encodedInputs) {
    $replay += "Input ``$($pair[0])``:`n`n${fence}powershell`n"
    $replay += "[IO.File]::WriteAllBytes(`"`$PWD\$($pair[0])`", [Convert]::FromBase64String('$($pair[1])'))`n"
    $replay += ".\build-fuzz\tests\$Target.exe .\$($pair[0])`n$fence`n`n"
}
if ($encodedInputs.Count -eq 0) {
    $replay = "The fuzzer saved no input for this finding; the log below is all there is.`n`n"
}
$tailLines = @($lines | Select-Object -Last 60)
$tail = ($tailLines -join "`n").Replace($fence, "'''")
$details = "Fuzz target ``$Target`` failed at commit ``$commit``.`n`n**$reason**`n`n" +
    "To reproduce (see tests/fuzz/README.md; build with ``tests\fuzz\Run-Campaign.ps1`` or ``scripts\Build-Analysis.ps1``):`n`n" +
    $replay +
    "The end of the fuzzer's log:`n`n$fence`n$tail`n$fence`n`n" +
    "This alert is the only copy: the run's log, summary and artifacts carry none of it. " +
    "A fix is checked by replaying the input above; the alert is then dismissed by hand " +
    "(no later run closes it), and the input belongs in tests/fuzz/Make-AbiSeeds.ps1."

# The message is plain text, and what the alert list shows: the reason, then
# the input once more in case the help text is not shown in full.
$message = "Fuzzing ${Target}: $reason"
foreach ($pair in $encodedInputs) { $message += "`nInput $($pair[0]) (base64): $($pair[1])" }

$ruleId = "fuzz/$Target"
$document = [ordered]@{
    '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
    version   = "2.1.0"
    runs      = @(
        [ordered]@{
            tool    = [ordered]@{
                driver = [ordered]@{
                    name           = "hkdfguard-fuzz"
                    informationUri = "https://llvm.org/docs/LibFuzzer.html"
                    rules          = @(
                        [ordered]@{
                            id                   = $ruleId
                            name                 = "FuzzFinding"
                            shortDescription     = @{ text = "Fuzzing finding in $Target" }
                            fullDescription      = @{ text = "A libFuzzer run of tests/fuzz/$Target.cpp crashed, tripped AddressSanitizer or a guard page, timed out, or broke one of the harness's assertions about the C ABI's contract." }
                            help                 = [ordered]@{ text = $details; markdown = $details }
                            defaultConfiguration = @{ level = "error" }
                            properties           = [ordered]@{ tags = @("security", "fuzzing"); 'security-severity' = "8.0" }
                        }
                    )
                }
            }
            results = @(
                [ordered]@{
                    ruleId              = $ruleId
                    ruleIndex           = 0
                    level               = "error"
                    message             = @{ text = $message }
                    locations           = @(
                        @{ physicalLocation = [ordered]@{
                                artifactLocation = @{ uri = "tests/fuzz/$Target.cpp" }
                                region           = @{ startLine = 1 }
                            }
                        }
                    )
                    partialFingerprints = @{ 'fuzzFinding/v1' = $fingerprint }
                }
            )
        }
    )
}
[IO.File]::WriteAllText($sarif, ($document | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
# One category per distinct finding, so a later finding never replaces an
# earlier alert and the same finding on another night updates its own.
$category = "fuzz-$Target-$($fingerprint.Substring(0, 16))"

if ($public) {
    # For the upload step. Nothing of the finding goes to the job log.
    if ($env:GITHUB_OUTPUT) {
        [IO.File]::AppendAllText($env:GITHUB_OUTPUT, "sarif=$sarif`ncategory=$category`n")
    }
    Write-Host "campaign: finding in $Target; see the Security tab (code scanning)."
} else {
    $tailLines | ForEach-Object { Write-Host $_ }
    Write-Host "campaign: finding in $Target; SARIF for code scanning written to $sarif." -ForegroundColor Red
}
exit 1
