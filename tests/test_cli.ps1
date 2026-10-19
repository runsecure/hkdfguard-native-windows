<#
Exercises hkdfguard.exe's own behavior - subcommand dispatch,
argument parsing, base64/length validation, --group resolution, and the
"don't touch an existing file without --force" guarantee - none of which is
covered by test_roundtrip.exe (which only calls into HkdfGuard.dll directly,
never spawns the CLI). Registered as ctest's "cli" test; see
tests/CMakeLists.txt.

The CLI has four subcommands: "provision" (hkdfguard_kek_exists /
hkdfguard_create_kek, then prints hkdfguard_kek_fingerprint), "wrap"
(hkdfguard_wrap_dek only, against an already-provisioned KEK; the DEK is fed
to it as base64 text on stdin via --dek-stdin, never as a command-line
argument), "status" (read-only) and "retire" (deletes a KEK by fingerprint;
elevated only - it also serves as the elevated scenarios' cleanup).

Most scenarios below are reachable without ever creating a machine-wide KEK
(each one fails - by design - before RunWrap()/RunProvision() in
hkdfguard_cli.cpp ever calls into HkdfGuard.dll), so this test
passes whether or not the process is elevated. This includes "wrap" against a
service that was never provisioned - opening a nonexistent key fails
(NTE_BAD_KEYSET -> HKDFGUARD_ERR_KEK_NOT_FOUND) regardless of privilege
level, so that scenario also runs unconditionally. The handful of scenarios
that need a real, persisted machine-wide KEK (an actual provision + wrap
round trip, and a --force overwrite of the resulting file) do need the
machine-wide KEK and so only run when this process happens to be elevated;
they're skipped (not failed) otherwise, consistent with this project's
existing convention that full wrap/unwrap coverage requires `ctest` to be
run elevated.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$CliExePath
)

$ErrorActionPreference = "Stop"
$failures = 0
function Check($condition, $what) {
    if ($condition) {
        Write-Host "[PASS] $what" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $what" -ForegroundColor Red
        $script:failures++
    }
}

# Quotes a single argument for Win32's CreateProcess command-line convention
# (the same one hkdfguard.exe's own wmain/CommandLineToArgvW
# parses): wrapped in double quotes, with any embedded double quote escaped
# as \" - whenever the argument is empty or contains a space or quote.
# ProcessStartInfo.ArgumentList (which would avoid needing this entirely) is
# unreliable on this Windows PowerShell 5.1 / .NET Framework combination -
# it can come back null - so this builds a single Arguments string instead.
function Format-CliArg([string]$arg) {
    if ($arg -eq "" -or $arg -match '[\s"]') {
        return '"' + ($arg -replace '"', '\"') + '"'
    }
    return $arg
}

# Runs the CLI with the given argv, returning its exit code and captured
# stdout/stderr. The child's stdin is always redirected and then closed, so
# a scenario can never block waiting on the console. $StdIn (text, sent as
# ASCII) or $StdInBytes (sent exactly as given) supplies its content - this
# is how "wrap --dek-stdin" scenarios below supply their base64 DEK. No
# trailing newline is added.
#
# Bytes are written straight to the pipe, never through
# $proc.StandardInput's text writer. On Windows PowerShell 5.1 (.NET
# Framework) that writer uses [Console]::InputEncoding, and when that is
# UTF-8 with a preamble it writes a byte-order mark into the pipe the moment
# Process.Start creates it - before anything the scenario sends. So the
# console's input encoding is switched to BOM-less UTF-8 just around
# Process.Start, then restored, which keeps results independent of the
# console the test happens to run in.
function Invoke-Cli {
    param(
        [string[]]$CliArgs,
        [string]$StdIn = "",
        [byte[]]$StdInBytes = $null
    )
    if ($null -eq $StdInBytes) {
        $StdInBytes = [System.Text.Encoding]::ASCII.GetBytes($StdIn)
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CliExePath
    $psi.Arguments = ($CliArgs | ForEach-Object { Format-CliArg $_ }) -join " "
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.UseShellExecute = $false
    $savedInputEncoding = $null
    try {
        $savedInputEncoding = [Console]::InputEncoding
        if ($savedInputEncoding.GetPreamble().Length -gt 0) {
            [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
        } else {
            $savedInputEncoding = $null
        }
    } catch {
        $savedInputEncoding = $null # no console to adjust; nothing to restore
    }
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } finally {
        if ($null -ne $savedInputEncoding) {
            try { [Console]::InputEncoding = $savedInputEncoding } catch { }
        }
    }
    # The child may legitimately exit before consuming all of stdin (e.g.
    # the oversized-input scenario), which can surface here as a broken
    # pipe; that's the child's behavior under test, not a harness error.
    $stdinStream = $proc.StandardInput.BaseStream
    try {
        $stdinStream.Write($StdInBytes, 0, $StdInBytes.Length)
        $stdinStream.Flush()
    } catch [System.IO.IOException] {
    } finally {
        try { $stdinStream.Close() } catch [System.IO.IOException] { }
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{ ExitCode = $proc.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

# %TEMP% itself may be spelled with an 8.3 short name - on GitHub's hosted
# runners it is C:\Users\RUNNER~1\... - and the CLI refuses short names, so
# it's expanded to its long form (GetLongPathName) before any path is built
# from it.
Add-Type -Namespace HkdfGuardCliTest -Name Path -MemberDefinition @"
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetLongPathNameW(string shortPath, System.Text.StringBuilder longPath, uint size);
"@
$tempLong = New-Object System.Text.StringBuilder 32768
$tempLen = [HkdfGuardCliTest.Path]::GetLongPathNameW($env:TEMP, $tempLong, 32768)
$tempDir = if ($tempLen -gt 0 -and $tempLen -lt 32768) { $tempLong.ToString() } else { $env:TEMP }
$workDir = Join-Path $tempDir ("hkdfguard-cli-test-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    $validB64 = [Convert]::ToBase64String((New-Object byte[] 32)) # 32 zero bytes - valid shape, not used for a real wrap

    # The --group every scenario below passes when the group itself isn't what
    # is under test: it must exist on every machine and must not be one of
    # the over-broad groups the CLI refuses (scenario 7b), so Administrators.
    $narrowGroup = "Administrators"

    # ---- 1. Top-level --help exits 0. ----
    $r = Invoke-Cli @("--help")
    Check ($r.ExitCode -eq 0) "--help exits 0"
    # "help" too, as the Linux tool accepts it.
    $r = Invoke-Cli @("help")
    Check ($r.ExitCode -eq 0) "help exits 0"

    # ---- 2. No arguments at all: missing required subcommand. ----
    $r = Invoke-Cli @()
    Check ($r.ExitCode -eq 2) "no arguments exits 2 (usage error)"

    # ---- 3. An unrecognized top-level command. ----
    $r = Invoke-Cli @("frobnicate")
    Check ($r.ExitCode -eq 2) "unrecognized command exits 2"
    Check ($r.StdErr -match 'unknown subcommand "frobnicate": expected `provision`, `wrap`, `retire` or `status`') "an unknown subcommand gets the macOS tool's message"
    $r = Invoke-Cli @()
    Check ($r.StdErr -match 'missing subcommand: expected `provision`, `wrap`, `retire` or `status`') "a missing subcommand gets the macOS tool's message"
    Check ($r.StdErr -match "--dek-stdin \| --dek-file <path>") "the usage text shows both DEK sources"
    $r = Invoke-Cli @("provision", "--service-name", "svc", "--force")
    Check (($r.ExitCode -eq 2) -and ($r.StdErr -match 'is not valid for `provision`; it belongs to `wrap`')) "provision refuses wrap-only flags, as on Linux"

    # #12: every repeated flag is a usage error, not "the last one wins".
    foreach ($case in @(
            @(@("wrap", "-kf", "a.key", "-kf", "b.key", "-sn", "svc", "--dek-stdin"), "--key-file-path"),
            @(@("wrap", "-kf", "a.key", "-sn", "a", "--service-name", "b", "--dek-stdin"), "--service-name"),
            @(@("wrap", "-kf", "a.key", "-sn", "svc", "--dek-stdin", "-f", "--force"), "--force"),
            @(@("wrap", "-kf", "a.key", "-sn", "svc", "--dek-stdin", "-g", "x", "--group", "x"), "--group"),
            @(@("provision", "-sn", "a", "-sn", "a"), "--service-name"))) {
        $r = Invoke-Cli $case[0]
        Check (($r.ExitCode -eq 2) -and ($r.StdErr -match "give $($case[1]) at most once")) "a repeated $($case[1]) is a usage error ($($case[0] -join ' '))"
    }

    # #16: an over-long service name gets the Linux tool's message, before the library sees it.
    $r = Invoke-Cli @("provision", "-sn", ("a" * 129))
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "--service-name must be at most 128 bytes, got 129")) "an over-long service name gets the Linux tool's message"

    # ---- 3b. retire and status argument parsing - usage errors (exit 2), ----
    #          all before any key is looked at. The macOS tool's messages.
    $zeroFp = "0" * 64
    foreach ($case in @(
            @(@("retire", "-sn", "svc"), "missing required --fingerprint\|-fp"),
            @(@("retire", "-fp", $zeroFp), "retire: missing required --service-name"),
            @(@("retire", "-sn", "svc", "-fp", $zeroFp, "--corrupt"), "--fingerprint and --corrupt are mutually exclusive"),
            @(@("retire", "-sn", "svc", "-fp", "abc"), "--fingerprint must be exactly 64 hex characters, got 3"),
            @(@("retire", "-sn", "svc", "-fp", ("g" * 64)), "--fingerprint must contain only hex characters"),
            @(@("retire", "-sn", "svc", "-fp", $zeroFp, "-fp", $zeroFp), "give --fingerprint at most once"),
            @(@("retire", "-sn", "svc", "--corrupt", "--provider", "disk"), "--provider must be ``tpm`` or ``software``"),
            @(@("retire", "-sn", "svc", "--corrupt", "--force"), "unrecognized argument for ``retire``"),
            @(@("status"), "status: missing required --service-name"),
            @(@("status", "-sn", "svc", "--corrupt"), "unrecognized argument for ``status``"),
            @(@("retire", "-sn", "svc", "--corrupt", "--corrupt"), "give --corrupt at most once"),
            @(@("retire", "-sn", "svc", "--corrupt", "--provider", "tpm", "--provider", "tpm"), "give --provider at most once"),
            @(@("retire", "-sn", "a", "-sn", "a", "--corrupt"), "give --service-name at most once"),
            @(@("status", "-sn", "a", "--service-name", "a"), "give --service-name at most once"),
            @(@("retire", "--corrupt", "-fp"), "-fp requires a value"),
            @(@("retire", "--corrupt", "--provider"), "--provider requires a value"),
            @(@("status", "-sn"), "-sn requires a value"),
            @(@("retire", "-sn", "svc", "--fingerprint", ""), "--fingerprint must not be empty"),
            @(@("status", "--service-name", ""), "--service-name must not be empty"))) {
        $r = Invoke-Cli $case[0]
        Check (($r.ExitCode -eq 2) -and ($r.StdErr -match $case[1])) "usage error: $($case[0] -join ' ')"
        if (-not (($r.ExitCode -eq 2) -and ($r.StdErr -match $case[1]))) { Write-Host "    exit $($r.ExitCode); stderr: $($r.StdErr)" }
    }

    # --help after either new subcommand prints the usage and exits 0.
    foreach ($sub in "retire", "status") {
        $r = Invoke-Cli @($sub, "--help")
        Check (($r.ExitCode -eq 0) -and ($r.StdErr -match "hkdfguard retire --service-name")) "$sub --help prints the usage (exit 0)"
    }

    # A malformed service name is an operational error (exit 1) with the
    # same message provision and wrap give - for retire before the
    # elevation check, so it is the same elevated or not.
    foreach ($sub in "retire", "status") {
        $extra = if ($sub -eq "retire") { @("--corrupt") } else { @() }
        $r = Invoke-Cli (@($sub, "-sn", "bad-name") + $extra)
        Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "must contain only alphanumeric characters or '.'")) "$sub refuses a service name with a hyphen"
        $r = Invoke-Cli (@($sub, "-sn", ".svc") + $extra)
        Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "may not start with '.' or contain")) "$sub refuses a service name starting with '.'"
    }

    # ---- 3c. status for a never-provisioned service: a definite "absent", ----
    #          exit 0, so scripts can tell "no key" from "can't tell".
    $absentService = "hkdfguardabsent" + [Guid]::NewGuid().ToString("N")
    $r = Invoke-Cli @("status", "-sn", $absentService)
    Check (($r.ExitCode -eq 0) -and ($r.StdOut -match "kek: absent")) "status reports a never-provisioned service as absent (exit 0)"

    # ---- 4. wrap: missing a required flag (--dek-stdin). ----
    $keyFile = Join-Path $workDir "missing-dek.key"
    $r = Invoke-Cli @("wrap", "--key-file-path", $keyFile, "--service-name", "svc", "--group", $narrowGroup)
    Check ($r.ExitCode -eq 2) "wrap missing --dek-stdin exits 2"

    # ---- 5. wrap: an unrecognized argument. ----
    $r = Invoke-Cli @("wrap", "--key-file-path", $keyFile, "--bogus-flag", "x")
    Check ($r.ExitCode -eq 2) "wrap unrecognized argument exits 2"

    # ---- 6. provision: missing the required --service-name. ----
    $r = Invoke-Cli @("provision")
    Check ($r.ExitCode -eq 2) "provision missing --service-name exits 2"

    # ---- 7. wrap: an unresolvable --group fails before any file is touched. ----
    $bogusGroupKeyFile = Join-Path $workDir "bogus-group.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $bogusGroupKeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", "ThisGroupShouldNotExist12345") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap unresolvable --group exits 1"
    Check (-not (Test-Path $bogusGroupKeyFile)) "wrap unresolvable --group does not create the key file"

    # ---- 7b. wrap: an over-broad --group is refused before any file is ----
    #          touched or any DEK is read. Anyone who can read the wrapped
    #          file can copy it, and the payload format deliberately allows
    #          an older payload to be swapped in, so "everybody" groups are
    #          never acceptable. Checked on the resolved SID, so a
    #          BUILTIN-qualified spelling is caught the same way. (English
    #          account names; a localized Windows names these differently.)
    #          "None" is the local SAM's RID-513 group (every local account's
    #          primary group); "NTLM Authentication" is in the token of every
    #          NTLM-authenticated logon, which is every local-account logon.
    $broadGroups = @(
        "Users", "BUILTIN\Users", "Everyone", "Authenticated Users",
        "NT AUTHORITY\Local account", "NT SERVICE\ALL SERVICES", "Guests",
        "None", "NT AUTHORITY\NTLM Authentication")
    foreach ($broad in $broadGroups) {
        $broadKeyFile = Join-Path $workDir ("broad-" + ($broad -replace '[\\ ]', '_') + ".key")
        $r = Invoke-Cli @(
            "wrap", "--key-file-path", $broadKeyFile, "--service-name", "svc", "--dek-stdin",
            "--group", $broad) -StdIn $validB64
        Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "over-broad")) "wrap refuses the over-broad --group `"$broad`""
        Check (-not (Test-Path $broadKeyFile)) "wrap with over-broad --group `"$broad`" does not create the key file"
    }

    # ---- 7c. wrap: a --group outside this host is refused, as for the ----
    #          KeyUseGroups policy. A domain group needs a domain; CREATOR
    #          OWNER (S-1-3-0, a well-known group with no domain at all) is
    #          the case every machine has.
    $creatorOwner = (New-Object System.Security.Principal.SecurityIdentifier("S-1-3-0")).Translate([System.Security.Principal.NTAccount]).Value
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", (Join-Path $workDir "creator-owner.key"), "--service-name", "svc", "--dek-stdin",
        "--group", $creatorOwner) -StdIn $validB64
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "only groups on this host")) "wrap refuses a --group that isn't on this host ($creatorOwner)"
    if ($r.StdErr -notmatch "only groups on this host") { Write-Host "    stderr: $($r.StdErr)" }

    # ---- 8. wrap: invalid base64 on stdin. ----
    $badB64KeyFile = Join-Path $workDir "bad-b64.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $badB64KeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup) -StdIn "not-valid-base64!!!"
    Check ($r.ExitCode -eq 1) "wrap invalid base64 on stdin exits 1"
    Check (-not (Test-Path $badB64KeyFile)) "wrap invalid base64 on stdin does not create the key file"

    # ---- 9. wrap: valid base64 that decodes to the wrong length (16 bytes, not 32). ----
    $wrongLenKeyFile = Join-Path $workDir "wrong-len.key"
    $shortB64 = [Convert]::ToBase64String((New-Object byte[] 16))
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $wrongLenKeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup) -StdIn $shortB64
    Check ($r.ExitCode -eq 1) "wrap wrong-length decoded DEK exits 1"
    Check (-not (Test-Path $wrongLenKeyFile)) "wrap wrong-length decoded DEK does not create the key file"

    # ---- 10. wrap: a --service-name containing a character other than an ----
    #          ASCII alphanumeric or '.' is rejected.
    $badCharsetKeyFile = Join-Path $workDir "bad-charset.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $badCharsetKeyFile, "--service-name", "hkdfguard-cli-test", "--dek-stdin",
        "--group", $narrowGroup) -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap: a service name containing a hyphen is rejected"
    Check (-not (Test-Path $badCharsetKeyFile)) "wrap: a rejected service name does not create the key file"

    # ---- 11. wrap: an existing file without --force is left completely untouched. ----
    $existingFile = Join-Path $workDir "existing.key"
    Set-Content -Path $existingFile -Value "pre-existing content" -NoNewline
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $existingFile, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup) -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap existing file without --force exits 1"
    Check ((Get-Content -Path $existingFile -Raw) -eq "pre-existing content") "wrap existing file without --force is left untouched"

    # ---- 11a. 8.3 short names are refused, never expanded - even when they ----
    #           name a perfectly real folder - before any KEK or DEK work.
    #           Where the volume doesn't generate short names, an elevated run
    #           assigns one with fsutil; skipped only when neither works.
    $longDir = Join-Path $workDir "long-folder-name-for-short-name-test"
    New-Item -ItemType Directory -Force -Path $longDir | Out-Null
    $fso = New-Object -ComObject Scripting.FileSystemObject
    $shortDir = $fso.GetFolder($longDir).ShortPath
    if ((-not $shortDir) -or ($shortDir -eq $longDir)) {
        & fsutil.exe file setshortname $longDir "HKCLIS~1" *> $null
        $shortDir = $fso.GetFolder($longDir).ShortPath
    }
    if ($shortDir -and ($shortDir -ne $longDir)) {
        $viaShort = Join-Path $shortDir "new.key"
        $r = Invoke-Cli @(
            "wrap", "--key-file-path", $viaShort, "--service-name", "svc", "--dek-stdin",
            "--group", $narrowGroup) -StdIn $validB64
        Check ($r.ExitCode -eq 1) "wrap to a path with an 8.3 short folder name exits 1"
        Check ($r.StdErr -match "8\.3 short name") "wrap to a short-name path names the 8.3 short name as the reason"
        Check (-not (Test-Path (Join-Path $longDir "new.key"))) "wrap to a short-name path creates nothing"
    } else {
        Write-Host "[SKIP] wrap refuses 8.3 short names (this volume doesn't generate them)" -ForegroundColor Yellow
    }

    # ---- 11b. The wrapped-key path must be a real file at a real location: ----
    #           a junction (creatable without any privilege, unlike a file
    #           symlink) anywhere in the path is refused before any KEK or DEK
    #           work happens, both without and with --force. Without this, an
    #           attacker who can plant a link in the output directory could
    #           redirect an elevated `wrap --force` at an arbitrary file.
    $realDir = Join-Path $workDir "real"
    $linkDir = Join-Path $workDir "link"
    New-Item -ItemType Directory -Force -Path $realDir | Out-Null
    New-Item -ItemType Junction -Path $linkDir -Target $realDir | Out-Null

    # (a) No --force, leaf doesn't exist, parent is a junction: refused, and
    #     nothing is created in the junction's target directory.
    $viaLinkNew = Join-Path $linkDir "new.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $viaLinkNew, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup) -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap through a junction (new file) exits 1"
    Check (-not (Test-Path (Join-Path $realDir "new.key"))) "wrap through a junction does not create the file in the junction target"
    # Matched on wording that only appears in the CLI's own message, never in
    # a file path, so a different error that merely echoes the path can't
    # pass this check by accident.
    Check ($r.StdErr -match "reparse point|resolves through") "wrap through a junction names the link as the reason"

    # (b) --force, parent is a junction, target file exists: refused, and the
    #     target file is left completely untouched (not overwritten, not
    #     deleted).
    $realTarget = Join-Path $realDir "target.key"
    Set-Content -Path $realTarget -Value "must survive" -NoNewline
    $viaLinkForce = Join-Path $linkDir "target.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $viaLinkForce, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup, "--force") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap --force through a junction exits 1"
    Check ((Test-Path $realTarget) -and ((Get-Content -Path $realTarget -Raw) -eq "must survive")) "wrap --force through a junction leaves the junction target file untouched"

    # (c) The output path *is* the junction: refused.
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $linkDir, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup, "--force") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap with the junction itself as the output path exits 1"

    # A junction must be removed as a directory entry, never recursed into
    # (that would delete the target's contents); cmd's rmdir does exactly that.
    & cmd /c rmdir "$linkDir" | Out-Null

    # ---- 11d. A hard link at the output path is refused, with --force, and ----
    #           the file it shares data with is left untouched. A hard link
    #           is not a reparse point, so 11b's checks can't see it; without
    #           this, --force's overwrite passes would destroy the other
    #           file's contents. Runs unprivileged: creating a hard link to a
    #           file this test owns needs no elevation.
    $hardTarget = Join-Path $workDir "hardlink-target.dat"
    $hardLink = Join-Path $workDir "hardlink.key"
    Set-Content -Path $hardTarget -Value "must survive the hard link" -NoNewline
    New-Item -ItemType HardLink -Path $hardLink -Target $hardTarget | Out-Null
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $hardLink, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup, "--force") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap --force onto a hard-linked file exits 1"
    Check ($r.StdErr -match "hard links") "wrap --force onto a hard-linked file names hard links as the reason"
    Check ((Get-Content -Path $hardTarget -Raw) -eq "must survive the hard link") "wrap --force onto a hard-linked file leaves the linked file's contents untouched"
    Check (Test-Path $hardLink) "wrap --force onto a hard-linked file does not delete the link"

    # ---- 11c. Oversized stdin is refused rather than buffered without ----
    #           bound: the reader uses one fixed allocation so DEK text is
    #           never left behind in a freed, unwiped buffer, which means a
    #           hard input cap. 5000 bytes is far past the 64-byte limit.
    $oversizeKeyFile = Join-Path $workDir "oversize.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $oversizeKeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", $narrowGroup) -StdIn ("A" * 5000)
    Check ($r.ExitCode -eq 1) "wrap with oversized stdin exits 1"
    Check (-not (Test-Path $oversizeKeyFile)) "wrap with oversized stdin does not create the key file"
    Check ($r.StdErr -match "longer than 64 bytes") "wrap with oversized stdin says why"

    # ---- 12. wrap against a service that was never provisioned reports an ----
    #          error (HKDFGUARD_ERR_KEK_NOT_FOUND) rather than silently
    #          failing or creating a KEK. Opening a nonexistent key fails
    #          regardless of elevation, so this runs unconditionally.
    $neverProvisionedService = "hkdfguardnokek" + [Guid]::NewGuid().ToString("N")
    $noKekFile = Join-Path $workDir "no-kek.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $noKekFile, "--service-name", $neverProvisionedService, "--dek-stdin",
        "--group", $narrowGroup) -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap against a never-provisioned service exits 1"
    Check (-not (Test-Path $noKekFile)) "wrap against a never-provisioned service does not create the key file"
    # Exact library wording, not just "KEK": the output file is named
    # no-kek.key, so a looser pattern would match any error echoing the path.
    Check ($r.StdErr -match "no KEK is provisioned for service") "wrap against a never-provisioned service reports a KEK-not-found/provision error"

    # ---- 12a. --group is optional, as on Linux: without it the arguments ----
    #           are complete, so the same call gets as far as the KEK lookup
    #           (not a usage error, exit 2). Given twice, it is a usage error.
    $noGroupFile = Join-Path $workDir "no-group.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $noGroupFile, "--service-name", $neverProvisionedService, "--dek-stdin") -StdIn $validB64
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "no KEK is provisioned for service")) "wrap without --group is accepted (reaches the KEK lookup)"
    Check (-not (Test-Path $noGroupFile)) "wrap without --group against a never-provisioned service creates no key file"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $noGroupFile, "--service-name", $neverProvisionedService, "--dek-stdin",
        "--group", $narrowGroup, "-g", $narrowGroup) -StdIn $validB64
    Check (($r.ExitCode -eq 2) -and ($r.StdErr -match "at most once")) "wrap with --group given twice exits 2"

    # ---- 12b. A UTF-8 byte-order mark ahead of the base64 DEK is tolerated. ----
    #           Some PowerShell/.NET consoles prepend one when piping text to
    #           a native process. Same never-provisioned service as above, so
    #           reaching the KEK-not-found error proves the DEK decoded.
    $bomKeyFile = Join-Path $workDir "bom.key"
    $bomBytes = [byte[]](0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::ASCII.GetBytes($validB64 + "`r`n")
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $bomKeyFile, "--service-name", $neverProvisionedService, "--dek-stdin",
        "--group", $narrowGroup) -StdInBytes $bomBytes
    Check ($r.StdErr -notmatch "not valid base64") "wrap accepts a base64 DEK preceded by a UTF-8 byte-order mark"
    Check ($r.StdErr -match "no KEK is provisioned for service") "wrap with a UTF-8 byte-order mark decodes the DEK and proceeds to the KEK lookup"
    Check (-not (Test-Path $bomKeyFile)) "wrap with a UTF-8 byte-order mark against a never-provisioned service creates no key file"

    # ---- 12b2. Strict base64, the Linux tool's rules exactly: one trailing ----
    #            newline (LF or CRLF) and nothing else; canonical padding;
    #            the standard alphabet only. Accepted input reaches the KEK
    #            lookup (never provisioned); refused input says why.
    $strictKeyFile = Join-Path $workDir "strict.key"
    $mixedB64 = [Convert]::ToBase64String([byte[]](@(0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF) + (1..26)))
    $strictCases = @(
        @{ In = "$validB64`n"; Ok = $true; What = "one trailing LF" },
        @{ In = "$validB64`r`n"; Ok = $true; What = "one trailing CRLF" },
        @{ In = $mixedB64; Ok = $true; What = "the '+' and '/' characters" },
        @{ In = "$validB64`n`n"; Ok = $false; What = "two trailing newlines" },
        @{ In = " $validB64"; Ok = $false; What = "a leading space" },
        @{ In = ($validB64.Substring(0, 20) + " " + $validB64.Substring(20)); Ok = $false; What = "a space inside" },
        @{ In = ($validB64.Substring(0, 20) + "`r`n" + $validB64.Substring(20)); Ok = $false; What = "a line break inside" },
        @{ In = $validB64.TrimEnd('='); Ok = $false; What = "missing padding" },
        @{ In = ($mixedB64.Replace('+', '-').Replace('/', '_')); Ok = $false; What = "the URL-safe alphabet" },
        @{ In = ($validB64.Substring(0, 42) + "B="); Ok = $false; What = "non-zero bits before the padding" }
    )
    foreach ($case in $strictCases) {
        $r = Invoke-Cli @(
            "wrap", "--key-file-path", $strictKeyFile, "--service-name", $neverProvisionedService, "--dek-stdin") -StdIn $case.In
        if ($case.Ok) {
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "no KEK is provisioned for service")) "strict base64: $($case.What) is accepted"
        } else {
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "not valid base64")) "strict base64: $($case.What) is refused"
            # One fixed message, the Linux tool's: no character, offset or
            # bits of the input reach it.
            Check ($r.StdErr -match [regex]::Escape("error: the DEK input is not valid base64 (standard alphabet, padded, at most one trailing newline)")) "strict base64: $($case.What) gets the one fixed message"
            Check ($r.StdErr -notmatch "offset") "strict base64: $($case.What) names no offset"
            if ($r.StdErr -notmatch "not valid base64") { Write-Host "    stderr: $($r.StdErr)" }
        }
        Check (-not (Test-Path $strictKeyFile)) "strict base64: $($case.What) creates no key file"
    }

    # ---- 12b3. --dek-stdin refuses an interactive console, where a typed ----
    #            or pasted DEK would be echoed and kept in the scrollback.
    #            Needs a real console to hand the CLI: this script's own,
    #            when it has one (a console run). Otherwise skipped. The CLI
    #            must exit at once - if it waited on the console instead, it
    #            is stopped after 15 s and the check fails.
    $consoleKeyFile = Join-Path $workDir "console.key"
    $haveConsole = $false
    try { $haveConsole = -not [Console]::IsInputRedirected } catch { $haveConsole = $false }
    if ($haveConsole) {
        $consoleErr = Join-Path $workDir "console.err"
        $p = Start-Process -FilePath $CliExePath -NoNewWindow -PassThru -RedirectStandardError $consoleErr -ArgumentList @(
            "wrap", "--key-file-path", (Format-CliArg $consoleKeyFile), "--service-name", "svc", "--dek-stdin")
        # Read the handle while the process may still be running: without
        # it, a Start-Process -PassThru object reports no ExitCode at all.
        $null = $p.Handle
        $exited = $p.WaitForExit(15000)
        if (-not $exited) { $p.Kill() }
        $errText = if (Test-Path $consoleErr) { Get-Content -Raw $consoleErr } else { "" }
        $p.WaitForExit()
        Check ($exited -and $p.ExitCode -eq 1 -and ($errText -match "interactive terminal")) "wrap --dek-stdin refuses an interactive console"
        if (-not ($exited -and $p.ExitCode -eq 1 -and ($errText -match "interactive terminal"))) {
            Write-Host "    exited: $exited; exit code: $($p.ExitCode); stderr: $errText"
        }
        Check (-not (Test-Path $consoleKeyFile)) "wrap --dek-stdin from a console creates no key file"
    } else {
        Write-Host "[SKIP] wrap --dek-stdin refuses an interactive console (this run has no console to hand it)"
    }

    # ---- 12d. --dek-file: the DEK read from a file, by the Linux tool's ----
    #           rules in ACL form. Accepted input reaches the KEK lookup
    #           (never provisioned). The scratch folder is under %TEMP%, so a
    #           new file inherits SYSTEM, Administrators and this user only -
    #           exactly what the rule accepts.
    $dekFileKey = Join-Path $workDir "dekfile.key"
    $dekFile = Join-Path $workDir "dek.b64"
    [System.IO.File]::WriteAllText($dekFile, "$validB64`n")
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", $dekFile)
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "no KEK is provisioned for service")) "--dek-file: a private file is accepted (reaches the KEK lookup)"
    if ($r.StdErr -notmatch "no KEK is provisioned") { Write-Host "    stderr: $($r.StdErr)" }
    Check (-not (Test-Path $dekFileKey)) "--dek-file: nothing written for a never-provisioned service"

    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", "svc", "--dek-stdin", "--dek-file", $dekFile) -StdIn $validB64
    Check (($r.ExitCode -eq 2) -and ($r.StdErr -match "give exactly one of --dek-stdin or --dek-file")) "--dek-file and --dek-stdin together is a usage error"
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", "svc")
    Check (($r.ExitCode -eq 2) -and ($r.StdErr -match "missing required --dek-stdin or --dek-file")) "no DEK source is a usage error"

    $looseDek = Join-Path $workDir "loose.b64"
    [System.IO.File]::WriteAllText($looseDek, $validB64)
    & icacls $looseDek /grant "*S-1-1-0:(R)" | Out-Null # Everyone: read
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", $looseDek)
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "grants access to") -and ($r.StdErr -match "icacls")) "--dek-file: a file Everyone may read is refused, with the fix"

    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", (Join-Path $workDir "absent.b64"))
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "failed to open --dek-file")) "--dek-file: a missing file is refused"
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", $workDir)
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "not a regular file|failed to open")) "--dek-file: a directory is refused"

    $bigDek = Join-Path $workDir "big.b64"
    [System.IO.File]::WriteAllText($bigDek, ("A" * 100))
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", $bigDek)
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "--dek-file is longer than 64 bytes")) "--dek-file: an oversized file is refused"

    $badDek = Join-Path $workDir "bad.b64"
    [System.IO.File]::WriteAllText($badDek, ($validB64.Substring(0, 20) + " " + $validB64.Substring(20)))
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", $badDek)
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "not valid base64 \(standard alphabet")) "--dek-file: malformed base64 gets the one fixed message"

    $dekLinkReal = Join-Path $workDir "dek-real"
    $dekLink = Join-Path $workDir "dek-link"
    New-Item -ItemType Directory -Path $dekLinkReal | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dekLinkReal "dek.b64"), $validB64)
    New-Item -ItemType Junction -Path $dekLink -Target $dekLinkReal | Out-Null
    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", (Join-Path $dekLink "dek.b64"))
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "resolves through a symbolic link, junction")) "--dek-file: a file reached through a junction is refused"
    [System.IO.Directory]::Delete($dekLink)

    $r = Invoke-Cli @("wrap", "--key-file-path", $dekFileKey, "--service-name", $neverProvisionedService, "--dek-file", "\\localhost\C$\hkdfguard-no-such\dek.b64")
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "not on a local drive")) "--dek-file: a UNC path is refused before anything is opened"

    # The output path follows the same rule, checked before even the
    # "already exists" probe would touch it - in every UNC spelling.
    foreach ($uncKey in @("\\localhost\C$\hkdfguard-no-such\out.key", "\\?\UNC\localhost\C$\hkdfguard-no-such\out.key", "//localhost/C$/hkdfguard-no-such/out.key")) {
        $r = Invoke-Cli @("wrap", "--key-file-path", $uncKey, "--service-name", $neverProvisionedService, "--dek-stdin") -StdIn $validB64
        Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "is not on a local drive")) "--key-file-path: a UNC path ($uncKey) is refused before anything is opened"
        if ($r.StdErr -notmatch "is not on a local drive") { Write-Host "    stderr: $($r.StdErr)" }
    }

    # ---- 12c. UTF-16 input is refused with a message that says so, rather ----
    #           than a generic "not valid base64".
    $utf16KeyFile = Join-Path $workDir "utf16.key"
    $utf16Bytes = [byte[]](0xFF, 0xFE) + [System.Text.Encoding]::Unicode.GetBytes($validB64)
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $utf16KeyFile, "--service-name", $neverProvisionedService, "--dek-stdin",
        "--group", $narrowGroup) -StdInBytes $utf16Bytes
    Check ($r.ExitCode -eq 1) "wrap with UTF-16 stdin exits 1"
    Check ($r.StdErr -match "UTF-16") "wrap with UTF-16 stdin names the encoding as the problem"
    Check (-not (Test-Path $utf16KeyFile)) "wrap with UTF-16 stdin creates no key file"

    # Finds an event this run caused in the Application log under the
    # library's event source. Matched on the event's insertion string (the
    # full text event_log.cpp builds), which is present whether or not the
    # source is registered on this machine - so this works on a dev box
    # where the MSI was never installed, too.
    #
    # XPath rather than -FilterHashtable: the hashtable's ProviderName key
    # looks up the provider's registration and throws ("The parameter is
    # incorrect") when the source isn't registered, which is the normal
    # state before the MSI is installed. Get-WinEvent also reports "no
    # events found" as an error, hence the try/catch.
    function Find-HkdfEvent([datetime]$Since, [int]$Id, [string]$Needle) {
        $sinceUtc = $Since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $xpath = "*[System[Provider[@Name='hkdfguard-native-windows'] and EventID=$Id and TimeCreated[@SystemTime>='$sinceUtc']]]"
        try {
            $events = Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction Stop
        } catch {
            return @()
        }
        return @($events | Where-Object { $_.Properties.Count -ge 1 -and ([string]$_.Properties[0].Value).Contains($Needle) })
    }

    # ---- 13. Full provision + wrap via the CLI, plus a --force overwrite - ----
    #          needs a real machine-wide KEK, so only runs when elevated.
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $happyKeyFile = Join-Path $workDir "happy.key"
        # Alphanumeric only - see the "service name containing a hyphen is
        # rejected" scenario above; the CLI's ValidateServiceCharset would
        # reject a hyphenated name like the other tests' "hkdfguard-*" ones.
        $serviceName = "hkdfguardclitest"

        $provisionStart = (Get-Date).AddSeconds(-2)
        $pr = Invoke-Cli @("provision", "--service-name", $serviceName)
        Check ($pr.ExitCode -eq 0) "provision succeeds (elevated)"
        if ($pr.ExitCode -ne 0) {
            Write-Host "    exit code: $($pr.ExitCode)"
            Write-Host "    stdout: $($pr.StdOut)"
            Write-Host "    stderr: $($pr.StdErr)"
        }

        # Only a genuine creation is logged; if a previous interrupted run
        # left this KEK behind, provision just confirms it and there is
        # nothing to look for.
        if ($pr.StdOut -match "KEK provisioned for service") {
            $created = @(Find-HkdfEvent -Since $provisionStart -Id 1000 -Needle "'$serviceName'") +
                       @(Find-HkdfEvent -Since $provisionStart -Id 1001 -Needle "'$serviceName'")
            Check ($created.Count -ge 1) "KEK creation is recorded in the Application event log (event 1000/1001)"
        }

        # Re-provisioning an existing KEK must still call hkdfguard_create_kek,
        # so the existing key's properties and ACL are re-verified rather than
        # accepted on hkdfguard_kek_exists's word alone.
        if ($pr.ExitCode -eq 0) {
            $pr2 = Invoke-Cli @("provision", "--service-name", $serviceName)
            Check ($pr2.ExitCode -eq 0) "re-provisioning an existing KEK succeeds (elevated)"
            Check ($pr2.StdOut -match "already provisioned .*; verified") "re-provisioning an existing KEK reports that it verified the key"
        }

        # provision prints the KEK's fingerprint, and status repeats it.
        $kekFingerprint = $null
        if ($pr.StdOut -match "fingerprint: ([0-9a-f]{64}) -- ") { $kekFingerprint = $Matches[1] }
        Check ($null -ne $kekFingerprint) "provision prints the KEK's 64-hex-character fingerprint"
        $st = Invoke-Cli @("status", "-sn", $serviceName)
        Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: present") -and ($st.StdOut -match "provider: Microsoft ")) "status reports the provisioned KEK as present, with its provider"
        Check ($kekFingerprint -and $st.StdOut -match "fingerprint: $kekFingerprint") "status reports the same fingerprint provision printed"

        $dekBytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes)
        $dekB64 = [Convert]::ToBase64String($dekBytes)

        $r = Invoke-Cli @(
            "wrap", "--key-file-path", $happyKeyFile, "--service-name", $serviceName, "--dek-stdin",
            "--group", $narrowGroup, "--force") -StdIn $dekB64
        Check ($r.ExitCode -eq 0) "full wrap via the CLI succeeds against a provisioned KEK (elevated)"
        if ($r.ExitCode -ne 0) {
            Write-Host "    exit code: $($r.ExitCode)"
            Write-Host "    stdout: $($r.StdOut)"
            Write-Host "    stderr: $($r.StdErr)"
        }

        # The key file's DACL: protected, the owner read/write and --group
        # read-only, nobody else; without --group, the owner alone.
        function Get-KeyFileAces([string]$path) {
            $acl = Get-Acl -LiteralPath $path
            [pscustomobject]@{
                Protected = $acl.AreAccessRulesProtected
                Aces = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })
                Sddl = $acl.Sddl
            }
        }
        # The ACL checks need a group that is neither the file's owner (an
        # elevated wrap's owner is Administrators, which $narrowGroup also is,
        # so their ACEs would merge into one) nor over-broad: BUILTIN\Performance
        # Log Users, named through its well-known SID so any display language works.
        $aclGroupSid = "S-1-5-32-559"
        $aclGroup = ([System.Security.Principal.SecurityIdentifier]$aclGroupSid).Translate([System.Security.Principal.NTAccount]).Value
        $groupSid = $aclGroupSid
        $groupedFile = Join-Path $workDir "grouped.key"
        $rg = Invoke-Cli @(
            "wrap", "--key-file-path", $groupedFile, "--service-name", $serviceName, "--dek-stdin", "--group", $aclGroup) -StdIn $dekB64
        Check ($rg.ExitCode -eq 0) "full wrap with --group $aclGroup succeeds (elevated)"
        if ($rg.ExitCode -eq 0) {
            $acl = Get-KeyFileAces $groupedFile
            Check ($acl.Protected -and $acl.Aces.Count -eq 2 -and ($acl.Aces -contains $groupSid)) "with --group, the key file grants exactly the owner and that group (protected DACL)"
            if (-not ($acl.Protected -and $acl.Aces.Count -eq 2 -and ($acl.Aces -contains $groupSid))) { Write-Host "    protected: $($acl.Protected); ACEs: $($acl.Aces -join ', '); SDDL: $($acl.Sddl)" }
            Check ($rg.StdOut -match "owner read/write \+ .* read-only") "with --group, the success line names the group's read-only access"
        } else {
            Write-Host "    stderr: $($rg.StdErr)"
        }
        $fromFileKey = Join-Path $workDir "from-dek-file.key"
        $elevDekFile = Join-Path $workDir "elevated-dek.b64"
        [System.IO.File]::WriteAllText($elevDekFile, $dekB64)
        $rf = Invoke-Cli @("wrap", "--key-file-path", $fromFileKey, "--service-name", $serviceName, "--dek-file", $elevDekFile)
        Check ($rf.ExitCode -eq 0) "full wrap with --dek-file succeeds (elevated)"
        if ($rf.ExitCode -ne 0) { Write-Host "    stderr: $($rf.StdErr)" }

        $ownerOnlyFile = Join-Path $workDir "owner-only.key"
        $ro = Invoke-Cli @(
            "wrap", "--key-file-path", $ownerOnlyFile, "--service-name", $serviceName, "--dek-stdin") -StdIn $dekB64
        Check ($ro.ExitCode -eq 0) "full wrap without --group succeeds (elevated)"
        if ($ro.ExitCode -eq 0) {
            $acl = Get-KeyFileAces $ownerOnlyFile
            Check ($acl.Protected -and $acl.Aces.Count -eq 1 -and -not ($acl.Aces -contains $groupSid)) "without --group, the key file grants the owner alone (protected DACL)"
            if (-not ($acl.Protected -and $acl.Aces.Count -eq 1 -and -not ($acl.Aces -contains $groupSid))) { Write-Host "    protected: $($acl.Protected); ACEs: $($acl.Aces -join ', '); SDDL: $($acl.Sddl)" }
            Check ($ro.StdOut -match "owner read/write, service") "without --group, the success line says owner read/write only"
            # The library's own key-file trust rule accepts it.
            $roBytes = [System.IO.File]::ReadAllBytes($ownerOnlyFile)
            Check ($roBytes.Length -eq 132) "the owner-only key file holds a 132-byte payload"
        }

        $providerName = $null
        if ($r.ExitCode -eq 0) {
            $bytes = [System.IO.File]::ReadAllBytes($happyKeyFile)
            Check ($bytes.Length -eq 132) "CLI-produced wrapped file is 132 bytes"
            $embedded = -join ($bytes[100..131] | ForEach-Object { $_.ToString("x2") })
            Check ($embedded -eq $kekFingerprint) "the fingerprint provision printed is the one embedded in the payload (bytes 100..131)"

            # The wrap is audited (event 1002) with a SHA-256 of the exact
            # payload written - the value an unwrap event will later repeat.
            $payloadHash = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) |
                ForEach-Object { $_.ToString("x2") })
            $wrapped = Find-HkdfEvent -Since $provisionStart -Id 1002 -Needle $payloadHash
            Check ($wrapped.Count -ge 1) "the wrap is recorded in the Application event log (event 1002) with the payload's SHA-256"
            if ($wrapped.Count -ge 1) {
                Check ($wrapped[0].UserId.Value -eq $identity.User.Value) "the wrap event records the calling user"
            }

            $dekBytes2 = New-Object byte[] 32
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes2)
            $dekB64_2 = [Convert]::ToBase64String($dekBytes2)
            $r2 = Invoke-Cli @(
                "wrap", "--key-file-path", $happyKeyFile, "--service-name", $serviceName, "--dek-stdin",
                "--group", $narrowGroup, "--force") -StdIn $dekB64_2
            Check ($r2.ExitCode -eq 0) "--force overwrites an existing wrapped-key file"

            $providerType = $bytes[1]
            $providerName = switch ($providerType) {
                1 { "Microsoft Platform Crypto Provider" }
                2 { "Microsoft Software Key Storage Provider" }
                default { $null }
            }
        }

        # ---- 14. retire: refuses anything but the exact KEK, then deletes it. ----
        #          Doubles as this test's cleanup, so repeated runs don't
        #          accumulate persisted keys.
        $retired = $false
        if ($kekFingerprint) {
            $wrongFp = if ($kekFingerprint.StartsWith("0")) { "1" + $kekFingerprint.Substring(1) } else { "0" + $kekFingerprint.Substring(1) }
            $r = Invoke-Cli @("retire", "-sn", $serviceName, "-fp", $wrongFp)
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "fingerprint mismatch") -and ($r.StdErr -match "nothing was deleted")) "retire refuses a wrong fingerprint"
            $r = Invoke-Cli @("retire", "-sn", $serviceName, "--corrupt")
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "not corrupt; nothing was deleted")) "retire --corrupt refuses a valid KEK"
            if ($providerName) {
                $other = if ($providerName -eq "Microsoft Platform Crypto Provider") { "software" } else { "tpm" }
                $r = Invoke-Cli @("retire", "-sn", $serviceName, "-fp", $kekFingerprint, "--provider", $other)
                Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "no KEK exists .* on the .*; nothing to retire")) "retire --provider looks only on that provider, and finds nothing there"
            }
            $st = Invoke-Cli @("status", "-sn", $serviceName)
            Check ($st.StdOut -match "kek: present") "the refused retires left the KEK in place"

            $retireStart = (Get-Date).AddSeconds(-2)
            $r = Invoke-Cli @("retire", "-sn", $serviceName.ToUpperInvariant(), "-fp", $kekFingerprint.ToUpperInvariant())
            Check (($r.ExitCode -eq 0) -and ($r.StdOut -match "retired KEK for service `"$serviceName`" \(fingerprint $kekFingerprint")) "retire deletes the KEK given its fingerprint (any case, service name normalized)"
            if ($r.ExitCode -ne 0) { Write-Host "    stderr: $($r.StdErr)" }
            $retired = $r.ExitCode -eq 0
            $st = Invoke-Cli @("status", "-sn", $serviceName)
            Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: absent")) "after retire, status reports the KEK absent"
            $evt = Find-HkdfEvent -Since $retireStart -Id 1004 -Needle "'$serviceName'"
            Check ($evt.Count -ge 1) "the retirement is recorded in the Application event log (event 1004)"
            if ($evt.Count -ge 1) {
                Check ([string]$evt[0].Properties[0].Value -match $kekFingerprint) "the retirement event names the KEK's fingerprint"
                Check ($evt[0].UserId.Value -eq $identity.User.Value) "the retirement event records the calling user"
            }
            $r = Invoke-Cli @("retire", "-sn", $serviceName, "-fp", $kekFingerprint)
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "nothing to retire")) "retiring an already-retired KEK reports there is nothing to retire"
        }

        # ---- 15. status and retire against keys this library would never ----
        #          create: planted directly in the software key store under
        #          a service's KEK name with .NET's CngKey (machine scope, as
        #          the library's own keys). They stand in for a corrupt or
        #          tampered KEK. Each scenario removes its own key.
        $cng = "System.Security.Cryptography"
        function Get-KekName([string]$service) { "hkdfguardwin_${service}_v1" }
        function Remove-PlantedKey([string]$service) {
            try {
                $k = [System.Security.Cryptography.CngKey]::Open(
                    (Get-KekName $service), [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,
                    [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)
                $k.Delete()
            } catch { }
        }
        function New-PlantedKey([string]$service, [System.Security.Cryptography.CngAlgorithm]$algorithm, [bool]$exportable) {
            Remove-PlantedKey $service
            $p = New-Object "$cng.CngKeyCreationParameters"
            $p.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
            $p.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
            $p.ExportPolicy = if ($exportable) { [System.Security.Cryptography.CngExportPolicies]::AllowExport } else { [System.Security.Cryptography.CngExportPolicies]::None }
            [System.Security.Cryptography.CngKey]::Create($algorithm, (Get-KekName $service), $p).Dispose()
        }
        # Under RequireTpm the library never looks at the software key store,
        # so what status reports for a planted software key depends on the
        # machine's KeyStoragePolicy. retire looks at both stores directly,
        # whatever the policy.
        $storagePolicy = $null
        try { $storagePolicy = (Get-ItemProperty -Path "HKLM:\Software\Policies\HkdfGuard" -Name KeyStoragePolicy -ErrorAction Stop).KeyStoragePolicy } catch { }
        $libraryReadsSoftware = ($null -eq $storagePolicy) -or ($storagePolicy -eq 0) -or ($storagePolicy -eq 2)

        # 15a. An RSA key under the name: corrupt. retire --fingerprint
        #      refuses it (no fingerprint to confirm); retire --corrupt deletes
        #      it and says the name can be provisioned again.
        $rsaService = "hkdfguardclitestrsa"
        try {
            New-PlantedKey $rsaService ([System.Security.Cryptography.CngAlgorithm]::Rsa) $false
            $st = Invoke-Cli @("status", "-sn", $rsaService)
            if ($libraryReadsSoftware) {
                Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: corrupt \(not a P-256 ECDH key; see retire --corrupt\)")) "status reports an RSA key under the KEK name as corrupt (exit 0)"
                Check ($st.StdOut -match "key under this name: software: a key of algorithm group RSA") "status says what the corrupt key is"
            } else {
                Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: absent") -and ($st.StdOut -match "other key under this name .*software: a key of algorithm group RSA")) "under RequireTpm, status lists the software key as unselected"
            }
            $r = Invoke-Cli @("retire", "-sn", $rsaService, "-fp", ("0" * 64))
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "not a P-256 ECDH key, so it has no fingerprint to confirm; if it is genuinely corrupt, retire it with --corrupt")) "retire --fingerprint refuses a key that has no fingerprint, pointing at --corrupt"
            $corruptStart = (Get-Date).AddSeconds(-2)
            $r = Invoke-Cli @("retire", "-sn", $rsaService, "--corrupt")
            Check (($r.ExitCode -eq 0) -and ($r.StdOut -match "retired KEK for service `"$rsaService`" \(corrupt: a key of algorithm group RSA") -and ($r.StdOut -match "can now be provisioned again")) "retire --corrupt deletes a non-P-256 key and says the name can be provisioned again"
            if ($r.ExitCode -ne 0) { Write-Host "    stderr: $($r.StdErr)" }
            $st = Invoke-Cli @("status", "-sn", $rsaService)
            Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: absent") -and ($st.StdOut -notmatch "key under this name")) "after retire --corrupt, nothing remains under the name"
            $evt = Find-HkdfEvent -Since $corruptStart -Id 1004 -Needle "'$rsaService'"
            Check (($evt.Count -ge 1) -and ([string]$evt[0].Properties[0].Value -match "corrupt: a key of algorithm group RSA")) "a corrupt-key retirement is recorded as event 1004, saying why the key was corrupt"
        } catch {
            Check $false "15a setup: plant an RSA machine key ($($_.Exception.Message))"
        } finally {
            Remove-PlantedKey $rsaService
        }

        # 15b. A P-384 ECDH key: the right algorithm, the wrong size - corrupt too.
        $p384Service = "hkdfguardclitestp384"
        try {
            New-PlantedKey $p384Service ([System.Security.Cryptography.CngAlgorithm]::ECDiffieHellmanP384) $false
            if ($libraryReadsSoftware) {
                $st = Invoke-Cli @("status", "-sn", $p384Service)
                Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: corrupt") -and ($st.StdOut -match "software: a 384-bit ECDH key")) "status reports a P-384 ECDH key under the KEK name as corrupt"
            }
            $r = Invoke-Cli @("retire", "-sn", $p384Service, "--corrupt")
            Check (($r.ExitCode -eq 0) -and ($r.StdOut -match "corrupt: a 384-bit ECDH key")) "retire --corrupt deletes a P-384 ECDH key"
        } catch {
            Check $false "15b setup: plant a P-384 machine key ($($_.Exception.Message))"
        } finally {
            Remove-PlantedKey $p384Service
        }

        # 15c. An exportable P-256 ECDH key: has a fingerprint, but the library
        #      refuses to use it - "unusable". --corrupt refuses it (it is a
        #      valid P-256 key); --fingerprint retires it.
        $exportService = "hkdfguardclitestexport"
        try {
            New-PlantedKey $exportService ([System.Security.Cryptography.CngAlgorithm]::ECDiffieHellmanP256) $true
            $st = Invoke-Cli @("status", "-sn", $exportService)
            $plantedFp = $null
            if ($st.StdOut -match "software: fingerprint ([0-9a-f]{64})") { $plantedFp = $Matches[1] }
            Check ($null -ne $plantedFp) "status prints the fingerprint of a P-256 key it finds under the name"
            if ($libraryReadsSoftware) {
                Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "kek: unusable \(")) "status reports an exportable P-256 key as unusable (exit 0)"
            }
            $r = Invoke-Cli @("retire", "-sn", $exportService, "--corrupt")
            Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "is a valid P-256 ECDH key \(fingerprint $plantedFp\), not corrupt; nothing was deleted")) "retire --corrupt refuses an unusable but valid P-256 key"
            if ($plantedFp) {
                $r = Invoke-Cli @("retire", "-sn", $exportService, "-fp", $plantedFp)
                Check (($r.ExitCode -eq 0) -and ($r.StdOut -match "retired KEK for service `"$exportService`" \(fingerprint $plantedFp")) "retire --fingerprint deletes an unusable P-256 key"
            }
        } catch {
            Check $false "15c setup: plant an exportable P-256 machine key ($($_.Exception.Message))"
        } finally {
            Remove-PlantedKey $exportService
        }

        # 15d. A key on both providers: a TPM KEK (provisioned normally) plus
        #      a P-256 key planted in the software store under the same name.
        #      Only possible where provision lands on the TPM.
        $bothService = "hkdfguardclitestboth"
        $tpmFp = $null
        try {
            $pb = Invoke-Cli @("provision", "-sn", $bothService)
            if ($pb.StdOut -match "fingerprint: ([0-9a-f]{64}) -- ") { $tpmFp = $Matches[1] }
            $st = Invoke-Cli @("status", "-sn", $bothService)
            if ($tpmFp -and $st.StdOut -match "provider: Microsoft Platform Crypto Provider") {
                New-PlantedKey $bothService ([System.Security.Cryptography.CngAlgorithm]::ECDiffieHellmanP256) $false
                $st = Invoke-Cli @("status", "-sn", $bothService)
                $swFp = $null
                if ($st.StdOut -match "other key under this name \(not selected by the KeyStoragePolicy\): software: fingerprint ([0-9a-f]{64})") { $swFp = $Matches[1] }
                Check (($st.ExitCode -eq 0) -and ($st.StdOut -match "fingerprint: $tpmFp") -and $swFp) "status reports the selected TPM KEK and lists the unselected software key"

                $r = Invoke-Cli @("retire", "-sn", $bothService, "-fp", $tpmFp)
                Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "on both providers .*refusing to choose which one to delete -- nothing was deleted") -and ($r.StdErr -match "--provider tpm or --provider software")) "retire refuses to choose between keys on both providers"
                $r = Invoke-Cli @("retire", "-sn", $bothService, "-fp", $tpmFp, "--provider", "software")
                Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "fingerprint mismatch")) "retire --provider software checks the software key's own fingerprint"
                if ($swFp) {
                    $r = Invoke-Cli @("retire", "-sn", $bothService, "-fp", $swFp, "--provider", "software")
                    Check (($r.ExitCode -eq 0) -and ($r.StdOut -match "note: service `"$bothService`" still has a key on the other provider \(tpm: fingerprint $tpmFp\)")) "retiring one provider's key leaves the other, and says so"
                }
                $r = Invoke-Cli @("retire", "-sn", $bothService, "-fp", $tpmFp, "--provider", "tpm")
                Check (($r.ExitCode -eq 0) -and ($r.StdOut -notmatch "still has a key")) "retire --provider tpm then deletes the TPM KEK"
            } else {
                Write-Host "[SKIP] both-providers retire scenario: provision did not create a TPM KEK on this machine"
            }
        } catch {
            Check $false "15d setup ($($_.Exception.Message))"
        } finally {
            Remove-PlantedKey $bothService
            if ($tpmFp) { Invoke-Cli @("retire", "-sn", $bothService, "-fp", $tpmFp) | Out-Null }
        }

        # Fallback cleanup, if retire couldn't run. Full path, not just
        # "certutil" - this test's PATH is whatever ctest baked into its
        # ENVIRONMENT property at configure time (see tests/CMakeLists.txt),
        # which isn't guaranteed to still resolve ordinary system tools.
        if ($providerName -and -not $retired) {
            # Matches kek_store.cpp's KeyName(): every piece is lowercase, and
            # $serviceName is already lowercase.
            $keyName = "hkdfguardwin_${serviceName}_v1"
            $certutilPath = Join-Path $env:SystemRoot "System32\certutil.exe"
            & $certutilPath -csp $providerName -delkey $keyName | Out-Null
        }
    } else {
        Write-Host "[INFO] skipping provision/full-wrap/--force/retire scenarios: not elevated (machine-wide KEK creation requires Administrator)"

        # retire refuses up front without elevation, before looking at any key.
        $r = Invoke-Cli @("retire", "-sn", "hkdfguardclitest", "-fp", ("0" * 64))
        Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "retire must run from an elevated prompt")) "retire without elevation is refused"

        # ---- 13b. Not elevated: a provision attempt is refused, and the ----
        #           refusal is recorded in the Application event log (event
        #           2000, access denied) with the service name. A fresh
        #           service name, so no existing KEK can change the outcome.
        $deniedService = "hkdfguardevt" + [Guid]::NewGuid().ToString("N")
        $deniedStart = (Get-Date).AddSeconds(-2)
        $r = Invoke-Cli @("provision", "--service-name", $deniedService)
        Check ($r.ExitCode -eq 1) "provision without elevation is refused"
        $denied = Find-HkdfEvent -Since $deniedStart -Id 2000 -Needle "'$deniedService'"
        Check ($denied.Count -ge 1) "the refused provision is recorded in the Application event log (event 2000)"
        if ($denied.Count -ge 1) {
            $evt = $denied[0]
            Check ([string]$evt.Properties[0].Value -match "HKDFGUARD_ERR_KEK_ACCESS_DENIED") "the event names the error code"
            Check ($evt.UserId -and $evt.UserId.Value -eq $identity.User.Value) "the event records the calling user"
            Check ($evt.LevelDisplayName -eq "Warning" -or $evt.Level -eq 3) "the event is logged as a warning"
        }
    }
}
finally {
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}

if ($failures -eq 0) {
    Write-Host "`nAll CLI checks passed."
    exit 0
} else {
    Write-Host "`n$failures CLI check(s) failed."
    exit 1
}
