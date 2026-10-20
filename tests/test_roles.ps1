<#
The production security model, checked with real, separate accounts - the
only way to show that the boundary is enforced by Windows and the library
rather than by who happens to run the test. Registered as ctest's "roles"
test; see tests/CMakeLists.txt.

Needs elevation (it creates local accounts and groups, a KEK, and an
administrator-owned key folder); skipped, not failed, otherwise. Also skipped
when this machine's SecurityModel policy is set to anything but production,
since that is the model under test.

The roles, as an administrator deploys them:
  security admin   - this elevated process: provisions the KEK and retires it.
  deployer         - a throwaway account in HkdfGuardDeployers: may persist
                     key files, and wrap/unwrap.
  application      - a throwaway account in HkdfGuardUsers: may unwrap, and
                     wrap ephemeral keys in memory, but must not be able to
                     persist a key file its own service would accept.

Key folder layout (the one docs/admin-guide.md describes): a folder under
C:\ owned by Administrators, full control for SYSTEM and Administrators,
Modify for HkdfGuardDeployers, read for HkdfGuardUsers. Each step runs the
CLI or role_probe.exe (the public ABI) as the account it is about.

Everything created is removed afterwards: the accounts, any group this test
had to create, the folders, and the KEK (retired by fingerprint).
#>
param(
    [Parameter(Mandatory = $true)][string]$CliExePath,
    [Parameter(Mandatory = $true)][string]$ProbeExePath,
    [Parameter(Mandatory = $true)][string]$DllPath
)

# Windows PowerShell started from PowerShell 7 (or by a tool that passes
# PowerShell 7's PSModulePath along) can't auto-load its own modules, so the
# two this script uses are imported by full path.
foreach ($module in "Microsoft.PowerShell.Security", "Microsoft.PowerShell.LocalAccounts") {
    $path = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules\$module"
    if (Test-Path -LiteralPath $path) { Import-Module $path -ErrorAction SilentlyContinue }
}

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

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[SKIP] role checks: not elevated (they create local accounts, groups and a KEK)"
    exit 0
}
$model = $null
try { $model = (Get-ItemProperty -Path "HKLM:\Software\Policies\HkdfGuard" -Name SecurityModel -ErrorAction Stop).SecurityModel } catch { }
if ($null -ne $model -and $model -ne 0) {
    Write-Host "[SKIP] role checks: this machine's SecurityModel policy is $model, not production"
    exit 0
}

$tag = [Guid]::NewGuid().ToString("N").Substring(0, 6)
$service = "hkdfguardroles$tag"
$root = "C:\HkdfGuardRoleTest-$tag"
$plantDir = "C:\HkdfGuardRolePlant-$tag"
$bin = Join-Path $root "bin"
$keys = Join-Path $root "keys"
$out = Join-Path $root "out"
$keyFile = Join-Path $keys "service.key"
$depName = "hkdfgdep$tag"
$appName = "hkdfgapp$tag"
$createdGroups = @()
$createdUsers = @()
$fingerprint = $null

# A password that meets any complexity policy, never written anywhere.
function New-Password {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ([Convert]::ToBase64String($bytes) -replace '[+/=]', 'x') + "Aa1!"
}

# Runs $FilePath as $Credential with $Arguments, stdin from $StdIn (text, or
# nothing), and returns its exit code and output. Output is captured to files
# in $out, which only Administrators can read: the parent opens them.
function Invoke-As {
    param([System.Management.Automation.PSCredential]$Credential, [string]$FilePath, [string[]]$Arguments, [string]$StdIn = "")
    $id = [Guid]::NewGuid().ToString("N")
    $inFile = Join-Path $out "$id.in"; $outFile = Join-Path $out "$id.out"; $errFile = Join-Path $out "$id.err"
    [System.IO.File]::WriteAllText($inFile, $StdIn)
    $quoted = $Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
    $p = Start-Process -FilePath $FilePath -ArgumentList $quoted -Credential $Credential -WorkingDirectory $bin `
        -RedirectStandardInput $inFile -RedirectStandardOutput $outFile -RedirectStandardError $errFile `
        -NoNewWindow -Wait -PassThru
    $result = [PSCustomObject]@{
        ExitCode = $p.ExitCode
        StdOut   = (Get-Content -Raw -ErrorAction SilentlyContinue $outFile) + ""
        StdErr   = (Get-Content -Raw -ErrorAction SilentlyContinue $errFile) + ""
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $inFile, $outFile, $errFile
    return $result
}

function Set-ProtectedAcl([string]$Path, [string]$Sddl) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

try {
    # ---- Groups and accounts. ----
    foreach ($group in "HkdfGuardUsers", "HkdfGuardDeployers") {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $group -Description "created by hkdfguard test_roles.ps1" | Out-Null
            $createdGroups += $group
        }
    }
    $depPassword = ConvertTo-SecureString (New-Password) -AsPlainText -Force
    $appPassword = ConvertTo-SecureString (New-Password) -AsPlainText -Force
    New-LocalUser -Name $depName -Password $depPassword -Description "hkdfguard role test: deployer" -AccountNeverExpires | Out-Null
    $createdUsers += $depName
    New-LocalUser -Name $appName -Password $appPassword -Description "hkdfguard role test: application" -AccountNeverExpires | Out-Null
    $createdUsers += $appName
    Add-LocalGroupMember -Group "HkdfGuardDeployers" -Member $depName
    Add-LocalGroupMember -Group "HkdfGuardUsers" -Member $appName
    $dep = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$depName", $depPassword)
    $app = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$appName", $appPassword)

    # ---- Folders: binaries everyone may run, an admin-only capture folder, ----
    #      and the key folder.
    New-Item -ItemType Directory -Path $root, $bin, $keys, $out | Out-Null
    Set-ProtectedAcl $root "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
    Set-ProtectedAcl $out "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    $deployers = (Get-LocalGroup -Name "HkdfGuardDeployers").SID.Value
    $users = (Get-LocalGroup -Name "HkdfGuardUsers").SID.Value
    Set-ProtectedAcl $keys "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$deployers)(A;OICI;0x1200a9;;;$users)"
    foreach ($file in $CliExePath, $ProbeExePath, $DllPath) { Copy-Item -LiteralPath $file -Destination $bin }
    $cli = Join-Path $bin (Split-Path -Leaf $CliExePath)
    $probe = Join-Path $bin (Split-Path -Leaf $ProbeExePath)

    # ---- Security admin: provision, after the groups exist, so the KEK's ----
    #      ACL grants both of them key use.
    $env:PATH = "$bin;$env:PATH"
    $pr = & $cli provision --service-name $service 2>&1 | Out-String
    Check ($LASTEXITCODE -eq 0) "security admin provisions the service's KEK"
    if ($pr -match "fingerprint: ([0-9a-f]{64})") { $fingerprint = $Matches[1] }

    # ---- Deployer. ----
    $r = Invoke-As $dep $probe @("model")
    Check ($r.StdOut -match "model=0 may_write=1 rc=0") "deployer: production model, and may persist key files"
    if ($r.StdOut -notmatch "may_write=1") { Write-Host "    $($r.StdOut) $($r.StdErr)" }

    $dekBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes)
    $r = Invoke-As $dep $cli @("wrap", "-kf", $keyFile, "-sn", $service, "--dek-stdin", "-g", "HkdfGuardUsers") -StdIn ([Convert]::ToBase64String($dekBytes))
    Check (($r.ExitCode -eq 0) -and (Test-Path -LiteralPath $keyFile)) "deployer: wrap persists a key file in the key folder"
    if ($r.ExitCode -ne 0) { Write-Host "    stderr: $($r.StdErr)" }
    $owner = (Get-Acl -LiteralPath $keyFile -ErrorAction SilentlyContinue).Owner
    Check ($owner -like "*\$depName") "deployer: the key file is owned by the deployer's own account (not Administrators)"

    $r = Invoke-As $dep $probe @("unwrap", $service, $keyFile)
    Check ($r.StdOut -match "open=0 unwrap=0") "deployer: may unwrap the key file it deployed"

    # ---- Application runner. ----
    $r = Invoke-As $app $probe @("model")
    Check ($r.StdOut -match "model=0 may_write=0 rc=0") "application: production model, and may not persist key files"

    $r = Invoke-As $app $probe @("unwrap", $service, $keyFile)
    Check ($r.StdOut -match "open=0 unwrap=0") "application: reads and unwraps the deployer's key file (a deployer group member's file is trusted)"
    if ($r.StdOut -notmatch "open=0 unwrap=0") { Write-Host "    $($r.StdOut) $($r.StdErr)" }

    $r = Invoke-As $app $probe @("ephemeral", $service)
    Check ($r.StdOut -match "generate=0 unwrap=0 wrap=0 unwrap2=0") "application: wraps and unwraps ephemeral keys in memory"
    if ($r.StdOut -notmatch "generate=0 unwrap=0 wrap=0 unwrap2=0") { Write-Host "    $($r.StdOut) $($r.StdErr)" }

    $appKey = Join-Path $keys "app.key"
    $r = Invoke-As $app $cli @("wrap", "-kf", $appKey, "-sn", $service, "--dek-stdin") -StdIn ([Convert]::ToBase64String($dekBytes))
    Check (($r.ExitCode -eq 1) -and ($r.StdErr -match "may not persist key files") -and -not (Test-Path -LiteralPath $appKey)) "application: the CLI refuses to persist a key file for it, and writes nothing"
    if ($r.StdErr -notmatch "may not persist") { Write-Host "    stderr: $($r.StdErr)" }

    $r = Invoke-As $app $probe @("overwrite", $keyFile)
    Check ($r.StdOut -match "write=5") "application: Windows refuses it write access to the deployed key file (ERROR_ACCESS_DENIED)"

    # Bypassing the CLI: a key file the application persists itself, in a
    # folder it creates at the drive root (any user may), is refused by
    # hkdfguard_open_file - its own files aren't trusted in production.
    $r = Invoke-As $app $probe @("plant", $keyFile, $plantDir, "planted.key")
    Check ($r.StdOut -match "mkdir=0 write=0") "application: can write a copy of a key file somewhere it may write"
    $r = Invoke-As $app $probe @("open", (Join-Path $plantDir "planted.key"))
    Check ($r.StdOut -match "open=-39") "application: hkdfguard_open_file refuses the key file it persisted itself (FILE_UNTRUSTED)"
    if ($r.StdOut -notmatch "open=-39") { Write-Host "    $($r.StdOut) $($r.StdErr)" }

    # Membership is read when the file is opened: no longer a deployer, the
    # deployer's files are no longer trusted.
    Remove-LocalGroupMember -Group "HkdfGuardDeployers" -Member $depName
    $r = Invoke-As $app $probe @("open", $keyFile)
    Check ($r.StdOut -match "open=-39") "application: once its author leaves HkdfGuardDeployers, the key file is refused"
}
catch {
    Check $false "role test setup or run: $($_.Exception.Message)"
}
finally {
    if ($fingerprint) {
        & $CliExePath retire --service-name $service --fingerprint $fingerprint 2>&1 | Out-Null
        Check ($LASTEXITCODE -eq 0) "cleanup: the security admin retires the test KEK"
    }
    foreach ($user in $createdUsers) { Remove-LocalUser -Name $user -ErrorAction SilentlyContinue }
    foreach ($group in $createdGroups) { Remove-LocalGroup -Name $group -ErrorAction SilentlyContinue }
    foreach ($dir in $root, $plantDir) { if (Test-Path -LiteralPath $dir) { Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue } }
}

if ($failures -eq 0) {
    Write-Host "`nAll role checks passed."
    exit 0
} else {
    Write-Host "`n$failures role check(s) failed."
    exit 1
}
