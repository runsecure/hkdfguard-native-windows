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

# This script uses no PowerShell module - not LocalAccounts (Get-LocalGroup
# and friends) nor Security (Get-Acl / Set-Acl). A Windows PowerShell that
# ctest starts from a PowerShell 7 session can fail to load either, even when
# imported by full path. Accounts and groups go through ADSI (WinNT://) and
# file permissions through .NET's ACL API, both always present.

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
    Write-Host "[SKIP] role checks: this machine's SecurityModel policy is $model, not production. If that isn't deliberate, an interrupted test run may have left it: remove HKLM\Software\Policies\HkdfGuard\SecurityModel." -ForegroundColor Yellow
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

# ---- Local accounts and groups, through ADSI. ----
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
# A SecureString for a PSCredential, built directly (ConvertTo-SecureString
# lives in the Security module).
function ConvertTo-Secure([string]$Plain) {
    $secure = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    return $secure
}
# DirectoryEntry.Exists actually checks; binding [ADSI] to a missing name
# returns a placeholder instead of failing.
function Test-LocalGroupExists([string]$Name) {
    return [System.DirectoryServices.DirectoryEntry]::Exists("WinNT://$env:COMPUTERNAME/$Name,group")
}
function New-TestLocalGroup([string]$Name) {
    $group = $computer.Create("group", $Name)
    $group.Put("description", "created by hkdfguard test_roles.ps1")
    $group.SetInfo()
}
# The password is set through ADSI, never on a command line.
function New-TestLocalUser([string]$Name, [string]$Password, [string]$Description) {
    $user = $computer.Create("user", $Name)
    $user.SetPassword($Password)
    $user.Put("description", $Description)
    $user.SetInfo()
}
function Add-TestGroupMember([string]$Group, [string]$User) {
    ([ADSI]"WinNT://$env:COMPUTERNAME/$Group,group").Add("WinNT://$env:COMPUTERNAME/$User,user")
}
function Remove-TestGroupMember([string]$Group, [string]$User) {
    ([ADSI]"WinNT://$env:COMPUTERNAME/$Group,group").Remove("WinNT://$env:COMPUTERNAME/$User,user")
}
function Get-GroupSid([string]$Name) {
    return (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

# ---- File permissions, through .NET. PowerShell 7 exposes them as
#      FileSystemAclExtensions, Windows PowerShell as instance methods. ----
$aclExtensions = [Type]::GetType("System.IO.FileSystemAclExtensions, System.IO.FileSystem.AccessControl", $false)
# Sets a folder's owner and DACL from SDDL (no SACL, which would need
# SeSecurityPrivilege).
function Set-ProtectedAcl([string]$Path, [string]$Sddl) {
    $info = New-Object System.IO.DirectoryInfo($Path)
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($Sddl, [System.Security.AccessControl.AccessControlSections]"Owner, Access")
    if ($aclExtensions) { $aclExtensions::SetAccessControl($info, $security) } else { $info.SetAccessControl($security) }
}
function Get-FileOwnerName([string]$Path) {
    $info = New-Object System.IO.FileInfo($Path)
    $security = if ($aclExtensions) { $aclExtensions::GetAccessControl($info) } else { $info.GetAccessControl() }
    return $security.GetOwner([System.Security.Principal.NTAccount]).Value
}

try {
    # ---- Groups and accounts. ----
    foreach ($group in "HkdfGuardUsers", "HkdfGuardDeployers") {
        if (-not (Test-LocalGroupExists $group)) {
            New-TestLocalGroup $group
            $createdGroups += $group
        }
    }
    $depPlain = New-Password
    $appPlain = New-Password
    $depPassword = ConvertTo-Secure $depPlain
    $appPassword = ConvertTo-Secure $appPlain
    New-TestLocalUser $depName $depPlain "hkdfguard role test: deployer"
    $createdUsers += $depName
    New-TestLocalUser $appName $appPlain "hkdfguard role test: application"
    $depPlain = $null; $appPlain = $null
    $createdUsers += $appName
    Add-TestGroupMember "HkdfGuardDeployers" $depName
    Add-TestGroupMember "HkdfGuardUsers" $appName
    $dep = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$depName", $depPassword)
    $app = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$appName", $appPassword)

    # ---- Folders: binaries everyone may run, an admin-only capture folder, ----
    #      and the key folder.
    New-Item -ItemType Directory -Path $root, $bin, $keys, $out | Out-Null
    Set-ProtectedAcl $root "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
    Set-ProtectedAcl $out "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    $deployers = Get-GroupSid "HkdfGuardDeployers"
    $users = Get-GroupSid "HkdfGuardUsers"
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
    $owner = try { Get-FileOwnerName $keyFile } catch { $null }
    Check ($owner -like "*\$depName") "deployer: the key file is owned by the deployer's own account (not Administrators)"

    $r = Invoke-As $dep $probe @("unwrap", $service, $keyFile)
    Check ($r.StdOut -match "open=0 unwrap=0") "deployer: may unwrap the key file it deployed"

    # The next release: the deployer replaces its own key file in place with
    # `wrap --force` - which overwrites, then deletes, the old file before
    # writing the new one - not elevated, as a deployer runs it.
    $before = [System.IO.File]::ReadAllBytes($keyFile)
    $nextDek = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nextDek)
    $r = Invoke-As $dep $cli @("wrap", "-kf", $keyFile, "-sn", $service, "--dek-stdin", "-g", "HkdfGuardUsers", "--force") -StdIn ([Convert]::ToBase64String($nextDek))
    $after = if (Test-Path -LiteralPath $keyFile) { [System.IO.File]::ReadAllBytes($keyFile) } else { $null }
    Check (($r.ExitCode -eq 0) -and $after -and -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$before, [byte[]]$after)) "deployer: wrap --force replaces its own key file with the next release's"
    if ($r.ExitCode -ne 0) { Write-Host "    stderr: $($r.StdErr)" }
    $r = Invoke-As $dep $probe @("unwrap", $service, $keyFile)
    Check ($r.StdOut -match "open=0 unwrap=0") "deployer: the replaced key file reads and unwraps"

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
    Remove-TestGroupMember "HkdfGuardDeployers" $depName
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
    foreach ($user in $createdUsers) { try { $computer.Delete("user", $user) } catch { Write-Host "[WARN] could not remove test account ${user}: $($_.Exception.Message)" } }
    foreach ($group in $createdGroups) { try { $computer.Delete("group", $group) } catch { Write-Host "[WARN] could not remove group ${group}: $($_.Exception.Message)" } }
    foreach ($dir in $root, $plantDir) { if (Test-Path -LiteralPath $dir) { Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue } }
}

if ($failures -eq 0) {
    Write-Host "`nAll role checks passed."
    exit 0
} else {
    Write-Host "`n$failures role check(s) failed."
    exit 1
}
