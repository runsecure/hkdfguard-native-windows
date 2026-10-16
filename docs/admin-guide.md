# Installation and Administration Guide

This guide is for administrators who install hkdfguard-native-windows on Windows machines
and manage the keys it protects. For building from source, the C API, and design details,
see the [README](../README.md).

> **Pre-release:** version 0.9.x is for pre-release testing. Releases numbered `v0.x.y`
> are marked as pre-releases on the GitHub Releases page.

## Contents

- [What it is](#what-it-is)
- [Requirements](#requirements)
- [Download and verify](#download-and-verify)
- [Install](#install)
- [Set up a service](#set-up-a-service)
- [Machine policy settings](#machine-policy-settings)
- [Monitoring and auditing](#monitoring-and-auditing)
- [Upgrade](#upgrade)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

## What it is

hkdfguard-native-windows protects a 32-byte data encryption key (DEK) by wrapping it with a
key encryption key (KEK) that never leaves the machine. Each KEK is a non-exportable
machine key, held by the TPM when one is available, or by the Windows software key store
otherwise.

You install two files:

| File | Used by | Purpose |
|---|---|---|
| `HkdfGuard.dll` | Applications | Wraps and unwraps DEKs. Applications load it at runtime. |
| `hkdfguard.exe` | Administrators | Creates a service's KEK (`provision`) and wraps a DEK to a file (`wrap`). |

The usual flow is:

1. **Once per machine:** install the MSI.
2. **Once per service:** an administrator provisions that service's KEK.
3. **Every release:** a deployment step wraps a fresh DEK into a key file.
4. **At runtime:** the service's account unwraps the key file through the DLL.

## Requirements

- 64-bit Windows, x64 or ARM64. Pick the MSI that matches the processor architecture of
  the applications that will load the DLL. An x64 process can't load the ARM64 DLL, and
  an ARM64 process can't load the x64 DLL. 32-bit processes aren't supported.
- Administrator rights to install, and to provision each service's KEK.
- A TPM is optional. Without one, keys are held by the Microsoft Software Key Storage
  Provider, unless policy requires a TPM (see [`KeyStoragePolicy`](#keystoragepolicy)).

## Download and verify

Download from the repository's
[Releases page](https://github.com/runsecure/hkdfguard-native-windows/releases). Each
release has:

| Asset | Contents |
|---|---|
| `hkdfguard-native-windows-<version>-win-x64.msi` | Installer for x64 |
| `hkdfguard-native-windows-<version>-win-arm64.msi` | Installer for ARM64 |
| `hkdfguard-native-windows-v<version>-win-x64.zip` / `-win-arm64.zip` | The two binaries, unpackaged |
| `*.sha256` | SHA-256 checksum of each file above |

Before installing, check that the MSI is validly signed and timestamped, and that its
checksum matches:

```powershell
$msi = ".\hkdfguard-native-windows-0.9.0-win-x64.msi"

# Status must be "Valid", and TimeStamperCertificate must not be empty.
Get-AuthenticodeSignature $msi | Format-List Status, SignerCertificate, TimeStamperCertificate

# Must match the contents of the .sha256 file.
(Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
Get-Content "$msi.sha256"
```

Each release also carries a build provenance attestation, which shows that the file was
built by this repository's release workflow. If you have the GitHub CLI installed, you can
check it with:

```powershell
gh attestation verify $msi --repo runsecure/hkdfguard-native-windows
```

> MSIs built by CI runs, from a run's "Artifacts" section, are **unsigned** and for
> testing only. Don't deploy them.

## Install

The MSI installs for the whole machine and must run elevated.

**Interactive:** double-click the MSI and accept the UAC prompt.

**Silent:** from an elevated prompt.

```powershell
msiexec /i hkdfguard-native-windows-0.9.0-win-x64.msi /qn /l*v install.log
```

You can deploy the same command as-is through Intune, Configuration Manager (SCCM) or
Group Policy software installation. Exit code `0` means success and `3010` means success
with a restart required. For anything else, see `install.log`.

### What the installer changes

| Change | Detail |
|---|---|
| Files | `C:\Program Files\HkdfGuard\HkdfGuard.dll` and `hkdfguard.exe`. The folder inherits the Program Files ACL, so only Administrators, SYSTEM and TrustedInstaller can write to it. The location can't be changed. |
| Registry | `HKLM\Software\hkdfguard-native-windows`, value `InstallPath` (`REG_SZ`). Applications read it to find the DLL. |
| Event log | Registers the Application log source `hkdfguard-native-windows`. |
| Local group | Creates `HkdfGuardUsers` if it doesn't already exist. |

The installer doesn't set any policy values. Those are left to whatever already manages
machine policy, such as Group Policy, Intune or SCCM.

### Check the install

```powershell
Get-ItemProperty HKLM:\Software\hkdfguard-native-windows | Select-Object InstallPath
Get-ChildItem "C:\Program Files\HkdfGuard"
net localgroup HkdfGuardUsers
& "C:\Program Files\HkdfGuard\hkdfguard.exe" --help
```

## Set up a service

A **service name** identifies one KEK, for example `myapp` or `contoso.billing`. Service
names may contain only ASCII letters, digits and `.`, may not start with `.` or contain `..`, are 1 to 128
characters long, and are
case-insensitive. The same name must be used to wrap and to unwrap.

### 1. Decide who can use the key

A KEK's access list is fixed **when the KEK is created**. Set up groups and policy *before*
provisioning.

| Who | Access | How they get it |
|---|---|---|
| SYSTEM, `BUILTIN\Administrators` | Full control | Always |
| Local group `HkdfGuardAdmins` | Full control | Only if the group exists when the KEK is created. The installer doesn't create it. |
| Local group `HkdfGuardUsers` | Use (wrap and unwrap) | If the group exists when the KEK is created. The installer creates it. |
| Groups listed in [`KeyUseGroups`](#keyusegroups) | Use (wrap and unwrap) | Policy in force when the KEK is created |

Usually you add the service's account to `HkdfGuardUsers`:

```powershell
net localgroup HkdfGuardUsers "NT SERVICE\MyAppService" /add
```

Because the KEK's access list names the group, you can change who has access later by
changing the group's membership. You don't need a new KEK. A running service only picks up
a new group membership after it restarts.

`HkdfGuardAdmins` is optional and for delegating key administration: its members get full
control of every KEK created while the group exists, including the ability to delete those
KEKs, without being local administrators. Most deployments don't need it, since
Administrators and SYSTEM already have full control. If you do, create it **before**
provisioning any service, because a KEK's access list is fixed when it's created:

```powershell
net localgroup HkdfGuardAdmins /add
net localgroup HkdfGuardAdmins "CONTOSO\KeyAdmin" /add
```

Both groups must be local groups on this machine. The installer never creates
`HkdfGuardAdmins`.

> Don't delete and recreate `HkdfGuardUsers` or `HkdfGuardAdmins`. A recreated group gets a
> new SID, so its members would silently lose access to every KEK created earlier.

### 2. Provision the KEK (elevated, once per service)

```powershell
& "C:\Program Files\HkdfGuard\hkdfguard.exe" provision --service-name myapp
```

`provision` creates the KEK if it's missing. If the KEK already exists, `provision` checks
its properties and access list and changes nothing, so it's safe to run on every
deployment.

There is no key rotation. If you need a new KEK, provision a new, versioned service name
(for example `myapp.v2`) and wrap new DEKs under it. **Never delete a KEK that is still
needed.** Deleting it makes every DEK wrapped under it unrecoverable.

### 3. Wrap a DEK into a key file (every release)

`wrap` uses an existing KEK and never creates one. It reads the DEK as base64 from
**stdin**, so the key never appears on a command line. The key file's ACL lets the owner
read and write and no one else (the owner is Administrators when `wrap` runs elevated).
The optional `--group` adds one group that can only read it. Use it when the application
runs as a different account, and use a dedicated group whose members are only the
service's account. Without `--group`, only the owner can read the file, so an
application running as another account can't open it.

```powershell
$exe = "C:\Program Files\HkdfGuard\hkdfguard.exe"

# One-time: a group for the account that reads the key file.
net localgroup App_1234 /add
net localgroup App_1234 "NT SERVICE\MyAppService" /add

# Every release: generate a random 32-byte DEK and wrap it.
$dek = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dek)
[Convert]::ToBase64String($dek) | & $exe wrap `
    --key-file-path C:\ProgramData\myapp\myapp.key --service-name myapp `
    --dek-stdin --group App_1234 --force
```

`--force` overwrites an existing key file. The wrapped file is always 132 bytes. The key
file must be on a real local path. Symbolic links, junctions, SUBST drives, mapped network
drives and hard-linked files are refused, and so are 8.3 short names such as `PROGRA~1`:
spell every folder with its full name. Don't build the path from `%TEMP%` or another
environment variable without expanding it first: Windows can set those variables with short
names (for example `C:\Users\RUNNER~1\AppData\Local\Temp` on GitHub-hosted runners), and a
path containing one is refused.

**Where to keep the key file.** Applications read it back through the library with the
same rules, so the path must be a plain local NTFS folder, for example
`C:\ProgramData\<app>\`. In addition to links and network paths, the
library refuses files on volumes with **Data Deduplication** enabled and **cloud
placeholder files** (OneDrive, Dropbox and similar), because Windows stores both as
reparse points. An application that hits this reports `HKDFGUARD_ERR_FILE_UNTRUSTED`
(-39). Move the file to a plain local folder and wrap it again there.

Configure applications with the key file's **full long path**, the same one you passed to
`wrap`. If an application builds the path from `%TEMP%`, `%USERPROFILE%` or another
environment variable, it must expand it to its long form first with the Windows
`GetLongPathNameW` function, or the library refuses it with -39. Don't assume a framework's
path helpers do this: some keep short names (PowerShell's `Resolve-Path`, for one).

**Who may own and change the folder.** The library also refuses the file with -39 unless
the file and every folder above it, up to the drive root, are owned by SYSTEM,
Administrators, TrustedInstaller or the account the application runs as, and no other
account may write the file or delete, rename, re-permission or take ownership of it or of
any of those folders. Read access for other accounts is fine, and so is a folder that lets
others create new files but not delete existing ones. A folder you create under
`C:\ProgramData` as an administrator passes. A folder created directly under `C:\` (such as
`C:\secrets`) does not: it inherits `Authenticated Users: Modify`, which lets any signed-in
user rename the folder away and put their own in its place. Narrow it first:

```powershell
icacls C:\secrets /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "App_1234:(OI)(CI)RX"
```

If the key file was written by `wrap` run without elevation, it is owned by that user, and
an application running as a different account refuses it. Run `wrap` elevated, or as the
application's own account.

Protect the key file. An older key file for the same service still unwraps, so anyone who
can replace the file can roll it back to an earlier DEK.

### 4. Unwrap at runtime

Applications unwrap the key file by calling `hkdfguard_unwrap_dek` in `HkdfGuard.dll`.
The command-line tool has no unwrap command. Applications must load the DLL by the full
path built from the `InstallPath` registry value, never by bare file name. See
[Consuming from other languages](../README.md#consuming-from-other-languages) in the README.

## Machine policy settings

All four settings are values under `HKLM\Software\Policies\HkdfGuard`. Set them with Group
Policy, Intune or SCCM, or with `reg add` for testing. They're read on every call, so a
change takes effect without a restart.

### KeyStoragePolicy

`REG_DWORD`. Selects where KEKs are stored.

| Value | Name | Behavior |
|---|---|---|
| absent or `0` | PreferTpm | Use the TPM if it's available, otherwise the software key store. |
| `1` | RequireTpm | TPM only. Fails rather than falling back, and refuses to unwrap payloads protected by a software KEK. |
| `2` | SoftwareOnly | Always use the software key store. |

Any other value, or a value of the wrong type, makes **every call fail** with
`invalid key storage policy`. It isn't treated as the default.

The policy also decides where an existing KEK is *looked for*. Changing it after keys
exist can make those keys unreachable. For example, switching to `RequireTpm` blocks KEKs
held in the software key store.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v KeyStoragePolicy /t REG_DWORD /d 1 /f
```

### KeyUseGroups

`REG_MULTI_SZ`. Extra groups that are granted use access on **newly created** KEKs. The
setting doesn't affect KEKs that already exist. Each entry must be a group name or an
`S-1-...` SID that:

- resolves to a real group, not a user account;
- is host-local, meaning in this machine's own accounts, `BUILTIN`, `NT AUTHORITY` or
  `NT SERVICE`. Domain groups are refused, even on a domain-joined machine;
- isn't over-broad. `Everyone`, `Authenticated Users`, `BUILTIN\Users`, `BUILTIN\Guests`,
  `NT AUTHORITY\Local account`, `NT SERVICE\ALL SERVICES`, `This Organization`, the
  logon-type groups, and the anonymous and NULL principals are all refused.

One invalid entry makes provisioning fail, and no KEK is created.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v KeyUseGroups /t REG_MULTI_SZ /d "App_1234\0App_5678" /f
```

### AuditUnwrapSuccess

`REG_DWORD`. Only an explicit `0` turns off the "DEK unwrapped" event (1003), for example
for an application that unwraps often. Every other event, including failed unwraps, is
always logged.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v AuditUnwrapSuccess /t REG_DWORD /d 0 /f
```

### SetupMinDelayMs

`REG_DWORD`, in milliseconds. The minimum time each setup call (`hkdfguard_create_kek`,
`hkdfguard_kek_exists`) takes, whatever its outcome. Setup calls also run one at a time.
This limits how hard a misbehaving application can drive the TPM. Wrapping and unwrapping
are never slowed.

| Value | Behavior |
|---|---|
| absent | 1000 ms. |
| `0` to `60000` | That many milliseconds. `0` turns the delay off. |
| anything else (above `60000`, or the wrong type) | 1000 ms, the same as absent. |

Provisioning with the CLI makes two setup calls, so it takes about two seconds.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v SetupMinDelayMs /t REG_DWORD /d 1000 /f
```

## Monitoring and auditing

Events go to the Windows **Application** log, source `hkdfguard-native-windows`. Each
event names the operation, the service, the result and the calling process. The event's
User field is the calling account.

| ID | Level | Meaning |
|---|---|---|
| 1000 | Information | A KEK was created. |
| 1001 | Warning | A KEK was created in the software key store because the TPM couldn't be used under `PreferTpm`. It isn't hardware-protected. |
| 1002 | Information | A DEK was wrapped. |
| 1003 | Information | A DEK was unwrapped. |
| 2000 | Warning | Access denied: an unauthorized account used a KEK, or provisioning ran without elevation. |
| 2002 | Error | An existing KEK has an access list this library would never create. **Investigate.** |
| 2003 | Warning | Unwrap rejected a tampered, corrupted or misdirected payload. |
| 2004 | Error | Policy is misconfigured (`KeyStoragePolicy` or `KeyUseGroups`), so calls fail. |
| 2005 | Error | The key store or cryptography layer failed. |
| 2006 | Error | An application asked the library to read a key file that looks like an *unwrapped* key (32 raw bytes, or its hex or base64), so it may be a plaintext key on disk. The event names the file; none of its contents are logged. **Investigate**, remove the file and re-mint that DEK. |
| 2007 | Warning | An application made more than 10 setup calls (`create_kek` / `kek_exists`) in one process. These should run once at startup; it is probably calling them per request. Logged once per process. |

Wrap and unwrap events include a SHA-256 of the wrapped payload, so each unwrap can be
traced to the wrap that produced it. To compare against a key file:
`(Get-FileHash C:\ProgramData\myapp\myapp.key -Algorithm SHA256).Hash.ToLower()`.

```powershell
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='hkdfguard-native-windows']]]" -MaxEvents 50 |
    Format-Table TimeCreated, Id, LevelDisplayName, UserId, Message -Wrap
```

Any local user can write to the Application log, so treat these events as an operational
aid, not tamper-proof evidence. Forward them to your SIEM for retention and alerting. Events
2002, 2006, 2003 and 1001 are good candidates for alerts.

## Upgrade

Install the newer MSI the same way as the first install. It removes the previous version
first. Existing KEKs, key files, groups and policy settings aren't affected.

Applications that have the DLL loaded keep it locked. Stop those services before
upgrading, or Windows Installer will ask to close them or schedule a restart. Installing an
older version over a newer one is blocked.

## Uninstall

```powershell
msiexec /x hkdfguard-native-windows-0.9.0-win-x64.msi /qn /l*v uninstall.log
```

You can also uninstall from **Settings → Apps**. Uninstalling removes the files, the
`InstallPath` value and the event source registration. It deliberately keeps:

- **All KEKs.** Deleting a KEK destroys every DEK wrapped under it.
- **The `HkdfGuardUsers` group.** A recreated group would get a new SID and lose access to
  existing KEKs.
- **Policy values** under `HKLM\Software\Policies\HkdfGuard`.

## Troubleshooting

The command-line tool exits with `0` on success, `2` for a usage or argument error (nothing
was attempted) and `1` for an operational failure. On failure it prints an `error:` line.

| Message contains | Likely cause | What to do |
|---|---|---|
| `no KEK is provisioned for this service` | `wrap` ran before `provision`, or the service name differs. | Run `provision` elevated with the same service name. |
| `this account is not authorized to use it` | Not elevated during `provision`, or the account isn't in a group on the KEK's access list. | Run `provision` from an elevated prompt. For `wrap`/unwrap, add the account to `HkdfGuardUsers` and restart the service. |
| `a KeyUseGroups policy entry is unresolvable, not a group, over-broad, or not host-local` | A `KeyUseGroups` entry is invalid. | Fix the entry. See [KeyUseGroups](#keyusegroups). |
| `invalid key storage policy` | `KeyStoragePolicy` isn't a `REG_DWORD` of `0`, `1` or `2`. | Correct or remove the value. |
| `KEK provider/key open or create failed` | Under `RequireTpm`: no usable TPM. Otherwise, the key store failed. | Check the TPM (`Get-Tpm`) and event 2005 for details. |
| `a KEK already exists under this service name, but its ACL is ...` | The existing KEK's access list was changed, or a key was planted under that name. It was left untouched. | Investigate it as a security event. To move on, provision a new versioned service name. |
| `wrapped payload was not produced under this service's current KEK` | The key file belongs to a different service or a different KEK. | Check the service name, and that the file was wrapped on this machine. |
| `service name is missing or malformed` | The name uses characters other than ASCII letters, digits and `.`, starts with `.`, contains `..`, or is longer than 128. | Use a valid name. |

An application that can't load the DLL usually has an architecture mismatch (see
[Requirements](#requirements)) or is loading by bare file name instead of the
`InstallPath` location.

Applications that read the key file through the library may report these codes, which the
command-line tool itself never produces:

| Code | Meaning | What to do |
|---|---|---|
| -39 `FILE_UNTRUSTED` | The key file's path is a link, passes through a junction or SUBST drive, uses an 8.3 short name (`PROGRA~1`), is on a network or deduplicated volume, or is a cloud placeholder. Or the file or a folder above it is owned by, or can be changed, deleted or renamed by, an account other than SYSTEM, Administrators, TrustedInstaller or the application's own. | Configure the application with the full long path (if it comes from `%TEMP%` or another environment variable, expand it first), or move the file to a plain local folder. For an ownership or permissions refusal, narrow the folder's permissions or re-run `wrap` elevated. See [Where to keep the key file](#3-wrap-a-dek-into-a-key-file-every-release). |
| -38 `FILE_MALFORMED` | The file is 132 bytes but does not hold a valid wrapped key (corrupted, edited, or not a key file at all). | Re-run `wrap` to rewrite the file. |
| -37 `FILE_PLAINTEXT_KEY` | The file is 32 raw bytes, or 32 bytes as hex or base64: probably an unwrapped key on disk. Event 2006 names it. | Treat the key as exposed. Find out how the file was written, remove it, and re-mint the DEK. |
| -35 / -36 `FILE_TOO_SHORT` / `FILE_TOO_LONG` | The file isn't 132 bytes, so it isn't a wrapped key. | Check the application is pointed at the right file; re-run `wrap`. |
| -32 / -33 / -34 `FILE_NOT_FOUND` / `FILE_ACCESS_DENIED` / `FILE_IO` | The file is missing, the service account can't read it, or another process has it open for writing. | Check the path and the file's `--group` ACL, and that nothing is rewriting the file while the service starts. |

For security assumptions and known TPM vendor behavior, see
[SecurityAssumptions.md](../SecurityAssumptions.md).
