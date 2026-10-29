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
- [Check or retire a KEK](#check-or-retire-a-kek)
- [Machine policy settings](#machine-policy-settings)
- [Monitoring and auditing](#monitoring-and-auditing)
- [Upgrade](#upgrade)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

## What it is

hkdfguard-native-windows protects a 32-byte data encryption key (DEK) by wrapping it with a
key encryption key (KEK) that never leaves the machine. Each KEK is a non-exportable
machine key, held by the TPM when one is available, or by the Windows software key store
otherwise. By default the KEK is a symmetric, post-quantum key (payload version 2); a
machine can be set to use the classical P-256 KEK (version 1) instead - see
[ClassicalMode](#classicalmode).

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
  For the default, post-quantum payload version 2, a TPM 2.0 is used through TBS; see
  [ClassicalMode](#classicalmode) for what it must allow.

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
| Files | `C:\Program Files\HkdfGuard\v1\HkdfGuard.dll` and `hkdfguard.exe`. The folder inherits the Program Files ACL, so only Administrators, SYSTEM and TrustedInstaller can write to it. The location can't be changed. |
| Registry | `HKLM\Software\hkdfguard-native-windows`, value `InstallPath` (`REG_SZ`). Applications read it to find the DLL. |
| Event log | Registers the Application log source `hkdfguard-native-windows`. |
| Local groups | Creates `HkdfGuardUsers` (applications: wrap and unwrap) and `HkdfGuardDeployers` (deployers: wrap, unwrap, and write key files) if they don't already exist. |

The installer doesn't set any policy values. Those are left to whatever already manages
machine policy, such as Group Policy, Intune or SCCM.

### Check the install

```powershell
Get-ItemProperty HKLM:\Software\hkdfguard-native-windows | Select-Object InstallPath
Get-ChildItem "C:\Program Files\HkdfGuard\v1"
net localgroup HkdfGuardUsers
net localgroup HkdfGuardDeployers
& "C:\Program Files\HkdfGuard\v1\hkdfguard.exe" --help
```

## Set up a service

A **service name** identifies one KEK, for example `myapp` or `contoso.billing`. Service
names may contain only ASCII letters, digits and `.`, may not start with `.` or contain `..`, are 1 to 128
characters long, and are
case-insensitive. The same name must be used to wrap and to unwrap.

### 1. Decide who can use the key

A machine runs one of two **security models**, set by the
[`SecurityModel`](#securitymodel) policy. **Production is the default**: it applies unless
an administrator sets the value to `1`.

| Role | Production model | Who, on Windows |
|---|---|---|
| **Security admin** | Provisions and retires KEKs. | A local administrator, from an elevated prompt. |
| **Deployer** | Wraps DEKs into key files and deploys them. May also unwrap. | A member of `HkdfGuardDeployers` (or of a group in [`DeployerGroups`](#deployergroups)). Not a local administrator, or the separation from the security admin is only on paper. |
| **Application** | Unwraps key files, and wraps and unwraps ephemeral keys in memory. **Can't persist a key file its own service would accept.** | The service's account, a member of `HkdfGuardUsers`. |

The application's limit is enforced two ways:

- **By Windows:** the key folder gives deployers Modify and applications only Read (see
  [Where to keep key files](#where-to-keep-key-files)), so an application can't overwrite
  a deployed key file.
- **By the library:** `hkdfguard_open_file` trusts a key file only if it, and every
  folder above it, is owned by SYSTEM, Administrators, TrustedInstaller, or a deployer
  group or a direct member of one. A key file the application wrote anywhere else is
  owned by the application, so it's refused.

Under the **developer** model (`SecurityModel` = `1`) the caller's own key files are
trusted too, so one account can provision, wrap to a file and read it back. Use it on
development machines only. Each process that reads a key file under it logs event 1005.

A KEK's access list is fixed **when the KEK is created**. Set up groups and policy *before*
provisioning.

| Who | Access | How they get it |
|---|---|---|
| SYSTEM, `BUILTIN\Administrators` | Full control | Always |
| Local group `HkdfGuardAdmins` | Full control | Only if the group exists when the KEK is created. The installer doesn't create it. |
| Local group `HkdfGuardUsers` | Use (wrap and unwrap) | If the group exists when the KEK is created. The installer creates it. |
| Local group `HkdfGuardDeployers` | Use (wrap and unwrap) | If the group exists when the KEK is created. The installer creates it. |
| Groups listed in [`DeployerGroups`](#deployergroups) | Use (wrap and unwrap) | Policy in force when the KEK is created |
| Groups listed in [`KeyUseGroups`](#keyusegroups) | Use (wrap and unwrap) | Policy in force when the KEK is created |

Usually you add the service's account to `HkdfGuardUsers`, and the account that deploys
key files to `HkdfGuardDeployers`:

```powershell
net localgroup HkdfGuardUsers "NT SERVICE\MyAppService" /add
net localgroup HkdfGuardDeployers "CONTOSO\deploy-agent" /add
```

Deployer membership is read every time a key file is opened. Only **individual accounts**
added **directly** to `HkdfGuardDeployers` count: user accounts (local or domain) and
service accounts (`NT SERVICE\<name>`). A group added to it - local, domain or built-in,
such as `Domain Users` or `Authenticated Users` - is ignored, and so are its members, so
adding a broad group can never make everyone a deployer. Add each deploying account
itself. Remove someone from `HkdfGuardDeployers` and the key files they own stop being
trusted, so redeploy them under a current deployer.

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
& "C:\Program Files\HkdfGuard\v1\hkdfguard.exe" provision --service-name myapp
```

`provision` creates the KEK if it's missing. If the KEK already exists, `provision` checks
its properties and access list and changes nothing, so it's safe to run on every
deployment.

`provision` then prints the KEK's **fingerprint**, 64 hex characters. Record it with the
service's deployment records:

- `retire` requires it before it will delete the KEK.
- On a later run, `provision` prints it again. If it ever differs from what you recorded,
  the KEK under that service name has been replaced. **Investigate** before wrapping
  anything new under it.

There is no key rotation. If you need a new KEK, provision a new, versioned service name
(for example `myapp.v2`) and wrap new DEKs under it. **Never delete a KEK that is still
needed.** Deleting it makes every DEK wrapped under it unrecoverable.

### 3. Wrap a DEK into a key file (every release)

Run `wrap` as a **deployer** (a member of `HkdfGuardDeployers`) or as an elevated
administrator. Under the production model it refuses any other account before writing
anything: an application can wrap in memory, but not persist the result.

`wrap` uses an existing KEK and never creates one. It reads the DEK as base64 from
**stdin**, so the key never appears on a command line. The key file's ACL lets the owner
read and write and no one else (the owner is Administrators when `wrap` runs elevated).
The optional `--group` adds one group that can only read it. Use it when the application
runs as a different account, and use a dedicated group whose members are only the
service's account. The group must be on this host, as for `KeyUseGroups`; a domain
group is refused. Without `--group`, only the owner can read the file, so an
application running as another account can't open it.

```powershell
$exe = "C:\Program Files\HkdfGuard\v1\hkdfguard.exe"

# One-time: a group for the account that reads the key file.
net localgroup App_1234 /add
net localgroup App_1234 "NT SERVICE\MyAppService" /add

# One-time: the key folder - see "Where to keep key files" below.
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "HkdfGuardDeployers:(OI)(CI)M"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T

# Every release, as a deployer: generate a random 32-byte DEK and wrap it.
$dek = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dek)
[Convert]::ToBase64String($dek) | & $exe wrap `
    --key-file-path C:\HkdfGuardKeys\myapp\myapp.key --service-name myapp `
    --dek-stdin --group App_1234 --force
```

`--force` overwrites an existing key file. The wrapped file is always 132 bytes. The key
file must be on a real local path. Symbolic links, junctions, SUBST drives, mapped network
drives and hard-linked files are refused, and so are 8.3 short names such as `PROGRA~1`:
spell every folder with its full name. Don't build the path from `%TEMP%` or another
environment variable without expanding it first: Windows can set those variables with short
names (for example `C:\Users\RUNNER~1\AppData\Local\Temp` on GitHub-hosted runners), and a
path containing one is refused.

#### Where to keep key files

Applications read the key file back through the library with the same rules, so the path
must be a plain local NTFS folder that no other account can tamper with - **not**
`C:\ProgramData` (see below). In addition to links and network paths, the
library refuses files on volumes with **Data Deduplication** enabled and **cloud
placeholder files** (OneDrive, Dropbox and similar), because Windows stores both as
reparse points. An application that hits this reports `HKDFGUARD_ERR_FILE_UNTRUSTED`
(-39). Move the file to a plain local folder and wrap it again there.

Configure applications with the key file's **full long path**, the same one you passed to
`wrap`. If an application builds the path from `%TEMP%`, `%USERPROFILE%` or another
environment variable, it must expand it to its long form first with the Windows
`GetLongPathNameW` function, or the library refuses it with -39. Don't assume a framework's
path helpers do this: some keep short names (PowerShell's `Resolve-Path`, for one).

**Who may own and change the folders.** The library also refuses the file with -39 unless:

- the file and every folder above it, **up to and including the drive root**, are owned by
  SYSTEM, Administrators, TrustedInstaller or - under the production model - a deployer
  group or a direct member of one (under the developer model: the account the application
  runs as), and no other account may write the file or delete, rename, re-permission or
  take ownership of it or those folders; and
- every folder **below the drive root** - the key file's own folder and each folder above
  it - lets no other account **create** files or folders in it ("Create files / write
  data" or "Create folders / append data"). This is the Windows form of the Linux build's
  rule that no directory above a key file may be writable by group or others, sticky
  (`/tmp`-style) or not.

Read access for other accounts is fine everywhere: the file is ciphertext.

The **drive root** is the one exception to the create rule. A default `C:\` lets
Authenticated Users create folders in it; that can't displace a folder already there, and
every folder below the root is judged on its own, so the root is held only to the owner and
write/delete/rename/re-permission rule. (If the create rule applied to the root too, no key
file on `C:` could ever be trusted.) A key file placed directly in the drive root is judged
by the drive-root rule - but keep it in a folder of its own anyway.

What this rules out:

- **`C:\ProgramData` and everything under it.** `C:\ProgramData` itself lets Users create
  files and folders, so a key file anywhere below it is refused, whatever the permissions of
  its own folder. Don't change the permissions of `C:\ProgramData`.
- **`C:\Windows\Temp`**, which lets Users create files and folders.
- **A folder created directly under `C:\` with its default permissions** (such as
  `C:\secrets`): it inherits `Authenticated Users: Modify`, which lets any signed-in user
  create entries in it, or rename the folder away and put their own in its place.
- Any folder that inherited create rights from one of those.

**Recommended location: a folder of its own directly under the drive root, with inherited
permissions removed**, for example `C:\HkdfGuardKeys\<app>\`. From an elevated prompt:

```powershell
# Create the folders. As an elevated administrator, they are owned by Administrators.
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null

# Remove every inherited permission (Authenticated Users: Modify from C:\) and grant
# exactly: SYSTEM and Administrators full control, deployers Modify (to write key files),
# Users read. Subfolders and files inherit these.
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "HkdfGuardDeployers:(OI)(CI)M"

# Make Administrators the owner of the folder and everything in it, in case it was
# created by a non-elevated account.
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T

# Check: only SYSTEM, Administrators, Users (RX) and HkdfGuardDeployers (M) are listed,
# none of them (I)nherited
# from C:\ - and the same for C:\HkdfGuardKeys\myapp, where they show as inherited from
# C:\HkdfGuardKeys.
icacls C:\HkdfGuardKeys
icacls C:\HkdfGuardKeys\myapp
```

The SIDs are used so the commands work in any display language: `S-1-5-18` is SYSTEM,
`S-1-5-32-544` is Administrators, `S-1-5-32-545` is Users. The application's account needs
read access to every folder on the way (the library reads each folder's permissions), which
the Users grant gives; to restrict that to the application, grant its group instead, for
example `"App_1234:(OI)(CI)RX"` in place of the Users entry. The key file itself is
protected separately: `wrap` gives it its own non-inherited ACL (the owner, plus
`--group`, read-only).

If you must use a folder that already exists, apply the same two `icacls` commands to it.
`/inheritance:r` drops only *inherited* entries; an entry set on the folder itself survives,
so remove it first with `icacls <folder> /remove:g <account>` - `wrap` names the account
and prints these commands when it refuses a folder. Every folder above it, below the drive
root, must pass too.

`wrap` checks all of this before it reads the DEK or touches a key store, so it never
writes a key file the library would then refuse. It never creates a missing folder (a
folder it made would inherit its parent's permissions, create rights included): create and
prepare the folder first.

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

## Check or retire a KEK

To see a service's KEK, run `status` from any account that can use the key:

```powershell
& "C:\Program Files\HkdfGuard\v1\hkdfguard.exe" status --service-name myapp
```

It prints the payload version this machine uses (see [ClassicalMode](#classicalmode)), and
whether the KEK of that version is `present`, `absent`, `corrupt` or `unusable`. It also
prints which key store holds the KEK (TPM or software) and its fingerprint. It also lists
any other key under the service's name: in the key store the `KeyStoragePolicy` doesn't
select, or of the other payload version. It never changes anything. It exits `0` when it
got an answer and `1` when it couldn't tell, for example because access was denied.

**Retiring a KEK deletes it, and every DEK wrapped under it becomes permanently
unrecoverable.** Retire a KEK only after every application has moved to a new, versioned
service name (for example from `myapp` to `myapp.v2`) and no key file wrapped under the old
name is still needed. From an elevated prompt:

```powershell
& "C:\Program Files\HkdfGuard\v1\hkdfguard.exe" retire --service-name myapp --fingerprint <recorded fingerprint>
```

`retire` deletes the KEK only if its fingerprint matches the one you give. Otherwise it
deletes nothing. It is the only way this product deletes a KEK. Applications can't delete
one: the library has no delete function.

- If a key under the service's name fails its KEK checks, it has no fingerprint. `status`
  reports it as `corrupt`. Retire it with `--corrupt` instead of `--fingerprint`. For a
  version 1 KEK that means a key that isn't a valid P-256 key; for a version 2 KEK, a TPM
  key file or AES key that fails its checks - including a key file whose TPM was cleared,
  so its storage root key is gone. `--corrupt` refuses a valid KEK, and refuses any key it
  couldn't check.
- If the service has a key in both the TPM and the software key store, `retire` won't
  choose between them. Run `status`, then add `--provider tpm` or `--provider software`.
- `retire` acts on the KEK of this machine's payload version. Add `--version 1` or
  `--version 2` to retire the other version's KEK, which `status` lists as unused.

Each retirement is logged as event **1004**, with the service, key store, fingerprint and
the account that ran it. Afterwards the service name can be provisioned again, which
creates a new KEK with a new fingerprint.

## Machine policy settings

All seven settings are values under `HKLM\Software\Policies\HkdfGuard`. Set them with Group
Policy, Intune or SCCM, or with `reg add` for testing. They're read on every call, so a
change takes effect without a restart.

### ClassicalMode

`REG_DWORD`. Selects the payload version - the cryptography - this machine uses for every
KEK, wrap and unwrap.

| Value | Payload version | KEK |
|---|---|---|
| absent or `0` | **2, post-quantum** (the default) | A symmetric key used as a PRF: an HMAC-SHA-256 key in the TPM, or an AES-256 key in the software key store. No public key, so nothing a quantum computer could break. |
| `1` | 1, classical | A P-256 ECDH key in the TPM or the software key store. |

Anything else, or a value of the wrong type, makes every call fail with
`invalid machine policy`.

**Set it before the first `provision` and leave it.** A machine uses exactly one version.
Each version has its own KEK, and a key file wraps under one: unwrap refuses a key file of
the other version (`HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED`) before it opens any key, and
nothing falls back from one version to the other. Changing the setting later makes every
existing key file unreadable until it is changed back. To move a service to the other
version, set the value, provision the service (which creates that version's KEK, with a
new fingerprint) and wrap its DEKs again.

Where a version 2 KEK lives:

| Key store | Version 2 KEK |
|---|---|
| TPM | A key file, `C:\ProgramData\HkdfGuard\TpmKeys\hkdfguardwin_<service>_v1.tpmkey`. The TPM made the key and only it can use it; the file holds it encrypted for this TPM. **The file's access list is the KEK's**: SYSTEM, Administrators and `HkdfGuardAdmins` full control, the key-use groups read - the same rules as any KEK. The library checks the file and its folders on every use and refuses one that anyone else could change, replace or read. |
| Software | An AES-256 machine key named `hkdfguardwin_<service>_v1_aes`, non-exportable, with the usual KEK access list. |

**Know what the TPM key file means before you choose version 2 on a TPM.** Reading the key
file is enough to use the KEK. The TPM doesn't check who loads it, so an account that reads
the file once keeps the use of the KEK on this machine from its copy, even after you remove
it from `KeyUseGroups` or change the file's access list. The only way to take that away is
to retire the KEK and wrap every DEK again. Administrators, backup operators, backup and
snapshot software, and agents running as SYSTEM can read the file too. A copy is useless on
any other machine, since only this TPM can load it. A version 1 TPM KEK, and a version 2
software KEK, don't have this weakness: their key store checks the access list on every use.

This is a deliberate trade. Version 2 protects payloads stored today against a future
quantum computer, which version 1 can't do and nothing can add later; the key file's
weakness is local and is planned to be closed in a later release. Choose accordingly:

- Version 2 on the TPM (the default): post-quantum, and the TPM protects the key at rest,
  but key-use access can't be revoked short of retiring the KEK.
- Version 2 with `KeyStoragePolicy` `SoftwareOnly`: post-quantum, and access is checked on
  every use, but the key is protected at rest only by machine DPAPI.
- Version 1 (`ClassicalMode` `1`): access checked on every use and TPM-protected, but not
  post-quantum.

Whichever you choose, keep the `HkdfGuard\TpmKeys` folder out of backups that accounts
outside the key-use groups can restore.

A TPM is used for version 2 only if all of these hold: Windows can reach it through TBS
(TPM 2.0), its storage root key at `0x81000001` exists, none of the TPM commands the library
needs is blocked (the Group Policy setting **Configure the list of blocked TPM commands**
must not block `TPM2_Create`, `TPM2_Load`, `TPM2_LoadExternal`, `TPM2_HMAC`,
`TPM2_StartAuthSession`, `TPM2_ReadPublic`, `TPM2_FlushContext` or `TPM2_GetCapability`), and
its HMAC passes a known-answer test. If not:

- Under `PreferTpm`, the KEK goes in the software key store instead (event 1001), unless a
  version 2 TPM key file already exists for the service - then the call fails.
- Under `RequireTpm`, the call fails with `HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` and event
  **2008** names the reason.

Either way, nothing falls back to version 1. On a machine whose TPM can't do version 2 and
that must keep using the TPM, set `ClassicalMode` to `1` before provisioning.

If the TPM is cleared, its storage root key changes and every version 2 TPM key file made
under the old one can no longer be used: `status` reports the KEK as `corrupt`. Key files
wrapped under it can't be recovered. Retire it with `--corrupt`, provision again, and wrap
new DEKs.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v ClassicalMode /t REG_DWORD /d 1 /f   # classical (version 1) only
```

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
  logon-type groups (including `TERMINAL SERVER USER`), the authentication-package
  groups (`NTLM Authentication`, `SChannel Authentication`, `Digest Authentication`,
  `Cloud Account Authentication`), `IUSR` (every anonymous IIS request), `IIS_IUSRS`
  (every IIS application pool), `DIALUP`, `OTHER ORGANIZATION`, the local SAM's `None`
  group (every local account's primary group; `Domain Users` on a domain), and the
  anonymous and NULL principals are all refused.

One invalid entry makes provisioning fail, and no KEK is created.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v KeyUseGroups /t REG_MULTI_SZ /d "App_1234\0App_5678" /f
```

### SecurityModel

`REG_DWORD`. Selects whose key files the library trusts. See
[Decide who can use the key](#1-decide-who-can-use-the-key) for the roles.

| Value | Model | Key files trusted when owned by |
|---|---|---|
| absent or `0` | Production | SYSTEM, Administrators, TrustedInstaller, a deployer group, or a direct member of one |
| `1` | Developer | SYSTEM, Administrators, TrustedInstaller, or the account reading the file |

Any other value, or a value of the wrong type, makes every key-file read and every `wrap`
fail with `invalid machine policy`. It isn't treated as the default. Wrapping and
unwrapping in memory work the same under both models. `hkdfguard.exe status` shows the
model in force.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v SecurityModel /t REG_DWORD /d 1 /f   # developer machines only
```

### DeployerGroups

`REG_MULTI_SZ`. Groups whose direct members are trusted, under the production model, to
have written key files, in addition to `HkdfGuardDeployers`. Each entry is vetted exactly
like a [`KeyUseGroups`](#keyusegroups) entry: a host-local group, not over-broad. One
invalid entry makes every key-file read and every `wrap` fail. Each group is also granted
use access on KEKs created while it is listed, since deployers wrap.

```powershell
reg add HKLM\Software\Policies\HkdfGuard /v DeployerGroups /t REG_MULTI_SZ /d "Deploy_1234" /f
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
| 1003 | Information | A DEK was unwrapped. Wrap and unwrap events record the payload version. |
| 1004 | Warning | A KEK was retired (deleted) with `hkdfguard.exe retire`. Every DEK wrapped under it is now unrecoverable. Names the service, key store, fingerprint and account. |
| 1005 | Warning | A process read a key file under the **developer** security model, which trusts the caller's own key files. Logged once per process. **Investigate** on any production machine and remove `SecurityModel`. |
| 2000 | Warning | Access denied: an unauthorized account used a KEK, or provisioning ran without elevation. |
| 2002 | Error | An existing KEK has an access list this library would never create. **Investigate.** |
| 2003 | Warning | Unwrap rejected a tampered, corrupted or misdirected payload, or one of the payload version this machine doesn't use. |
| 2004 | Error | Policy is misconfigured (`KeyStoragePolicy`, `ClassicalMode`, `SecurityModel` or `KeyUseGroups`), so calls fail. |
| 2005 | Error | The key store or cryptography layer failed. |
| 2006 | Error | An application asked the library to read a key file that looks like an *unwrapped* key (32 raw bytes, or its hex or base64), so it may be a plaintext key on disk. The event names the file; none of its contents are logged. **Investigate**, remove the file and re-mint that DEK. |
| 2007 | Warning | An application made more than 10 setup calls (`create_kek` / `kek_exists`) in one process. These should run once at startup; it is probably calling them per request. Logged once per process. |
| 2008 | Error | Payload version 2 is unavailable: the TPM can't be used for it, and the `KeyStoragePolicy` (or an existing version 2 TPM key file) rules out the software key store. Names the reason - no TPM 2.0, no storage root key, a blocked TPM command, a failed known-answer test - and the fixes. See [ClassicalMode](#classicalmode). |

Wrap and unwrap events include a SHA-256 of the wrapped payload, so each unwrap can be
traced to the wrap that produced it. To compare against a key file:
`(Get-FileHash C:\HkdfGuardKeys\myapp\myapp.key -Algorithm SHA256).Hash.ToLower()`.

```powershell
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='hkdfguard-native-windows']]]" -MaxEvents 50 |
    Format-Table TimeCreated, Id, LevelDisplayName, UserId, Message -Wrap
```

Any local user can write to the Application log, so treat these events as an operational
aid, not tamper-proof evidence. Forward them to your SIEM for retention and alerting. Events
2002, 2006, 2003, 2008, 1005, 1004 and 1001 are good candidates for alerts.

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

You can also uninstall **HkdfGuard for Windows** from **Settings → Apps**. Uninstalling removes the files, the
`InstallPath` value and the event source registration. It deliberately keeps:

- **All KEKs**, including the version 2 TPM key files under
  `C:\ProgramData\HkdfGuard\TpmKeys`. Deleting a KEK destroys every DEK wrapped under it.
  To remove one on purpose, [retire](#check-or-retire-a-kek) it before you uninstall.
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
| `KEK provider/key open or create failed` | Under `RequireTpm`: no usable TPM. Otherwise, the key store failed. | Check the TPM (`Get-Tpm`) and event 2005 for details. |
| `a KEK already exists under this service name, but its ACL is ...` | The existing KEK's access list was changed, or a key was planted under that name. It was left untouched. | Investigate it as a security event. To move on, provision a new versioned service name. |
| `wrapped payload was not produced under this service's current KEK` | The key file belongs to a different service or a different KEK. | Check the service name, and that the file was wrapped on this machine. |
| `hkdfguard_open_file would refuse to read a key file there` | `wrap`'s `--key-file-path` is in a folder that another account can create, delete or rename entries in (for example anywhere under `C:\ProgramData`), or that isn't owned by SYSTEM, Administrators, TrustedInstaller or you. Nothing was read or written. | Use a folder prepared as in [Where to keep key files](#where-to-keep-key-files); the message names the folder and account and prints the `icacls` commands. |
| `this account may not persist key files` | Under the production model, `wrap` ran as an account that is neither an elevated administrator nor a member of `HkdfGuardDeployers` or a `DeployerGroups` group. Nothing was written. | Run `wrap` as a deployer: add the account to `HkdfGuardDeployers`, then sign in again. |
| `invalid machine policy` | `KeyStoragePolicy` isn't a `REG_DWORD` of `0`, `1` or `2`, or `SecurityModel` or `ClassicalMode` isn't a `REG_DWORD` of `0` or `1`. | Correct or remove the value. |
| `payload version 2 is unavailable on this host` | The TPM can't be used for version 2 and the `KeyStoragePolicy` (or an existing version 2 TPM key file) rules out the software key store. Event 2008 names the reason. | Fix what event 2008 names (for a blocked command, the Group Policy list of blocked TPM commands). Or set `KeyStoragePolicy` to allow the software key store, or set [ClassicalMode](#classicalmode) to `1` before provisioning. |
| `not the payload version this host uses` | The key file was wrapped while `ClassicalMode` had the other value. | Set `ClassicalMode` back to what it was when the file was wrapped, or provision this version's KEK and wrap the DEK again. |
| `kek: corrupt` from `status`, for a TPM KEK | Often a TPM that was cleared since provisioning: the key file is pinned to a storage root key that no longer exists. | Everything wrapped under it is unrecoverable. Retire it with `--corrupt`, provision again and wrap new DEKs. |
| `a KeyUseGroups or DeployerGroups policy entry is ...` | An entry in either value is invalid, or a deployer group's members couldn't be read. | Fix the entry. See [KeyUseGroups](#keyusegroups) and [DeployerGroups](#deployergroups). |
| `service name is missing or malformed` | The name uses characters other than ASCII letters, digits and `.`, starts with `.`, contains `..`, or is longer than 128. | Use a valid name. |

An application that can't load the DLL usually has an architecture mismatch (see
[Requirements](#requirements)) or is loading by bare file name instead of the
`InstallPath` location.

Applications that read the key file through the library may report these codes, which the
command-line tool itself never produces:

| Code | Meaning | What to do |
|---|---|---|
| -39 `FILE_UNTRUSTED` | The key file's path is a link, passes through a junction or SUBST drive, uses an 8.3 short name (`PROGRA~1`), is on a network or deduplicated volume, or is a cloud placeholder. Or the file or a folder above it is owned by, or can be changed, deleted or renamed by, an account other than SYSTEM, Administrators, TrustedInstaller or the application's own. Or a folder above it, other than the drive root, lets such an account create files or folders in it - every folder under `C:\ProgramData` or `C:\Windows\Temp`, and a folder under `C:\` with its default permissions. | Configure the application with the full long path (if it comes from `%TEMP%` or another environment variable, expand it first), or move the file to a plain local folder. For an ownership or permissions refusal, move the file to a folder prepared with `icacls /inheritance:r` (or prepare its folder that way) and re-run `wrap` elevated. See [Where to keep key files](#where-to-keep-key-files). |
| -38 `FILE_MALFORMED` | The file is 132 bytes but does not hold a valid wrapped key (corrupted, edited, or not a key file at all). | Re-run `wrap` to rewrite the file. |
| -37 `FILE_PLAINTEXT_KEY` | The file is 32 raw bytes, or 32 bytes as hex or base64: probably an unwrapped key on disk. Event 2006 names it. | Treat the key as exposed. Find out how the file was written, remove it, and re-mint the DEK. |
| -35 / -36 `FILE_TOO_SHORT` / `FILE_TOO_LONG` | The file isn't 132 bytes, so it isn't a wrapped key. | Check the application is pointed at the right file; re-run `wrap`. |
| -32 / -33 / -34 `FILE_NOT_FOUND` / `FILE_ACCESS_DENIED` / `FILE_IO` | The file is missing, the service account can't read it, or another process has it open for writing. | Check the path and the file's `--group` ACL, and that nothing is rewriting the file while the service starts. |

For security assumptions and known TPM vendor behavior, see
[SecurityAssumptions.md](../SecurityAssumptions.md).
