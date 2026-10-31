# hkdfguard-native-windows

Windows-native Key Wrapper.
Wraps and unwraps a 32-byte key using a persistent, machine-wide scoped, non-exportable
Key Encryption Key (KEK) held by a TPM/vTPM, or by the Microsoft Software Key Storage
Provider - which one is machine policy (see "Key storage policy" below); the default
prefers the TPM and falls back to software when no TPM is available (bare servers, VMs
without a vTPM, containers).

By default every payload is **version 2, post-quantum**: the KEK is a symmetric key the
provider uses as an HMAC-SHA-256 PRF - an HMAC key in the TPM (Microsoft Platform Crypto
Provider), or an SP 800-108 key in the Software Key Storage Provider, both persisted
NCrypt machine keys - so there is no public key for a quantum computer to break. The construction is the
Linux library's, byte for byte. **Version 1**, the classical construction (a P-256 ECDH
KEK), is used only where an administrator sets `ClassicalMode` (below). See
[docs/adr/0001-post-quantum-payload-version-2.md](docs/adr/0001-post-quantum-payload-version-2.md).

**Key storage policy**: the `REG_DWORD` value `HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy`
selects the provider: `0` = `PreferTpm` (the default when the value is absent - TPM if
available, otherwise software), `1` = `RequireTpm` (TPM or fail; never falls back),
`2` = `SoftwareOnly`. It is read on every call, so it also governs which provider an
existing KEK is *looked for* on. Under `RequireTpm` a payload that routes to a
software-backed KEK is refused on unwrap as well (`VerifyKeyProperties` demands
hardware backing), so the policy is enforced end to end, not just at creation. A value
that is present but not one of `0`/`1`/`2` (or not a `REG_DWORD`) is a configuration
error and fails every call with `HKDFGUARD_ERR_POLICY_INVALID` - it is deliberately
*not* treated as the default, since a typo'd value most likely intended the stricter
setting. The `PreferTpm` fallback is intentional and administrator-chosen: the
`provider_type` byte in every payload records which provider actually protected it,
so a consumer that needs to know can check. It applies only when the TPM is
unusable for the service (no TPM, or the TPM key is absent and could not be created).
An existing TPM KEK that fails verification, or a TPM that errors while being probed,
fails the call instead of quietly creating or using a software KEK beside it.

**Payload version**: the `REG_DWORD` value `HKLM\Software\Policies\HkdfGuard\ClassicalMode`
selects the one payload version a host writes and accepts. Absent or `0` is version 2
(post-quantum), the default; `1` is version 1 (classical). Anything else fails every
call with `HKDFGUARD_ERR_POLICY_INVALID`. A host uses exactly one: unwrap refuses a
payload of the other version with `HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED` before any key
is opened, and nothing falls back from one version to the other. Each version has its
own KEK, so `hkdfguard_create_kek` provisions the one for this host's setting. A TPM is
unusable for version 2 when the Platform Crypto Provider can't be opened, reports no TPM
device, or can't create an HMAC-SHA-256 key. Then `PreferTpm` falls back to the software
key store (event 1001), as it does for version 1, and `RequireTpm` fails with
`HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` and logs event 2008 with the reason - set
`ClassicalMode` to `1` on such a host to keep using version 1.

**Deployment model**: the KEK is created with `NCRYPT_MACHINE_KEY_FLAG`, not tied to
the account that created it, and is meant to be long-lived - there is no key-rotation
mechanism. This is intended for a specific split: a deployment-time utility (running
elevated) calls `hkdfguard_create_kek` once per service, provisioning that service's KEK
if it doesn't already exist (safe to call again on every later deployment - it verifies
rather than re-creating); a separate, lower-privileged service account later calls
`hkdfguard_unwrap_dek` to recover a DEK, without ever needing to create anything itself.
`hkdfguard_wrap_dek` never creates a KEK - it fails with `HKDFGUARD_ERR_KEK_NOT_FOUND` if
`hkdfguard_create_kek` hasn't provisioned one yet; `hkdfguard_kek_exists` lets a caller
check first without side effects. The DEKs actually protected are expected to be re-minted
on every release (bi-weekly/monthly) and wrapped fresh under the same, stable service
name; if a genuinely new KEK is ever wanted, that's done by versioning the *service name*
itself (e.g. `myapp.v2`), not by rotating anything under the existing one.

Creating a KEK for the first time requires the calling process to be elevated -
opening/using an already-created one does not. Who else may use it is machine policy,
not something either the creating tool or a caller chooses: SYSTEM and
`BUILTIN\Administrators` always get full control; the local groups `HkdfGuardAdmins` (full
control), `HkdfGuardUsers` and `HkdfGuardDeployers` (use access) are granted if they exist when
the KEK is created (the MSI creates `HkdfGuardUsers` and `HkdfGuardDeployers`, never
`HkdfGuardAdmins`); every entry of `HKLM\Software\Policies\HkdfGuard\DeployerGroups` gets use
access too; and every entry of the `REG_MULTI_SZ`
registry value `HKLM\Software\Policies\HkdfGuard\KeyUseGroups` is granted use (unwrap)
access when the KEK is created - each entry must resolve to a real, host-local group
(this machine's own SAM, `BUILTIN`, `NT AUTHORITY`, or `NT SERVICE`; domain groups are
rejected even on a domain-joined machine, and broad principals like `Everyone`,
`NT AUTHORITY\Local account`, `NT SERVICE\ALL SERVICES` or
`BUILTIN\Users` are refused outright) - see `include/hkdfguard.h` for the exact rules.
This is a deliberate trade-off: any principal an administrator has explicitly listed is
able to use the key, in exchange for wrap and unwrap not needing to be the same account.
If you need per-user isolation instead, that means leaving `NCRYPT_MACHINE_KEY_FLAG`
unset (current-user scope) - not offered as a build option here, since this project
targets the shared-service deployment model above.

**Security model**: the `REG_DWORD` value `HKLM\Software\Policies\HkdfGuard\SecurityModel`
decides whose *key files* the library trusts. Absent or `0` is **production**, the
default. There, a key file and every folder above it must be owned by SYSTEM,
Administrators, TrustedInstaller, or a deployer group (`HkdfGuardDeployers` and each
`DeployerGroups` entry) or an individual account that is a direct member of one - a user
or a service account, never a group nested inside it. `1` is **developer**, which also trusts
the reading account's own files, so one account can provision, wrap to a file and read
it back. Anything else fails closed with `HKDFGUARD_ERR_POLICY_INVALID`. Wrapping and
unwrapping in memory are the same under both: any account with key use on the KEK may
do either. What production adds is that an application, which unwraps and may wrap
ephemeral keys, can't *persist* a key file its own service would accept. A file it
wrote is owned by it, so it's refused. The key folder's permissions (deployers Modify,
applications Read) stop it overwriting a deployed one. The roles, the folder recipe and
the settings are in [docs/admin-guide.md](docs/admin-guide.md). The CLI's `wrap` refuses
to persist under production for any account but a deployer or an elevated
administrator, and `status` shows the model.

The library exposes a small, stable C ABI (`include/hkdfguard.h`) with eleven functions.
No Windows handle, CNG/NCrypt type, or COM interface crosses that boundary, and no C++
exception ever escapes it - every call returns an integer status code.

```c
int hkdfguard_kek_exists(
    const char* service,
    int* out_exists);

int hkdfguard_security_model(
    int* out_model, int* out_may_write_key_files);

int hkdfguard_key_file_principal_trusted(
    const char* sid, int* out_trusted);

int hkdfguard_kek_fingerprint(
    const char* service,
    uint8_t* out, int* out_len);

int hkdfguard_create_kek(
    const char* service);

int hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int dek_len,
    uint8_t* out, int* out_len);

int hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int wrapped_len,
    uint8_t* out, int* out_len);

int hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out, int* out_len);

int hkdfguard_open_file(
    const char* path,
    uint8_t* out, int* out_len);

int hkdfguard_harden_process(void);
int hkdfguard_harden_process_with_flags(unsigned int flags);
```

`service` is a null-terminated UTF-8 string (non-empty, at most 128 bytes, ASCII letters/
digits/`.` only, not starting with `.`, no `..`) identifying which persistent KEK to use - e.g. an application or tenant
name. It's case-insensitive (normalized to lowercase internally, so `"MyApp"` and
`"myapp"` are the same service everywhere). Different service names get independent,
non-interoperable KEKs; the same service name must be passed to both wrap and unwrap a
given payload, since it is not itself recorded in the wrapped bytes (a SHA-256
fingerprint of the KEK's public key is, though - see the Design section below).

A payload is bound to its service name and KEK, and to nothing release-specific, so a
DEK wrapped by any earlier release keeps unwrapping for as long as the KEK exists. That's
deliberate: rolling a deployment back to a previous release has to be able to recover
that release's DEK. It also means anyone who can replace a wrapped-key file can swap in
an older payload for the same service. Protect the file itself, which is what the CLI's
`--group` ACL is for. If your application must refuse older DEKs, it has to check that
after unwrapping.

`dek_len` must be exactly 32 (`HKDFGUARD_DEK_LEN`). On Windows a wrapped payload is always
exactly 132 bytes (`HKDFGUARD_WRAPPED_MAX_LEN`), whichever KEK provider produced it, so a
buffer of that size never needs a retry. A payload is only ever unwrapped on the host
that wrapped it. `out` may be NULL only with `*out_len` 0, a
size probe that returns `HKDFGUARD_ERR_BUFFER_TOO_SMALL` with the size to allocate, before
any provider is reached or file opened. A negative capacity or `wrapped_len` is
`HKDFGUARD_ERR_INVALID_ARGUMENT`. An invalid service name is reported before a too-small
buffer. `*out_len` is left unchanged on every failure except `BUFFER_TOO_SMALL`. Lengths
and status codes are plain 32-bit `int`. See `include/hkdfguard.h` for the full set of
`HKDFGUARD_ERR_*` status codes: general codes (-1..-7), service name and policy (-8, -9),
wrapped payload (-10..-12), KEK and process (-16..-20), key file (-32..-39), and
`HKDFGUARD_ERR_WIN_GROUP_INVALID` (-64), a more precise form of
`HKDFGUARD_ERR_POLICY_INVALID` that can be treated as it. The header also reserves a few
codes that this library never returns; each is marked as such there. A NULL, empty, over-long or badly formed `service` fails
with `HKDFGUARD_ERR_INVALID_SERVICE_NAME` on every call.

`hkdfguard_generate_and_wrap_dek` generates its own cryptographically random 32-byte DEK
(via `BCryptGenRandom`) and wraps it in one call, for callers minting a brand new
Ephemeral Data Protection Key - the plaintext DEK never crosses back out to the caller;
it's zeroed internally the moment it's wrapped. Recover it later via
`hkdfguard_unwrap_dek` on the resulting payload, with the same `service`.

`hkdfguard_open_file` reads a wrapped-key file, such as one written by the CLI's `wrap`,
and returns its 132 bytes **still wrapped**, ready for a later, separate
`hkdfguard_unwrap_dek` call. It never unwraps, opens no KEK, and needs only read access to
the file. `path` is UTF-8, absolute or relative to the current directory, and follows the
same rules as the CLI's `--key-file-path`: it must be a real file on a local drive, reached
through real directories. A symbolic link, junction or other reparse point at the path or
anywhere above it is refused, never followed, and so are 8.3 short names (`PROGRA~1`),
UNC paths, mapped and SUBST drives and device paths - all with
`HKDFGUARD_ERR_FILE_UNTRUSTED`, and the network and device cases before anything
is opened, so the process never connects to a server named in a path. Configure key-file
paths as full long paths, and don't build them from `%TEMP%` or other environment variables
without first expanding them with `GetLongPathNameW`: Windows can set those variables with
short names (for example `C:\Users\RUNNER~1\AppData\Local\Temp` on GitHub-hosted runners),
and a path containing one is refused.

The file and every folder above it must also be owned by SYSTEM, Administrators,
TrustedInstaller or - under the production security model, the default - a deployer group
or a direct member of one (under the developer model: the account the process runs as),
and must not let any other account write, delete, rename or re-permission them. Every
folder **below the drive root** - the key file's own folder and each one above it - must
also not let any other account **create** files or folders in it. Otherwise it fails with
`HKDFGUARD_ERR_FILE_UNTRUSTED`: reading a wrapped DEK gains nothing, but anyone who could
replace it, and could also wrap under the service's KEK, could plant a DEK they know. Read
access for other accounts is never refused.

What that means in practice:

- `C:\ProgramData` and `C:\Windows\Temp` let Users create entries, so **no key file
  anywhere under them is trusted** - including a folder created under `C:\ProgramData` with
  its default, inherited permissions.
- A folder made directly under `C:\` inherits `Authenticated Users: Modify` and is refused
  until its inherited permissions are removed.
- **The drive root is the one exception to the create rule.** A default `C:\` lets
  Authenticated Users create folders; that can't displace a folder already there, and every
  folder below it is judged itself, so the drive root is held only to the owner and
  write/delete/rename/re-permission rule. (Without this, no key file on `C:` could ever be
  trusted.) A key file directly in the drive root is judged by the drive-root rule.

Keep key files in a folder of their own prepared with `icacls /inheritance:r` - for example
`C:\HkdfGuardKeys\<app>\`, with deployers granted Modify and applications Read;
[docs/admin-guide.md](docs/admin-guide.md#where-to-keep-key-files) gives the exact commands.

It checks the file's size before reading anything, and fails with
`HKDFGUARD_ERR_FILE_PLAINTEXT_KEY` for a file of exactly 32 bytes (the size of an
*unwrapped* DEK, so probably a plaintext key written to disk - treat it as exposed; its
contents are never read). It also fails with `HKDFGUARD_ERR_FILE_PLAINTEXT_KEY` for a DEK
written as text: 64 hex digits, or base64 (standard or URL-safe, padded or not), with any
surrounding whitespace. A file of 96 bytes or fewer is read into a wiped buffer to tell, and
none of it is returned. Any other size under 132 is `HKDFGUARD_ERR_FILE_TOO_SHORT`, and
anything over is `HKDFGUARD_ERR_FILE_TOO_LONG`. A 132-byte file must also pass the same
structural checks unwrap applies before it touches a KEK, or it fails with
`HKDFGUARD_ERR_FILE_MALFORMED` (an unrecognized version included). `HKDFGUARD_ERR_FILE_NOT_FOUND`,
`HKDFGUARD_ERR_FILE_ACCESS_DENIED` and `HKDFGUARD_ERR_FILE_IO` cover a file that can't be
opened or read; directories, pipes and devices are refused, and so is a file another
process has open for writing. On any failure the output buffer is zeroed; `*out_len` is
left unchanged except on `HKDFGUARD_ERR_BUFFER_TOO_SMALL`, as with wrap and unwrap.

`hkdfguard_harden_process` is opt-in, process-wide hardening against memory disclosure.
The library never calls it itself. It does three things:

- It tells Windows Error Reporting to leave the heap out of crash reports
  (`WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`).
- It replaces the process object's DACL. Only SYSTEM may then read or write the process's
  memory, inject threads or duplicate its handles. The account it runs as keeps query,
  synchronize and terminate access. An OWNER RIGHTS ACE removes the owner's implicit right
  to put the old DACL back.
- It applies the same restriction to every thread that exists at the time of the call.

After the call, a dump from the same account fails, whether it comes from Task Manager,
procdump or `MiniDumpWriteDump`, and so does attaching a debugger.

This is a same-user barrier only. Administrators holding `SeDebugPrivilege`, SYSTEM and
the kernel bypass it. Threads started after the call keep the default thread DACL, so call
it again once worker threads are running, or use the strict flag below. Handles that were
opened before the call keep their access. A GUI process can still be injected into
through window hooks (`SetWindowsHookEx`) by a same-user process on the same desktop, so
host key handling in a service or console process. The page file, hibernation and
machine-wide dump settings (WER `LocalDumps`) are outside its reach. The call is
idempotent. It returns `HKDFGUARD_OK` or `HKDFGUARD_ERR_PROCESS_HARDENING_FAILED`, and
steps applied before a failure stay applied.

`hkdfguard_harden_process_with_flags(flags)` is the same call with options;
`hkdfguard_harden_process()` is `..._with_flags(0)`. Unknown flag bits return
`HKDFGUARD_ERR_INVALID_ARGUMENT` before anything is changed. The one flag,
`HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE` (`0x1`), requires that no other process of
the same user can debug or inject code into this one. It adds two steps, applied first:

- It replaces the process token's **default DACL**, which every unnamed object the process
  creates from then on receives. SYSTEM keeps every right; the account keeps only
  `SYNCHRONIZE` and `READ_CONTROL`. Threads started later are then closed like the
  existing ones.
- It replaces the **token's own DACL**, so the account can only query and duplicate it.
  Without this, a same-user process could open the token and put the old default DACL
  back. Duplicate is kept because the TPM key store duplicates its own process token on
  every key open.

The cost is why it's a flag. Everything the process creates afterwards without an explicit
security descriptor is closed to its own account too: child processes (Task Manager can't
stop them; the creator's own handle still can), and named pipes, events and other named
objects. A same-user client can't connect to a pipe created with a NULL security
descriptor. Pass it in a service or console process that doesn't share objects by name
with other processes. Window hooks into a GUI process stay outside it.

## Command-line tool

Arguments are taken as the Unicode text they were typed as and handed to the library as
UTF-8, with no code-page conversion in between: a path, service name or group name with
characters outside the system code page is used exactly, never best-fit mapped to a
look-alike (`ā` is not `a`). Output is written as Unicode on a console, whatever its code
page, and as UTF-8 when redirected to a file or pipe. For the same reason `--key-file-path`
and `--dek-file` refuse any name Windows would rewrite or redirect: a folder or file name
ending in a dot or space (Windows drops it), a reserved device name such as `CON`, `NUL`,
`COM1` or `LPT1`, with or without an extension (Windows programs open the device instead),
and a path ending in a separator.

`tools/hkdfguard_cli.cpp` builds `hkdfguard.exe`, a thin
wrapper around the ABI above with four subcommands: `provision`, `wrap`, `status` and
`retire`.

It hardens itself before reading anything. It calls
`hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE)`, so
crash reports leave out the heap, and no same-user process can dump, debug or inject into
it, including through threads the key storage provider starts later. If hardening
fails, the CLI refuses to run. Every copy of the DEK the CLI makes, both the base64 text
and the decoded bytes, lives in one buffer. That buffer is locked into RAM with
`VirtualLock`, so it is never written to the page file, and it is wiped before it is
freed. Stdin is read with `ReadFile`, not through the C runtime's buffered stream, which
would keep a copy that can't be wiped. If the lock fails, the CLI warns and continues.
Windows has no way to lock a whole process's memory, so the library's own transient
copies while it wraps are not locked. Hardening still keeps them out of crash reports and
away from other processes.

- **`provision`** - always calls `hkdfguard_create_kek`, which creates the KEK if it
  is missing and otherwise re-verifies the existing key's properties and ACL (failing
  with `HKDFGUARD_ERR_KEK_INVALID` on a pre-planted or widened key). Never wraps a
  DEK, never touches a file. This is the *only* subcommand that can create a KEK. Run
  it elevated: creating a KEK requires elevation (see "Deployment model" above), and
  verifying an existing one reads its ACL, which a key-use-only account cannot do.
  Afterwards it prints the KEK's fingerprint (`hkdfguard_kek_fingerprint`). Record it:
  `retire` requires it, and on a later run it lets you confirm that the KEK is still
  the one you provisioned, not one another administrator planted under the same name.

  ```
  hkdfguard.exe provision --service-name|-sn <name>
  ```

- **`wrap`** - calls `hkdfguard_wrap_dek` only, against an *already-provisioned* KEK;
  it never creates one (a missing KEK fails with `HKDFGUARD_ERR_KEK_NOT_FOUND` and a
  hint to run `provision` first). The DEK is 32 raw bytes, base64-encoded, read from
  **stdin** rather than a command-line argument, specifically so it never appears in
  this process's `argv`, where another process on the same host could otherwise read
  it via a command-line/process listing (e.g. a WMI query) for the life of the run.
  The input rules are strict: standard base64 (`+/`, padded,
  as `[Convert]::ToBase64String` writes it), at most 64 bytes, with one trailing newline
  (LF or CRLF) allowed and no other whitespace. A leading UTF-8 byte-order mark is
  skipped, and UTF-16 input is refused with a message saying so.
  `--dek-file <path>` reads the same text from a file instead. The file must be on a
  local drive, a regular file with no link, junction or
  8.3 name at or above it, and owned by SYSTEM, Administrators or you. Its DACL must grant
  nothing to anyone else, not even read, since it holds the plaintext DEK. All of this is
  checked on the open handle; a refusal says how to fix the ACL with `icacls`. Decoding is
  constant time with respect to the DEK text (no branch or table lookup depends on it),
  and any malformed input gets one fixed message that
  names no character or offset, so a mistyped DEK never ends up in a log. `--dek-stdin`
  refuses an interactive console: pipe the DEK in rather than typing or pasting it, so
  it isn't echoed or kept in the scrollback.

  ```
  hkdfguard.exe wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>)
                     [--group|-g <name>] [--force|-f]
  ```

  The wrapped **file's** Windows ACL is protected (nothing inherited) and grants the
  owner read/write and no one else. The owner is the token owner, so Administrators when
  `wrap` runs elevated. The optional `--group|-g` adds that group, read-only. This has
  nothing to do with the KEK's own ACL, which is
  governed entirely by machine policy (see "Deployment model" above), not by anything
  passed on this command line. Name a dedicated group for the service that will read
  the file, for example a local group `App_1234` whose only member is that service's
  account. The group must already exist. Over-broad groups are refused, because anyone
  who can read the file can copy it, and the payload format deliberately allows an
  older payload to be swapped in (see above). Refused groups are `Everyone`,
  `Authenticated Users`, `BUILTIN\Users`, `BUILTIN\Guests`, `NT AUTHORITY\Local account`,
  `NT SERVICE\ALL SERVICES`, `This Organization`, the logon-type groups, the
  authentication-package groups (`NTLM Authentication` and its siblings), `IUSR` and
  `IIS_IUSRS` (every anonymous IIS request and every IIS application pool), `DIALUP`,
  `OTHER ORGANIZATION`, the local SAM's `None` group and the anonymous and NULL
  principals - the same set refused as a
  KEK key-use group. As for a
  key-use group, the group must be on this host (a local group, `BUILTIN`, `NT AUTHORITY`
  or `NT SERVICE`): a domain group is refused, since its members could never be granted
  the KEK to unwrap the file. Repeating any flag (`-kf`, `-sn`, `-g`, `-f`, the DEK source)
  is a usage error rather than the last value winning.

  `--key-file-path` must be a real local file reached through real directories. A
  symbolic link, junction, or other reparse point at the path or anywhere above it
  is refused, never followed, with or without `--force` - so a link planted in the
  output directory cannot redirect a (possibly elevated) `wrap --force` at some other
  file. Paths through a SUBST or mapped network drive are refused for the same
  reason; put the file on a real local path. So is a path that spells any folder with
  its 8.3 short name (`PROGRA~1`): use full names, and expand a path taken from `%TEMP%` or
  another environment variable first, since Windows can set those with short names. An
  existing file with more than one
  hard link is refused too, so `--force` cannot overwrite a file at some other path
  that shares its data.

  The folders above `--key-file-path` must be ones `hkdfguard_open_file` will read from
  (see above): owned by an account it trusts under the security model in force, and -
  below the drive root - letting no other account create, delete or rename entries in
  them. `wrap` asks the library who is trusted, so the two can't disagree. `wrap`
  checks this up front, before it reads the DEK or touches a key storage provider, and
  refuses with the folder, the account and the `icacls` commands that fix it (or, for
  `C:\ProgramData` and `C:\Windows\Temp`, a pointer to a folder of its own instead). `wrap`
  never creates a missing folder - one it made would inherit its parent's permissions,
  create rights included - so prepare the folder first, as
  [docs/admin-guide.md](docs/admin-guide.md#where-to-keep-key-files) describes.

  Under the production security model, `wrap` persists a key file only for an elevated
  administrator or a member of a deployer group; for any other account it refuses before
  touching the file, since `hkdfguard_open_file` would refuse a key file that account
  wrote. Wrapping in memory through the library is not restricted.

- **`status`** - read-only. Reports the payload version this host uses, whether the
  service has a KEK of that version, which provider holds it and its fingerprint. It also
  lists any other key under the service's name: on the provider the `KeyStoragePolicy`
  doesn't select, or of the other payload version. Such a key is unused today, but a
  policy change would pick it up. Exits `0` whenever it got a definite answer (present,
  absent, corrupt or unusable) and `1` when it couldn't tell (for example, access
  denied, or a TPM that can't be reached to check a version 2 TPM KEK).

  It also prints the security model in force and whether the calling account may persist
  key files under it.

  ```
  hkdfguard.exe status --service-name|-sn <name>
  ```

- **`retire`** - deletes a service's KEK. **Every DEK wrapped under it becomes
  permanently unrecoverable**, so retire a KEK only after the service has moved to a
  new, versioned service name. It is the only command that deletes keys. It lives in
  the CLI, not the library, so no application that loads `HkdfGuard.dll` can wipe a
  KEK in one call. It must run elevated, and it deletes only after the operator proves
  which key they mean:

  - `--fingerprint|-fp <hex>`: the 64 hex characters `provision` printed. The key under
    the service's name must be a valid KEK with exactly that fingerprint.
  - `--corrupt`: for a key under the service's name that definitely fails its KEK
    checks, so has no fingerprint - for version 1, a key that is not a P-256 ECDH key;
    for version 2, a key that is not the TPM's HMAC-SHA-256 key or the software key
    store's SP 800-108 key, or is exportable. A key that merely couldn't be checked is
    never treated as corrupt, and neither is a version 2 key whose only fault is its
    access list: `status` reports that as `access list invalid`, and the fix is to restore
    the ACL, not to retire the key.

  It retires the KEK of this host's payload version; `--version 1|2` picks the other's.
  A service can have a key on both the TPM and the software provider. Then `retire`
  refuses to choose, and `--provider tpm|software` picks one. A version 1 key is opened
  once, checked, and deleted through that same handle, so what is deleted is exactly what
  was checked; a version 2 key is checked and deleted by the library's own version 2
  code, which the CLI compiles in. The name is then re-opened to confirm the key is gone.
  Each retirement is logged as event 1004 with the fingerprint and the calling user.

  ```
  hkdfguard.exe retire --service-name|-sn <name> (--fingerprint|-fp <hex> | --corrupt)
                       [--provider tpm|software] [--version 1|2]
  ```

Example, from an elevated PowerShell prompt - provisioning a KEK once, then wrapping a
freshly-generated DEK under it on every later release:

```powershell
# One-time, elevated: create the KEK for this service if it doesn't already exist.
.\hkdfguard.exe provision --service-name myapp

# One-time: a dedicated local group for the account that will read the wrapped file.
net localgroup App_1234 /add
net localgroup App_1234 "NT SERVICE\MyAppService" /add

# One-time: a key folder no other account can create, delete or rename entries in
# (not under C:\ProgramData - see docs/admin-guide.md, "Where to keep key files").
# Deployers get Modify, so they can write key files; everyone else reads.
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "HkdfGuardDeployers:(OI)(CI)M"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T

# Every release, as a deployer or elevated administrator: mint a random 32-byte DEK and
# wrap it, piping the base64 DEK to the tool's stdin rather than passing it as an argument.
$dekBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes)
$dekBase64 = [Convert]::ToBase64String($dekBytes)
$dekBase64 | .\hkdfguard.exe wrap `
    --key-file-path C:\HkdfGuardKeys\myapp\myapp.v1.key --service-name myapp `
    --dek-stdin --group App_1234 --force
```

`--help`/`-h` at the top level, or after any subcommand, prints the usage text. Exit code `0` is success, `2` is a usage/argument error (nothing was attempted),
and `1` is an operational failure (parsing succeeded but the operation itself failed -
see the printed `error: ...` text and `include/hkdfguard.h`'s `HKDFGUARD_ERR_*` codes
for what it means). There is no `unwrap` subcommand - unwrapping is DLL-only; see
"Consuming from other languages" below for calling `hkdfguard_unwrap_dek` directly.

## Building

Requires CMake 3.20+, a Windows 10/11 SDK, and an MSVC C++20 toolchain (Visual Studio
2022 Build Tools with the "Desktop development with C++" workload, or equivalent).

**Recommended: `scripts\run-build-test-verify.bat`.** Double-click it, or run it from
any shell. It's a thin, self-elevating wrapper: if the shell it's launched from isn't
already Administrator, it relaunches itself with a UAC prompt, then hands off to
`scripts\Build-Test-Verify.ps1` (below) and forwards it any arguments you passed.
Elevation is required up front because both `ctest` and the end-to-end verification
step create machine-wide KEKs.

```
scripts\run-build-test-verify.bat [-Configuration Release] [-Group "Some Group"] [-NoCleanup]
```

**`scripts\Build-Test-Verify.ps1`** does the actual work, and can also be run directly
from an *already*-elevated shell (it checks for Administrator itself and refuses to
proceed otherwise) if you'd rather skip the UAC prompt:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\Build-Test-Verify.ps1 -Configuration Debug -Group App_1234
```

It locates the MSVC/CMake/Ninja toolchain from the Visual Studio Build Tools install,
configures and builds the project, runs the full `ctest` suite (see below), then does
one further end-to-end check outside of `ctest`: provisions a throwaway KEK, wraps a
random 32-byte DEK with the real CLI, and independently unwraps it via a direct
P/Invoke call into the built DLL - proving the CLI's output is actually consumable by
an external caller, not just by the CLI itself. Parameters:

- **`-Configuration`** (`Debug` or `Release`, default `Debug`) - the CMake build
  configuration to use.
- **`-Group`** (default `Administrators`) - the group passed to the verification
  wrap's `--group`, i.e. who gets read-only access to the throwaway wrapped-key file
  it produces. It must be an existing group that `--group` accepts, so not an
  over-broad one such as `Users`; the default is used because it exists on every
  machine.
- **`-NoCleanup`** - skip deleting the verification KEK and wrapped-key file
  afterward, if you want to inspect them.

Or build and test manually, from an already-elevated shell:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

**`ctest` must run from an elevated (Administrator) shell.** `hkdfguard_create_kek`
creates a machine-wide KEK (`NCRYPT_MACHINE_KEY_FLAG`) the first time a given service
name is used, and that creation step fails outright without elevation - see "Deployment
model" above.

This produces `build/HkdfGuard.dll` (+ its `.lib` import library) and
`build/tools/hkdfguard.exe`, and registers four tests with `ctest`:

- **`roundtrip`** (`tests/test_roundtrip.cpp`, built to `build/tests/test_roundtrip.exe`)
  exercises the public ABI end to end, by linking directly against the built DLL: KEK
  provisioning (`hkdfguard_kek_exists`/`hkdfguard_create_kek`, including that wrap fails
  with `KEK_NOT_FOUND` before a KEK is provisioned), a basic wrap/unwrap roundtrip and
  KEK reuse across repeated calls, case-insensitive service names, the `KeyUseGroups`
  policy (rejecting over-broad/non-local/non-group entries before touching the key
  store), all three `KeyStoragePolicy` values (`RequireTpm`/`SoftwareOnly`/`PreferTpm`,
  forced via an internal test-only seam so this doesn't depend on the machine's real
  registry policy or TPM availability), invalid-argument and buffer-too-small handling,
  that the output buffer is zeroed on every malformed-payload/authentication-failure/
  KEK-mismatch path, and `hkdfguard_generate_and_wrap_dek`. It never spawns the CLI. Run
  it directly (the DLL must be findable - `ctest` arranges this automatically via
  `tests/CMakeLists.txt`'s `ENVIRONMENT PATH` property, but a direct run needs it on
  `PATH` yourself):

  ```
  build\tests\test_roundtrip.exe
  ```

- **`cli`** (`tests/test_cli.ps1`) exercises `hkdfguard.exe`'s own
  subcommand dispatch, argument parsing, validation, and file-handling by spawning the
  real built `.exe` as a subprocess - including, when elevated, a full
  provision-then-wrap-then-`--force`-overwrite run through it, and (unconditionally,
  since it needs no elevation) that `wrap` against a never-provisioned service reports
  a clear error rather than silently failing or creating a KEK. It takes the CLI's path
  as a required parameter, so it can also be pointed at any build of the tool:

  ```powershell
  powershell -ExecutionPolicy Bypass -File tests\test_cli.ps1 -CliExePath build\tools\hkdfguard.exe
  ```

- **`harden_process`** (`tests/test_harden_process.cpp`) checks
  `hkdfguard_harden_process` from outside the hardened process: it starts a copy of
  itself, hardens it, and confirms a same-user process can no longer dump, debug or
  inject into it.

- **`roles`** (`tests/test_roles.ps1`, with `tests/role_probe.cpp`) checks the
  production security model with real, separate accounts. It creates a throwaway
  deployer account and application account, then runs the CLI and a small probe of the
  public ABI as each: the deployer persists a key file, the application unwraps it and
  wraps ephemeral keys, and the application is refused when it tries to persist or
  overwrite a key file. Elevated only; skipped otherwise.

Every test deletes what it creates - KEKs, accounts, groups, folders - and restores any
policy value it set for its run, so repeated runs leave the machine as they found it.
`roundtrip` and `cli` set `SecurityModel` to developer while they run the checks written
for it, and put the previous value back afterwards.

Run the full suite elevated on a machine with an active TPM to exercise the
`RequireTpm`/`PreferTpm` policy checks against the real TPM-backed ECDH + HKDF path
(`provider_type` resolves to 1, the Platform Crypto Provider) rather than just the
software fallback. The Software Key Storage Provider path (`provider_type` 2) shares the
same code apart from which NCrypt provider name is opened, and is exercised by the same
suite's `SoftwareOnly` policy check regardless of whether a TPM is present.

**TPM tests are the developer's and maintainer's responsibility.** CI runners and the
container tests have no TPM, so the TPM-only checks there print `[SKIP]` - a CI pass
does not cover them. Developers changing key storage code, and the maintainer before
tagging every release, must run `scripts\run-build-test-verify.bat -Configuration Release`
on a machine with an active TPM and confirm `TPM provider available: yes` and no
`[SKIP]` lines for the TPM sections (`PreferTpm, TPM probe error` and
`PreferTpm, existing TPM KEK fails verification`) in the roundtrip output.

## Testing and compatibility

This library has been exercised end to end - KEK creation, wrap, unwrap, and
the `RequireTpm`/`PreferTpm`/`SoftwareOnly` policy paths - against:

- **Intel PTT** (Platform Trust Technology - Intel's firmware TPM), via the
  Microsoft Platform Crypto Provider
- **AMD fTPM** (firmware TPM), via the Microsoft Platform Crypto Provider -
  see `SecurityAssumptions.md` section 4 for the specific provider quirks
  found (and accommodated in `src/kek_store.cpp`) on this vendor
- An **STMicroelectronics discrete TPM** (manufacturer `STM`, firmware
  71.12.17568.4100, TPM 2.0 library revision 1.16), via the Microsoft Platform
  Crypto Provider, on Windows 11 build 26200 - through the test suites
- The **Microsoft Software Key Storage Provider** (the software fallback
  path), which is vendor-independent

Payload version 2's TPM KEK - an HMAC-SHA-256 key in the Platform Crypto
Provider - has run on all three hardware TPMs above: the AMD fTPM, Intel PTT
and the STMicroelectronics discrete TPM. The full test suite has also passed on
a **Hyper-V virtual TPM** (manufacturer `MSFT`, 8213.275.21.18467) in Windows
Server 2022 (build 20348) and Windows Server 2025 (build 26100) guests.

Discrete TPMs from other vendors - **Infineon**, **Nuvoton** - have **not yet
been tested**. They are legitimate Microsoft Platform Crypto Provider backends
and are expected to work, but a TPM's own firmware could in principle report
key properties or usage flags differently than the TPMs above do - see the
accommodation table in `SecurityAssumptions.md` section 4 before assuming a new
vendor behaves identically. If you do exercise this library against one,
please fold the result (and any new quirks) back into that section. On any
discrete TPM, whether version 2's HMAC output is protected on the bus is still
open (`SecurityAssumptions.md` section 17).

## Audit logging

The DLL writes security-relevant events to the Windows **Application** event log, source
`hkdfguard-native-windows`. The MSI registers that source; without it the events are
still recorded, just shown in Event Viewer with a "description cannot be found"
preamble. Each event's text names the API call, the service, the `HKDFGUARD_ERR_*`
code, and the calling process. The event's User field is the calling account,
including the impersonated client when a service acts on someone's behalf.

| ID | Level | When |
|---|---|---|
| 1000 | Information | A KEK was created (not merely found). |
| 1001 | Warning | A KEK was created on the software provider because `PreferTpm`'s TPM attempt failed, so it isn't hardware-protected. |
| 1002 | Information | A DEK was wrapped (`hkdfguard_wrap_dek` or `hkdfguard_generate_and_wrap_dek`). |
| 1003 | Information | A DEK was unwrapped. 1002 and 1003 both record the payload version, the KEK fingerprint and a SHA-256 of the payload. |
| 1004 | Warning | A KEK was retired (deleted) by `hkdfguard.exe retire`. Names the service, the provider and the fingerprint, or why the key was corrupt. Written by the CLI; the library has no delete. |
| 1005 | Warning | `hkdfguard_open_file` read a key file under the developer security model, which trusts the caller's own key files. Once per process. Not expected on a production machine. |
| 2000 | Warning | `KEK_ACCESS_DENIED` on any call: use of a KEK by an unauthorized account, or provisioning without elevation. |
| 2002 | Error | `KEK_INVALID`: an existing KEK under the service name has an ACL this library would never create. Investigate it. |
| 2003 | Warning | `PAYLOAD_AUTH_FAILED`, `KEK_FINGERPRINT_MISMATCH`, `PAYLOAD_MALFORMED`, `PAYLOAD_UNSUPPORTED` or `PAYLOAD_VERSION_REFUSED` on unwrap: a tampered, corrupted, misdirected or unknown-version payload, or one of the payload version this host doesn't use. |
| 2004 | Error | `POLICY_INVALID` or `WIN_GROUP_INVALID`: the registry policy is misconfigured, so calls fail closed. |
| 2005 | Error | `PROVIDER_ERROR`, `CRYPTO_ERROR` or `INTERNAL_ERROR`: the key storage provider or crypto layer failed. |
| 2006 | Error | `hkdfguard_open_file` refused a file that looks like an unwrapped DEK (32 raw bytes, or its hex or base64), so possibly a plaintext key on disk. Names the file; none of its contents are logged or returned. Investigate it. |
| 2007 | Warning | A process made more than 10 `hkdfguard_create_kek` / `hkdfguard_kek_exists` calls. They are meant to run once at startup, so a caller is probably looping on them. Logged once per process. |
| 2008 | Error | `PROVIDER_UNAVAILABLE`: payload version 2 is unavailable on this host. Names the reason: the Platform Crypto Provider can't be opened, no TPM device, or the TPM can't create an HMAC-SHA-256 key - and the fixes. Logged on every failing call. |

The wrap and unwrap events also record the KEK's fingerprint and a SHA-256 of the
wrapped payload. Both are public values that reveal nothing about the DEK. Because the
same payload produces the same hash in its wrap event and in every later unwrap event,
you can tie each unwrap back to the wrap that produced it. That also makes a substituted
older payload visible, which matters because the format deliberately allows rollback
(see the note on what a payload is bound to). To compute a wrapped file's hash for
comparison: `(Get-FileHash <file> -Algorithm SHA256).Hash.ToLower()`.

Deliberately not logged: caller mistakes (`INVALID_ARGUMENT`, `BUFFER_TOO_SMALL`,
`INVALID_SERVICE_NAME`) and `KEK_NOT_FOUND`. `hkdfguard_open_file` writes only event 2006;
its other failures (a missing, unreadable, wrong-sized or malformed file, or a rejected
path) involve no KEK and are reported to the caller alone. No key material is ever logged. Every
successful wrap and unwrap writes one event, which suits deployment-time wrapping and
unwrap-at-service-start.

**Turning off unwrap-success events.** For a caller that legitimately unwraps often, an
administrator can turn off event 1003 alone with a REG_DWORD value:

```
reg add HKLM\Software\Policies\HkdfGuard /v AuditUnwrapSuccess /t REG_DWORD /d 0 /f
```

Only an explicit REG_DWORD `0` turns it off. A missing value, any non-zero DWORD, or a
value of the wrong type all leave it on, so a misconfigured value can't silently reduce
auditing. The value is read on every unwrap, so a change takes effect without
restarting the calling process. It affects nothing else: wrap events and every failure
event, including failed unwraps, are always written. With it off, the log no longer
shows who unwrapped successfully or which payload they used. Logging
is best effort and can never change a call's result. Any local user can write to the
Application log, so treat these events as an operational aid, not tamper-proof
evidence. Forward them to your SIEM if you need retention. Running the test suites
writes a burst of these events, since the tests exercise the failure paths on purpose.

To list recent events from PowerShell:

```powershell
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='hkdfguard-native-windows']]]" -MaxEvents 50 |
    Format-Table TimeCreated, Id, LevelDisplayName, UserId, Message -Wrap
```


## Setup calls are deliberately slow

`hkdfguard_create_kek` and `hkdfguard_kek_exists` are meant to run once per application
startup, so each takes **at least one second** of wall-clock time whatever its outcome
(found, not found, or error), and they run one at a time across threads. This bounds how
fast a buggy or hot-looping caller can drive the TPM: every call opens a fresh key storage
provider handle. Argument errors (null pointer, invalid service name) still return
immediately, since they never reach a provider. After more than 10 setup calls in one
process, event 2007 is logged once.

The floor is about load, not secrecy. `hkdfguard_wrap_dek` is the hot path and is not
slowed, and it answers `KEK_NOT_FOUND` (`-17`) at once for a service with no KEK. Treat
service names as public identifiers, never as secrets.

An administrator can tune the floor per host with a REG_DWORD value, in milliseconds (up
to 60000; `0` disables it):

```
reg add HKLM\Software\Policies\HkdfGuard /v SetupMinDelayMs /t REG_DWORD /d 1000 /f
```

A missing value means 1000. A value above 60000, or of the wrong type, also keeps the
1000 ms default: a typo can neither remove the floor nor turn startup into a long hang.
It is read on every setup call.

## Design

- **Crypto, version 2** (the default): NIST SP 800-108 in counter mode with the KEK as the
  PRF's key, then AES-256-GCM (`src/sp800_108.h`, `src/kek_v2.h`). The wrapping key is
  `PRF(KEK, [1]_32 || "hkdfguard-wrap-v1" || 0x00 || u16le(len(service)) || service ||
  header || [256]_32)` and the KEK fingerprint the same over the label
  `"hkdfguard-kek-fingerprint-v1"` and an empty context - byte for byte the Linux
  library's construction, pinned by its known-answer values in `tests/test_v2_kek.cpp`.
  The PRF is HMAC-SHA-256 keyed by the KEK, and both KEKs are persisted, non-exportable
  NCrypt machine keys with version 1's ACL, so the provider checks the caller on every
  use. In the TPM the KEK is an `HMAC-SHA256` key in the Platform Crypto Provider, with
  the PCP's signature key usage; `NCryptSignHash` over the block returns its HMAC,
  computed in the TPM. In the Software Key Storage Provider the KEK is an
  `SP800_108_CTR_HMAC` key; `NCryptKeyDerivation` builds the same block from the label
  and context and returns the same HMAC. Each process checks the software key store's
  derivation against BCrypt's HMAC-SHA-256 with a throwaway key before first using it.
  The TPM's HMAC can't be checked that way (the PCP won't import a known key); the KEK
  fingerprint, itself a PRF output, pins it instead. Wrapping needs the KEK, as in
  version 1, so **only an account authorized to use the KEK can create a payload**; and
  there is no public key at all. The AES-256-GCM step and the
  fingerprint check are as for version 1, below.
- **Crypto, version 1** (`ClassicalMode` = `1`): ECDH (P-256) between the KEK's private key and a point hashed from a
  random per-payload salt, then HKDF-SHA512 and AES-256-GCM. Each wrap draws a 32-byte
  salt and hashes it to a P-256 point `H(salt)` (`src/hash_to_curve.cpp`: RFC 9380
  `P256_XMD:SHA-256_SSWU_RO_`, checked against the RFC's test vectors). The shared
  secret `Z = ECDH(KEK private key, H(salt))` is computed by `NCryptSecretAgreement` on the
  KEK's own provider - inside the TPM for a Platform Crypto Provider KEK - for wrap and
  unwrap alike, taken out raw (`BCRYPT_KDF_RAW_SECRET`) and reversed to big-endian, then
  fed to one self-contained HKDF-SHA512 implementation: salt = the payload salt, info =
  `"hkdfguard-wrap-v1:"` || `u16le(len(service))` || normalized service || the payload's
  header (bytes 0..39) || KEK fingerprint, pinned by a golden payload in the test suite.
  Nobody knows the discrete log of
  `H(salt)`, so **only an account authorized to use the KEK can create a payload**:
  knowing the KEK's public key is not enough to forge one. Every wrap is therefore a use
  of the KEK's private key - a TPM operation of about 10 ms for a TPM-backed KEK. See
  `src/ecdh_hkdf.cpp` for the derivation design note. The AES-256-GCM step authenticates
  the same header || fingerprint bytes as additional authenticated data
  (`src/aes_gcm.cpp`'s `AesGcmEncrypt`/`AesGcmDecrypt`, called from `src/hkdfguard.cpp`).
  So the service, the version, the routing fields and the specific KEK are bound into
  the wrapping key itself, and every header byte is also checked by the tag. The
  fingerprint also travels in the payload and is
  checked against the opened KEK before any ECDH or decryption, so "wrong KEK"
  (`HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH`) is distinguishable from tampering
  (`HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED`).
- **Wire format**: `src/wire_format.h` documents the exact 132-byte layout, shared by
  both versions (version, provider type, key id, salt, AES-GCM nonce/ciphertext/tag, KEK
  fingerprint), serialized field-by-field rather than via a packed
  C struct so the format has no dependency on compiler struct-packing rules.
- **KEK lifecycle**: the version 2 KEK lives in `src/kek_v2.cpp`, with the same
  `KeyStoragePolicy` rules, ACL, creation-only and verify-on-every-open behavior as the
  version 1 KEK described here, under its own names (version 1's with `_hmac` for the
  TPM key or `_kdf` for the software key). For
  version 1, `src/kek_store.cpp` creates the KEK (Platform Crypto Provider first,
  falling back to Software KSP under `PreferTpm`) only via `hkdfguard_create_kek`, which
  also applies the `KeyUseGroups`-driven ACL and is idempotent - safe to call again for
  an already-provisioned service, which just re-verifies it - including that the existing
  key's ACL is a real DACL with SYSTEM and Administrators on it and grants nothing to an
  over-broad principal such as Everyone (`HKDFGUARD_ERR_KEK_INVALID` otherwise; the
  key is left untouched). Wrap, unwrap and `hkdfguard_kek_fingerprint` apply the same
  check whenever the calling account can read the KEK's ACL, so a KEK widened after
  provisioning is refused as soon as an administrator or deployer uses it. Key use
  is granted as `GENERIC_READ`, which normally includes reading the ACL, so an
  application account will likely get the check too (untested); if it can't read
  the ACL, the provisioning-time check stands for it. `hkdfguard_wrap_dek` and `hkdfguard_unwrap_dek` only ever *open*
  an existing KEK, never create one; unwrap opens the exact provider/key recorded in the
  payload. Every create/open/delete call passes `NCRYPT_MACHINE_KEY_FLAG` (and
  `NCRYPT_SILENT_FLAG`, so a key with an unexpected UI-requiring protection policy fails
  instead of prompting) - see the Deployment model note above. If a newly created key fails
  any post-finalize verification step, that same call deletes it before reporting the
  error, so a later wrap can't silently end up using a key that was never fully verified.
  An *existing* KEK is never deleted or replaced by any library call. Only the CLI's
  `retire` deletes one, after the operator confirms its fingerprint.
- **Memory security**: `src/secure_buffer.h` (RAII `SecureZeroMemory` wrapper) and
  `src/handle_traits.h` (RAII closers for every NCrypt/BCrypt handle type) ensure key
  material and handles are wiped/closed on every exit path, including exceptions. Every
  ABI entry point in `src/hkdfguard.cpp` catches every exception; `hkdfguard_unwrap_dek`
  additionally zeros the caller's output buffer on any failure (it calls into a CNG
  function - `BCryptDecrypt` - that can write unauthenticated plaintext before reporting
  a tag mismatch).

## Installing on target machines

> Administrators deploying a release: see the
> [Installation and Administration Guide](docs/admin-guide.md) for downloading,
> verifying, installing, provisioning services, policy settings and troubleshooting.
> This section covers building the installer.

The DLL and CLI are installed machine-wide by an MSI, not shipped inside application
packages (NuGet or otherwise). Each machine gets exactly one copy, in a folder only
administrators can change, and applications load it from there.

**Building signed distributables** (no elevation needed). One command builds both
architectures, signs everything, and with `-Msi` also builds the signed installers:

```
scripts\build-dist-signed.bat
scripts\build-dist-signed.bat -Msi -Version 0.9.0
```

`scripts\Build-Dist-Signed.ps1` checks the signing setup first, then runs `Build-Dist.ps1
-Sign` (or `Build-Msi.ps1 -Sign` with `-Msi`) for x64 and ARM64. Afterwards it verifies
that every artifact has a valid, timestamped signature and prints each one's SHA-256. Use
`-Arch x64` or `-Arch ARM64` for one architecture. `Build-Dist.ps1` and `Build-Msi.ps1`
also take `-Sign` on their own.

Signing uses [Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/)
through `scripts\ArtifactSigning.ps1`. The signing machine needs:

- The Windows SDK's signtool, version 10.0.22621 or later. The scripts pick the newest x64
  copy automatically.
- .NET 8 or later, for the signtool plugin. The scripts fetch the plugin themselves on first
  use: Microsoft's `Microsoft.ArtifactSigning.Client` NuGet package, pinned by version and
  SHA-256 (the same package the release workflow uses), cached in
  `%LOCALAPPDATA%\HkdfGuard\signing`. Every run re-checks the cached plugin's hash and its
  Microsoft signature. The winget client tools aren't used: their installer ships the
  plugin unsigned. A plugin named with `-SigningDlib` or `HKDFGUARD_SIGNING_DLIB` must be
  Microsoft-signed.
- `scripts\signing\metadata.json`, which names the account's regional endpoint, the
  account and the certificate profile. It holds no secrets. The endpoint must match the
  account's region, or signing fails with a 403.
- An Azure CLI sign-in (`az login`) for an account holding the **Artifact Signing
  Certificate Profile Signer** role.

Artifact Signing certificates are valid for three days, so every signature is
timestamped, and the scripts fail on any signature that isn't. The certificate key never
leaves Microsoft's HSMs, so there is no certificate file or thumbprint to manage.

**Building the MSI on its own** (no elevation needed):

```
scripts\build-msi.bat -Arch x64 -Version 0.9.0 -Sign
```

`scripts\Build-Msi.ps1` clean-builds Release via `Build-Dist.ps1`, signs both binaries
*before* packaging and then the MSI itself, and writes
`dist\hkdfguard-native-windows-<version>-win-<arch>.msi`. `-Arch` is `x64` or `ARM64`.
`-Version` must increase with every release, or the upgrade won't replace the installed
copy. Omitting `-Sign` produces an unsigned MSI, which is for local testing only.
Afterwards the script reads the built MSI's own tables back and fails if the
package doesn't install exactly what's described below. The WiX toolset (5.0.2) is
pinned in `dotnet-tools.json` and restored automatically; only the .NET SDK is required.

**Installing** (elevated; deployable as-is through Intune, SCCM or Group Policy):

```
msiexec /i hkdfguard-native-windows-0.9.0-win-x64.msi /qn /l*v install.log
```

The MSI does four things:

- **Installs both files** to `C:\Program Files\HkdfGuard\v1\`. That folder
  inherits the Program Files ACL, where only Administrators, SYSTEM and TrustedInstaller
  can write. This is what stops a less-privileged user from planting a fake DLL next to
  the CLI and getting code execution the next time an administrator runs the elevated
  `provision` step. The location is deliberately not overridable from the `msiexec`
  command line, so nobody can redirect the install into a user-writable folder.
- **Records the folder** in `HKLM\Software\hkdfguard-native-windows`, value `InstallPath`
  (`REG_SZ`, with a trailing backslash). Only administrators can change it.
- **Registers the event log source** `hkdfguard-native-windows`, so the audit events
  described under "Audit logging" render cleanly in Event Viewer.
- **Creates the local groups `HkdfGuardUsers` and `HkdfGuardDeployers`** if they don't
  already exist. KEKs created while they exist grant both use access. Add application
  accounts to `HkdfGuardUsers`, and the accounts that deploy key files to
  `HkdfGuardDeployers`, which the production security model trusts to have written them.
  A group has to exist before a service's KEK is provisioned to be included, so install
  the MSI first. The MSI does not create the optional
  `HkdfGuardAdmins` group (full control of KEKs created while it exists); create it
  yourself, before provisioning, only if you want to delegate key administration.

Then, once per service, elevated:

```
"C:\Program Files\HkdfGuard\v1\hkdfguard.exe" provision --service-name myapp
```

**Upgrades** remove the previous version before installing the new one. A service with
the DLL loaded keeps it locked, so stop those services first, or Windows Installer will
ask to close them or schedule a reboot.

**Uninstalling** removes the files, the `InstallPath` value and the event source
registration (past events keep their text), and deliberately nothing
else:

- **KEKs are never touched.** Deleting one destroys every DEK wrapped under it.
- **The `HkdfGuardUsers` and `HkdfGuardDeployers` groups are kept.** Every KEK created
  while they existed has their SIDs in its ACL. A recreated group gets a new SID, which
  would silently lock its members out of those KEKs, and make deployers' key files
  untrusted.

No policy value (`KeyStoragePolicy`, `KeyUseGroups`, `SecurityModel`, `DeployerGroups`
and the rest) is set by the MSI. They stay with whatever already manages machine policy
(Group Policy, Intune, SCCM).

## Consuming from other languages

This repository only implements the native Windows library and its C ABI. To call it
from C#, Python, Java, Go, or Node, install the MSI above and bind to the installed
`HkdfGuard.dll` with the platform's standard FFI mechanism.

**Load it by its full, known path - never by a bare filename.** Every binding below that
accepts just a name (`"HkdfGuard.dll"`, `Native.load("HkdfGuard", ...)`, a bare-name
`[DllImport]`, ...) resolves it through the operating system's standard DLL search order,
which - depending on the host process's configuration - can include the current working
directory or other locations a lower-privileged or otherwise unexpected file could
occupy. Since this library exists specifically to protect a Data Encryption Key, a
process that can get a different DLL loaded in its place has effectively compromised
whatever secret the real library would have protected, however carefully the real
library guards it. Resolve the absolute path from the `InstallPath` registry value the MSI
writes (relying on `PATH` search, or on a copy sitting in your own application folder, is
not equivalent) and load *that*, and
prefer an explicit, non-searching load API over a bare-name one wherever the binding
layer offers one (e.g. .NET's `NativeLibrary.Load(absolutePath)` over a bare-name
`[DllImport]`; `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` over a bare
`LoadLibrary`). For any deployment where the host filesystem isn't already fully
trusted, also sign the shipped DLL (Authenticode) and verify that signature before
loading it.

- **C#**: `NativeLibrary.Load(<absolute-path>)` plus `GetExport`/delegates, which never
  performs a name-based search at all. The calling process must match the installed
  architecture: an x64 process for the x64 MSI, an ARM64 process for the ARM64 MSI. A
  32-bit process, or an x64 process on an ARM64 machine with the ARM64 MSI installed,
  cannot load the DLL. Read the path from the 64-bit registry view:

  ```csharp
  using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
  using var key = hklm.OpenSubKey(@"Software\hkdfguard-native-windows")
      ?? throw new InvalidOperationException("hkdfguard-native-windows is not installed");
  string dir = (string)key.GetValue("InstallPath")!;
  IntPtr lib = NativeLibrary.Load(Path.Combine(dir, "HkdfGuard.dll"));
  ```
- **Python**: `ctypes.WinDLL(r"<absolute-path>\HkdfGuard.dll")`
- **Java**: JNA's `NativeLibrary.getInstance("<absolute-path>")`, or a thin JNI shim that
  calls `LoadLibraryW` with an absolute path
- **Go**: `cgo` linking against `HkdfGuard.lib` (resolved at link time, not
  a runtime search - the safest option of all here), or, for dynamic loading,
  `golang.org/x/sys/windows.LoadLibraryEx(absPath, 0,
  LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`
- **Node**: `ffi-napi`/`koffi` given an absolute path, or a native addon (N-API) linking
  `HkdfGuard.lib`

All five bindings map directly onto the eleven exported functions
(`hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`, `hkdfguard_create_kek`,
`hkdfguard_wrap_dek`, `hkdfguard_unwrap_dek`, `hkdfguard_generate_and_wrap_dek`,
`hkdfguard_open_file`, `hkdfguard_harden_process`,
`hkdfguard_harden_process_with_flags`, `hkdfguard_security_model`,
`hkdfguard_key_file_principal_trusted`) and the status codes in
`include/hkdfguard.h`; none of them need to know anything about TPMs, CNG, or NCrypt.

## License

Mozilla Public License 2.0 (MPL-2.0) - see [LICENSE](LICENSE).
