# hkdfguard-native-windows

Windows-native Key Wrapper.
Wraps and unwraps a 32-byte key using a persistent, machine-wide scoped, non-exportable
P-256 ECDH Key Encryption Key (KEK) held by a TPM/vTPM via the Microsoft Platform Crypto
Provider, or by the Microsoft Software Key Storage Provider - which one is machine
policy (see "Key storage policy" below); the default prefers the TPM and falls back to
software when no TPM is available (bare servers, VMs without a vTPM, containers).

**Key storage policy**: the `REG_DWORD` value `HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy`
selects the provider: `0` = `PreferTpm` (the default when the value is absent - TPM if
available, otherwise software), `1` = `RequireTpm` (TPM or fail; never falls back),
`2` = `SoftwareOnly`. It is read on every call, so it also governs which provider an
existing KEK is *looked for* on. Under `RequireTpm` a payload that routes to a
software-backed KEK is refused on unwrap as well (`VerifyKeyProperties` demands
hardware backing), so the policy is enforced end to end, not just at creation. A value
that is present but not one of `0`/`1`/`2` (or not a `REG_DWORD`) is a configuration
error and fails every call with `HKDFGUARD_ERR_INVALID_POLICY` - it is deliberately
*not* treated as the default, since a typo'd value most likely intended the stricter
setting. The `PreferTpm` fallback is intentional and administrator-chosen: the
`provider_type` byte in every payload records which provider actually protected it,
so a consumer that needs to know can check. It applies only when the TPM is
unusable for the service (no TPM, or the TPM key is absent and could not be created).
An existing TPM KEK that fails verification, or a TPM that errors while being probed,
fails the call instead of quietly creating or using a software KEK beside it.

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
`BUILTIN\Administrators` always get full control, and every entry of the `REG_MULTI_SZ`
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

The library exposes a small, stable C ABI (`include/hkdfguard.h`) with five functions.
No Windows handle, CNG/NCrypt type, or COM interface crosses that boundary, and no C++
exception ever escapes it - every call returns an integer status code.

```c
int32_t hkdfguard_kek_exists(
    const char* service,
    int32_t* out_exists);

int32_t hkdfguard_create_kek(
    const char* service);

int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int32_t dek_len,
    uint8_t* out, int32_t* out_len);

int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int32_t wrapped_len,
    uint8_t* out, int32_t* out_len);

int32_t hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out, int32_t* out_len);
```

`service` is a null-terminated UTF-8 string (non-empty, at most 128 bytes, ASCII letters/
digits/`.` only) identifying which persistent KEK to use - e.g. an application or tenant
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

`dek_len` must be exactly 32 (`HKDFGUARD_DEK_LEN`). A wrapped payload is always exactly
164 bytes (`HKDFGUARD_WRAPPED_LEN`) - a fixed size regardless of which KEK provider
produced it - so callers can allocate output buffers without a size-query round trip.
See `include/hkdfguard.h` for the full set of `HKDFGUARD_ERR_*` status codes.

`hkdfguard_generate_and_wrap_dek` generates its own cryptographically random 32-byte DEK
(via `BCryptGenRandom`) and wraps it in one call, for callers minting a brand new
Ephemeral Data Protection Key - the plaintext DEK never crosses back out to the caller;
it's zeroed internally the moment it's wrapped. Recover it later via
`hkdfguard_unwrap_dek` on the resulting payload, with the same `service`.

## Command-line tool

`tools/hkdfguard-v1-initialize.cpp` builds `hkdfguard-v1-initialize.exe`, a thin
wrapper around the ABI above with two subcommands:

- **`provision`** - always calls `hkdfguard_create_kek`, which creates the KEK if it
  is missing and otherwise re-verifies the existing key's properties and ACL (failing
  with `HKDFGUARD_ERR_KEK_ACL_INVALID` on a pre-planted or widened key). Never wraps a
  DEK, never touches a file. This is the *only* subcommand that can create a KEK. Run
  it elevated: creating a KEK requires elevation (see "Deployment model" above), and
  verifying an existing one reads its ACL, which a key-use-only account cannot do.

  ```
  hkdfguard-v1-initialize.exe provision --service-name|-sn <name>
  ```

- **`wrap`** - calls `hkdfguard_wrap_dek` only, against an *already-provisioned* KEK;
  it never creates one (a missing KEK fails with `HKDFGUARD_ERR_KEK_NOT_FOUND` and a
  hint to run `provision` first). The DEK is 32 raw bytes, base64-encoded, read from
  **stdin** rather than a command-line argument, specifically so it never appears in
  this process's `argv`, where another process on the same host could otherwise read
  it via a command-line/process listing (e.g. a WMI query) for the life of the run.

  ```
  hkdfguard-v1-initialize.exe wrap --key-file-path|-kf <path> --service-name|-sn <name> --dek-stdin --group|-g <name> [--force|-f]
  ```

  `--group|-g` sets the wrapped **file's** Windows ACL (owner read/write, that group
  read-only, no one else) - it has nothing to do with the KEK's own ACL, which is
  governed entirely by machine policy (see "Deployment model" above), not by anything
  passed on this command line. Name a dedicated group for the service that will read
  the file, for example a local group `App_1234` whose only member is that service's
  account. The group must already exist. Over-broad groups are refused, because anyone
  who can read the file can copy it, and the payload format deliberately allows an
  older payload to be swapped in (see above). Refused groups are `Everyone`,
  `Authenticated Users`, `BUILTIN\Users`, `BUILTIN\Guests`, `NT AUTHORITY\Local account`,
  `NT SERVICE\ALL SERVICES`, `This Organization`, the logon-type groups and the
  anonymous and NULL principals - the same set refused as a KEK key-use group.

  `--key-file-path` must be a real local file reached through real directories. A
  symbolic link, junction, or other reparse point at the path or anywhere above it
  is refused, never followed, with or without `--force` - so a link planted in the
  output directory cannot redirect a (possibly elevated) `wrap --force` at some other
  file. Paths through a SUBST or mapped network drive are refused for the same
  reason; put the file on a real local path. An existing file with more than one
  hard link is refused too, so `--force` cannot overwrite a file at some other path
  that shares its data.

Example, from an elevated PowerShell prompt - provisioning a KEK once, then wrapping a
freshly-generated DEK under it on every later release:

```powershell
# One-time, elevated: create the KEK for this service if it doesn't already exist.
.\hkdfguard-v1-initialize.exe provision --service-name myapp

# One-time: a dedicated local group for the account that will read the wrapped file.
net localgroup App_1234 /add
net localgroup App_1234 "NT SERVICE\MyAppService" /add

# Every release: mint a random 32-byte DEK and wrap it, piping the base64 DEK to the
# tool's stdin rather than passing it as an argument.
$dekBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes)
$dekBase64 = [Convert]::ToBase64String($dekBytes)
$dekBase64 | .\hkdfguard-v1-initialize.exe wrap `
    --key-file-path C:\secrets\myapp.v1.key --service-name myapp `
    --dek-stdin --group App_1234 --force
```

`--help`/`-h` at the top level, or after either subcommand, prints usage for that
level. Exit code `0` is success, `2` is a usage/argument error (nothing was attempted),
and `1` is an operational failure (parsing succeeded but the operation itself failed -
see the printed `error: ...` text and `include/hkdfguard.h`'s `HKDFGUARD_ERR_*` codes
for what it means). There is no `unwrap` subcommand - unwrapping is DLL-only; see
"Consuming from other languages" below for calling `hkdfguard_unwrap_dek` directly.

## Building

Requires CMake 3.20+, a Windows 10/11 SDK, and an MSVC C++17 toolchain (Visual Studio
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

This produces `build/HkdfGuardV1.dll` (+ its `.lib` import library) and
`build/tools/hkdfguard-v1-initialize.exe`, and registers two tests with `ctest`:

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

- **`cli`** (`tests/test_cli.ps1`) exercises `hkdfguard-v1-initialize.exe`'s own
  subcommand dispatch, argument parsing, validation, and file-handling by spawning the
  real built `.exe` as a subprocess - including, when elevated, a full
  provision-then-wrap-then-`--force`-overwrite run through it, and (unconditionally,
  since it needs no elevation) that `wrap` against a never-provisioned service reports
  a clear error rather than silently failing or creating a KEK. It takes the CLI's path
  as a required parameter, so it can also be pointed at any build of the tool:

  ```powershell
  powershell -ExecutionPolicy Bypass -File tests\test_cli.ps1 -CliExePath build\tools\hkdfguard-v1-initialize.exe
  ```

Both tests delete any KEKs they create once they finish, so repeated runs don't
accumulate persisted keys in the machine's key storage.

Run the full suite elevated on a machine with an active TPM to exercise the
`RequireTpm`/`PreferTpm` policy checks against the real TPM-backed ECDH + HKDF path
(`provider_type` resolves to 1, the Platform Crypto Provider) rather than just the
software fallback. The Software Key Storage Provider path (`provider_type` 2) shares the
same code apart from which NCrypt provider name is opened, and is exercised by the same
suite's `SoftwareOnly` policy check regardless of whether a TPM is present.

## Testing and compatibility

This library has been exercised end to end - KEK creation, wrap, unwrap, and
the `RequireTpm`/`PreferTpm`/`SoftwareOnly` policy paths - against:

- **Intel PTT** (Platform Trust Technology - Intel's firmware TPM), via the
  Microsoft Platform Crypto Provider
- **AMD fTPM** (firmware TPM), via the Microsoft Platform Crypto Provider -
  see `SecurityAssumptions.md` section 4 for the specific provider quirks
  found (and accommodated in `src/kek_store.cpp`) on this vendor
- The **Microsoft Software Key Storage Provider** (the software fallback
  path), which is vendor-independent

It has **not yet been tested** against a discrete (dTPM) hardware TPM from
**Infineon** or **Nuvoton**. Both are legitimate Microsoft Platform Crypto
Provider backends and are expected to work, but neither has actually been
run against this code. A discrete TPM's own firmware could in principle
report key properties or usage flags differently than the two firmware TPMs
above do - see the accommodation table in `SecurityAssumptions.md` section 4
before assuming a new vendor behaves identically to AMD fTPM or Intel PTT.
If you do exercise this library against either, please fold the result (and
any new quirks) back into that section.

## Audit logging

The DLL writes security-relevant events to the Windows **Application** event log, source
`HkdfGuard.Kms.Windows.v1`. The MSI registers that source; without it the events are
still recorded, just shown in Event Viewer with a "description cannot be found"
preamble. Each event's text names the API call, the service, the `HKDFGUARD_ERR_*`
code, and the calling process. The event's User field is the calling account,
including the impersonated client when a service acts on someone's behalf.

| ID | Level | When |
|---|---|---|
| 1000 | Information | A KEK was created (not merely found). |
| 1001 | Warning | A KEK was created on the software provider because `PreferTpm`'s TPM attempt failed, so it isn't hardware-protected. |
| 1002 | Information | A DEK was wrapped (`hkdfguard_wrap_dek` or `hkdfguard_generate_and_wrap_dek`). |
| 1003 | Information | A DEK was unwrapped. |
| 2000 | Warning | `ACCESS_DENIED` on any call: use of a KEK by an unauthorized account, or provisioning without elevation. |
| 2002 | Error | `KEK_ACL_INVALID`: an existing KEK under the service name has an ACL this library would never create. Investigate it. |
| 2003 | Warning | `AUTH_FAILED`, `KEK_MISMATCH` or `MALFORMED` on unwrap: a tampered, corrupted, or misdirected payload. |
| 2004 | Error | `INVALID_POLICY` or `GROUP_INVALID`: the registry policy is misconfigured, so calls fail closed. |
| 2005 | Error | `PROVIDER`, `CRYPTO` or `INTERNAL`: the key storage provider or crypto layer failed. |

The wrap and unwrap events also record the KEK's fingerprint and a SHA-256 of the
wrapped payload. Both are public values that reveal nothing about the DEK. Because the
same payload produces the same hash in its wrap event and in every later unwrap event,
you can tie each unwrap back to the wrap that produced it. That also makes a substituted
older payload visible, which matters because the format deliberately allows rollback
(see the note on what a payload is bound to). To compute a wrapped file's hash for
comparison: `(Get-FileHash <file> -Algorithm SHA256).Hash.ToLower()`.

Deliberately not logged: caller mistakes (`INVALID_ARG`, `BUFFER_TOO_SMALL`,
`SERVICE_NAME_INVALID`) and `KEK_NOT_FOUND`. No key material is ever logged. Every
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
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='HkdfGuard.Kms.Windows.v1']]]" -MaxEvents 50 |
    Format-Table TimeCreated, Id, LevelDisplayName, UserId, Message -Wrap
```

## Design

- **Crypto**: ephemeral ECDH (P-256) + HKDF-SHA512 + AES-256-GCM, matching the macOS
  Secure Enclave implementation's pattern. See `src/ecdh_hkdf.cpp` for the derivation
  design note - wrap-side and unwrap-side both extract the *raw* ECDH shared secret
  (`BCRYPT_KDF_RAW_SECRET`, works identically via `BCryptDeriveKey` and
  `NCryptDeriveKey`) and then run one shared, self-contained HKDF-SHA512
  implementation, rather than relying on two separately-implemented KDF code paths
  inside BCrypt and NCrypt. The AES-256-GCM step authenticates the normalized `service`
  name followed by a SHA-256 fingerprint of the KEK's public key as additional
  authenticated data (`src/aes_gcm.cpp`'s `AesGcmEncrypt`/`AesGcmDecrypt`, called from
  `src/hkdfguard.cpp`) - binding a wrapped payload to both the exact service and the
  specific KEK it was wrapped under. The fingerprint also travels in the payload and is
  checked against the opened KEK before any ECDH or decryption, so "wrong KEK"
  (`HKDFGUARD_ERR_KEK_MISMATCH`) is distinguishable from tampering
  (`HKDFGUARD_ERR_AUTH_FAILED`). Matches the construction this project's macOS and
  Linux implementations use.
- **Wire format**: `src/wire_format.h` documents the exact 164-byte `WrappedDekV1`
  layout (version, provider type, key id, ephemeral public key, AES-GCM nonce/
  ciphertext/tag, KEK fingerprint), serialized field-by-field rather than via a packed
  C struct so the format has no dependency on compiler struct-packing rules.
- **KEK lifecycle**: `src/kek_store.cpp` creates the KEK (Platform Crypto Provider first,
  falling back to Software KSP under `PreferTpm`) only via `hkdfguard_create_kek`, which
  also applies the `KeyUseGroups`-driven ACL and is idempotent - safe to call again for
  an already-provisioned service, which just re-verifies it - including that the existing
  key's ACL is a real DACL with SYSTEM and Administrators on it and grants nothing to an
  over-broad principal such as Everyone (`HKDFGUARD_ERR_KEK_ACL_INVALID` otherwise; the
  key is left untouched). `hkdfguard_wrap_dek` and `hkdfguard_unwrap_dek` only ever *open*
  an existing KEK, never create one; unwrap opens the exact provider/key recorded in the
  payload. Every create/open/delete call passes `NCRYPT_MACHINE_KEY_FLAG` (and
  `NCRYPT_SILENT_FLAG`, so a key with an unexpected UI-requiring protection policy fails
  instead of prompting) - see the Deployment model note above. If a newly created key fails
  any post-finalize verification step, that same call deletes it before reporting the
  error, so a later wrap can't silently end up using a key that was never fully verified.
  An *existing* KEK is never deleted or replaced by any library call.
- **Memory security**: `src/secure_buffer.h` (RAII `SecureZeroMemory` wrapper) and
  `src/handle_traits.h` (RAII closers for every NCrypt/BCrypt handle type) ensure key
  material and handles are wiped/closed on every exit path, including exceptions. All
  five ABI entry points in `src/hkdfguard.cpp` catch every exception; `hkdfguard_unwrap_dek`
  additionally zeros the caller's output buffer on any failure (it calls into a CNG
  function - `BCryptDecrypt` - that can write unauthenticated plaintext before reporting
  a tag mismatch).

## Installing on target machines

The DLL and CLI are installed machine-wide by an MSI, not shipped inside application
packages (NuGet or otherwise). Each machine gets exactly one copy, in a folder only
administrators can change, and applications load it from there.

**Building signed distributables** (no elevation needed). One command builds both
architectures, signs everything, and with `-Msi` also builds the signed installers:

```
scripts\build-dist-signed.bat
scripts\build-dist-signed.bat -Msi -Version 1.0.0
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
- The Artifact Signing client tools, which provide the signtool plugin:
  `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`. They need .NET 8 or
  later.
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
scripts\build-msi.bat -Arch x64 -Version 1.0.0 -Sign
```

`scripts\Build-Msi.ps1` clean-builds Release via `Build-Dist.ps1`, signs both binaries
*before* packaging and then the MSI itself, and writes
`dist\HkdfGuard.Kms.Windows.v1-<version>-win-<arch>.msi`. `-Arch` is `x64` or `ARM64`.
`-Version` must increase with every release, or the upgrade won't replace the installed
copy. Omitting `-Sign` produces an unsigned MSI, which is for local testing only.
Afterwards the script reads the built MSI's own tables back and fails if the
package doesn't install exactly what's described below. The WiX toolset (5.0.2) is
pinned in `dotnet-tools.json` and restored automatically; only the .NET SDK is required.

**Installing** (elevated; deployable as-is through Intune, SCCM or Group Policy):

```
msiexec /i HkdfGuard.Kms.Windows.v1-1.0.0-win-x64.msi /qn /l*v install.log
```

The MSI does four things:

- **Installs both files** to `C:\Program Files\HkdfGuard\Kms.Windows.v1\`. That folder
  inherits the Program Files ACL, where only Administrators, SYSTEM and TrustedInstaller
  can write. This is what stops a less-privileged user from planting a fake DLL next to
  the CLI and getting code execution the next time an administrator runs the elevated
  `provision` step. The location is deliberately not overridable from the `msiexec`
  command line, so nobody can redirect the install into a user-writable folder.
- **Records the folder** in `HKLM\Software\HkdfGuard\Kms.Windows.v1`, value `InstallPath`
  (`REG_SZ`, with a trailing backslash). Only administrators can change it.
- **Registers the event log source** `HkdfGuard.Kms.Windows.v1`, so the audit events
  described under "Audit logging" render cleanly in Event Viewer.
- **Creates the local group `HkdfGuardUsers`** if it doesn't already exist. KEKs created
  while the group exists grant it use access, so add the accounts that need to wrap or
  unwrap to it. The group has to exist before a service's KEK is provisioned to be
  included, so install the MSI first.

Then, once per service, elevated:

```
"C:\Program Files\HkdfGuard\Kms.Windows.v1\hkdfguard-v1-initialize.exe" provision --service-name myapp
```

**Upgrades** remove the previous version before installing the new one. A service with
the DLL loaded keeps it locked, so stop those services first, or Windows Installer will
ask to close them or schedule a reboot.

**Uninstalling** removes the files, the `InstallPath` value and the event source
registration (past events keep their text), and deliberately nothing
else:

- **KEKs are never touched.** Deleting one destroys every DEK wrapped under it.
- **The `HkdfGuardUsers` group is kept.** Every KEK created while it existed has the
  group's SID in its ACL. A recreated group gets a new SID, which would silently lock its
  members out of those KEKs.

`KeyStoragePolicy` and `KeyUseGroups` are not set by the MSI. They stay with whatever
already manages machine policy (Group Policy, Intune, SCCM).

## Consuming from other languages

This repository only implements the native Windows library and its C ABI. To call it
from C#, Python, Java, Go, or Node, install the MSI above and bind to the installed
`HkdfGuardV1.dll` with the platform's standard FFI mechanism.

**Load it by its full, known path - never by a bare filename.** Every binding below that
accepts just a name (`"HkdfGuardV1.dll"`, `Native.load("HkdfGuardV1", ...)`, a bare-name
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
  using var key = hklm.OpenSubKey(@"Software\HkdfGuard\Kms.Windows.v1")
      ?? throw new InvalidOperationException("HkdfGuard KMS is not installed");
  string dir = (string)key.GetValue("InstallPath")!;
  IntPtr lib = NativeLibrary.Load(Path.Combine(dir, "HkdfGuardV1.dll"));
  ```
- **Python**: `ctypes.WinDLL(r"<absolute-path>\HkdfGuardV1.dll")`
- **Java**: JNA's `NativeLibrary.getInstance("<absolute-path>")`, or a thin JNI shim that
  calls `LoadLibraryW` with an absolute path
- **Go**: `cgo` linking against `HkdfGuardV1.lib` (resolved at link time, not
  a runtime search - the safest option of all here), or, for dynamic loading,
  `golang.org/x/sys/windows.LoadLibraryEx(absPath, 0,
  LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`
- **Node**: `ffi-napi`/`koffi` given an absolute path, or a native addon (N-API) linking
  `HkdfGuardV1.lib`

All five bindings map directly onto the five exported functions
(`hkdfguard_kek_exists`, `hkdfguard_create_kek`, `hkdfguard_wrap_dek`,
`hkdfguard_unwrap_dek`, `hkdfguard_generate_and_wrap_dek`) and the status codes in
`include/hkdfguard.h`; none of them need to know anything about TPMs, CNG, or NCrypt.

## License

Mozilla Public License 2.0 (MPL-2.0) - see [LICENSE](LICENSE).
