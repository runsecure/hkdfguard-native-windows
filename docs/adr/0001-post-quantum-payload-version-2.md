# ADR-0001: Add a post-quantum wrapping suite as payload version 2

**Status:** Accepted, not yet implemented
**Date:** 2026-10-29
**Deciders:** HkdfGuard maintainers

## Context

Every Windows payload today is version 1: ECDH between the service's P-256
KEK and a point hashed from the payload's salt, then HKDF-SHA512 and
AES-256-GCM (see `src/ecdh_hkdf.h`). The symmetric parts are not at risk
from a quantum computer. The ECDH step is: Shor's algorithm recovers the
KEK's private key from its public key, and with it every wrapping key the
KEK ever produced. The public key is not hard to come by. It is in the key
store, readable by every account the key's ACL admits and by anything that
can copy the key store's files. A copy of those files plus the stored
payloads is enough to harvest now and decrypt later.

The Linux library has already replaced its ECDH suite with a symmetric one
(hkdfguard-native-linux, ADR-0001): the KEK is an HMAC-SHA-256 key held by
the provider, and the wrapping key is an SP 800-108 KDF block computed by
that key. That design keeps the property that matters most here: wrapping,
like unwrapping, needs the protected key, so nobody can forge a payload
from public values.

Windows has constraints Linux does not:

- **No supported way to use a TPM HMAC key through CNG.** The Platform
  Crypto Provider does list a persisted HMAC-SHA256 key, but Microsoft
  doesn't document it, and using an HMAC key through NCrypt is ruled out
  for this library.
- **No HMAC key in the Microsoft Software KSP.** It can persist
  non-exportable AES keys, not HMAC keys.
- **ML-KEM and ML-DSA are BCrypt-only.** They have been in CNG since the
  November 2025 update to Windows 11 and Server 2025, but only for keys in
  memory. Persisting one in the Software KSP fails with
  `NTE_NOT_SUPPORTED`, and no TPM supports them.
- **Version 1 must stay available.** Hosts already provisioned under it,
  and hosts whose TPM can't do version 2, need a way to keep running it, but
  only by an explicit administrator decision.

## Decision

### 1. Two payload versions, selected by policy alone

| Version | Suite | KEK |
|---|---|---|
| 1 | Today's ECDH P-256 + HKDF-SHA512 + AES-256-GCM, byte for byte unchanged | ECDH P-256 key in the PCP or the Software KSP (NCrypt), as today |
| 2 | SP 800-108 counter-mode KDF keyed by the KEK, then AES-256-GCM | HMAC-SHA-256 key in the TPM (through TBS), or AES-256 key in the Software KSP |

Both versions use the same 132-byte layout (`src/wire_format.h`), so
payload sizes and `HKDFGUARD_WRAPPED_MAX_LEN` don't change. The
ProviderType byte keeps its meaning (1 = TPM, 2 = software); which key it
routes to depends on the version.

The machine policy value `HKLM\Software\Policies\HkdfGuard\ClassicalMode`
(`REG_DWORD`) selects the one version a host uses:

| `ClassicalMode` | Wrap writes | Unwrap accepts | Provisioning creates |
|---|---|---|---|
| absent or `0` | version 2 | version 2 only | the version 2 KEK |
| `1` | version 1 | version 1 only | the version 1 KEK |
| anything else, wrong type, or unreadable policy key | fails: `HKDFGUARD_ERR_POLICY_INVALID` | fails | fails |

Post-quantum is the default: a host gets version 1 only if an administrator
sets `ClassicalMode` to `1`. There is no fallback and no migration:

- Unwrap compares the payload's version byte with the policy's version
  before any key is opened. Any other version fails with a new code,
  `HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED` (-13), and logs event 2003. The
  version byte is also bound into each version's key derivation (version
  1: HKDF info and AAD; version 2: the KDF context and AAD), so rewriting
  it gains nothing.
- Wrap never writes the other version. A host that can't do version 2
  doesn't drop to version 1; it fails (section 5).
- Changing `ClassicalMode` on a host with existing payloads makes them
  unreadable until it is changed back. Neither version's keys are touched
  by the change: a version 1 KEK and a version 2 KEK for the same service
  can exist side by side, under different names.

### 2. The version 2 construction: Linux's, unchanged

```text
K_wrap      = PRF(KEK, [1]_32 || "hkdfguard-wrap-v1" || 0x00 || Context || [256]_32)
Context     = u16_le(len(service)) || service || header
fingerprint = PRF(KEK, [1]_32 || "hkdfguard-kek-fingerprint-v1" || 0x00 || [256]_32)
```

`header` is payload bytes 0..39 (Version, ProviderType, Reserved, KeyId,
Salt). `service` is the normalized service name. `K_wrap` is the AES-256-GCM
key directly, with no HKDF step. The AAD is `header || fingerprint`, as in
version 1. The labels and framing are byte-identical to Linux's (`-v1`
there names the construction, not the Windows payload version), so the
same known-answer vectors pin both implementations. The longest PRF input
is 196 bytes (128-byte service name), well under the TPM's 1,024-byte
input buffer.

The PRF depends on the provider:

| Provider | PRF | One block of output |
|---|---|---|
| TPM (ProviderType 1) | HMAC-SHA-256 | 256 bits: one PRF call per output, as on Linux |
| Software KSP (ProviderType 2) | AES-256-CMAC (SP 800-38B) | 128 bits: two counter blocks, `i = 1` and `i = 2`, concatenated, each with `[L]_32 = [256]_32` |

Both are PRFs approved for SP 800-108. The fingerprint replaces version 1's
SHA-256 of the public key. A version 2 KEK has no public key, and the
fingerprint is still public and reveals nothing about the KEK. `provision`
prints it and `retire` requires it, as today.

### 3. TPM provider: raw TPM 2.0 commands through TBS

The library sends TPM 2.0 commands itself through `tbs.dll`
(`Tbsi_Context_Create`, `Tbsip_Submit_Command`), with a small in-tree
marshaling layer for exactly the commands below. NCrypt is not used for
version 2 on the TPM.

- **Parent:** Windows' storage root key, persistent handle `0x81000001`
  (RSA-2048, restricted decrypt, empty authValue). Provisioning reads its
  public area, checks the template attributes and records its Name in the
  key file. Every load compares the Name and refuses a mismatch
  (`HKDFGUARD_ERR_KEK_INVALID`), so a replaced storage root key is never
  silently used.
- **KEK:** `TPM2_Create` under the storage root key: keyed-hash,
  HMAC(SHA-256), TPM-generated, with `fixedTPM`, `fixedParent`,
  `sensitiveDataOrigin`, `userWithAuth`, `noDA` and `sign`, and an empty
  authValue. Nothing is made persistent in the TPM.
- **Key file:** the key's `TPM2B_PUBLIC` and `TPM2B_PRIVATE` (TPM-encrypted
  under the storage root key) plus the recorded storage root key Name, under
  a fixed folder below `%ProgramData%\HkdfGuard`. **The key file's ACL is the
  access control:** the TPM doesn't check who loads a key, so any account
  that can read the file and reach TBS can use the key. The file and folder
  get the KEK ACL rules used today (SYSTEM and Administrators full control,
  key-use groups read, protected DACL, Administrators as owner), are
  verified on every open, and are read through the same no-follow, local-only
  checks as `hkdfguard_open_file`. A file that fails any check is
  `HKDFGUARD_ERR_KEK_INVALID` and is left untouched.
- **Each wrap or unwrap:** one TBS context: `TPM2_Load` (password session
  on the storage root key), then one `TPM2_HMAC` per PRF output in a salted
  HMAC session (salt RSA-OAEP-encrypted to the storage root key) with
  AES-128-CFB command and response parameter encryption, the response HMAC
  verified, then `TPM2_FlushContext`. Response encryption is always on, so
  `K_wrap` never crosses a discrete TPM's bus in the clear.
- **One-shot only:** `TPM2_HMAC`, never the `TPM2_HMAC_Start` sequence,
  which put the Linux development TPM into failure mode.
- **Known-answer test:** before its first TPM operation, each process loads
  a fixed HMAC key with `TPM2_LoadExternal` in the NULL hierarchy, runs
  `TPM2_HMAC` over a 196-byte input and compares with BCrypt HMAC-SHA-256.
  A TPM that fails is not used.

### 4. Software provider: AES-256-CMAC in the Software KSP

- **KEK:** a persisted, non-exportable AES-256 machine key in the Microsoft
  Software KSP, created, ACL'd and verified exactly as today's software KEK.
  It uses its own name, distinct from the version 1 ECDH key's.
- **PRF:** AES-256-CMAC, computed by this library on top of `NCryptEncrypt`
  with the key, on two handles opened for the call:
  - One handle is set to ECB, for the subkeys from `E_K(0^128)`.
  - One handle is set to CBC, for one call per 128-bit output block with an
    explicit zero IV over the prepared message. The tag is the last
    ciphertext block.

  A wrapping key is four calls, about 0.1 ms. The chaining mode is a
  property of the opened handle only, never saved to the key. The key never
  leaves the KSP's isolated process. Only CMAC's intermediate values do, and
  they reveal nothing about it.
- **Known-answer test:** the CMAC composition is tested against SP 800-38B /
  RFC 4493 vectors, using a BCrypt AES key with a known value. The KSP's own
  AES is trusted, as BCrypt is.

### 5. Provider selection, and hosts that can't do version 2

`KeyStoragePolicy` keeps its meaning (`PreferTpm`, `RequireTpm`,
`SoftwareOnly`). Under version 2, the TPM is usable only if TBS reaches a
TPM 2.0, the storage root key is present with the expected template, none
of the needed commands is blocked, and the known-answer test passes.

- `PreferTpm`: a TPM that isn't usable for version 2 falls back to the
  Software KSP at provisioning, with event 1001, as today.
- `RequireTpm`, or no usable provider at all: the call fails with
  `HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` (-3, now returned on Windows) and
  logs **event 2008** (Error) with the specific reason: no TPM 2.0, storage
  root key missing or unexpected, a command blocked by TBS (naming it),
  known-answer test mismatch, or a TPM error. The event's text names the
  remedies: fix the TPM or its Group Policy block list, change
  `KeyStoragePolicy`, or set `ClassicalMode` to `1`.

Version 2 never falls back to version 1, whatever the policy.

### 6. Events, status codes and the CLI

- **Event 2008** (new, Error): this host can't do version 2. Raised on every
  failing call, not once per process, so it can't be missed.
- **Events 1000, 1002, 1003:** also record the payload version.
- **Event 2003:** also covers `PAYLOAD_VERSION_REFUSED`.
- **Event 2004:** also covers an invalid `ClassicalMode`.
- **`HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED` (-13):** new, shared with Linux.
  Linux has one version and never returns it, but reserves the code.
- **CLI:** `provision` and `status` show the version, the provider and, on
  the TPM, the pinned storage root key Name. `retire` handles both
  versions' keys.

## Options considered

### Option A: Linux's symmetric suite as version 2, version 1 behind `ClassicalMode` (chosen)

Quantum-safe with no public-key step, forgery-resistant, built only from
approved functions, and byte-identical to Linux. It costs a TPM 2.0 command
layer and session cryptography in this library, and two key types per
provider while version 1 is supported.

### Option B: Hybrid (`HKDF(Z_ecdh || S_symmetric)`) as version 2

**Rejected.** Twice the keys and device calls, to hedge against
HMAC-SHA-256 or AES-CMAC failing, which nothing suggests. Linux rejected it
for the same reason.

### Option C: ML-KEM per payload, ML-DSA signatures

**Rejected.** An ML-KEM ciphertext is 768 to 1,568 bytes and an ML-DSA-44
signature 2,420, so neither fits a 132-byte payload. Anyone holding a KEM
public key can encapsulate to it, which reintroduces the forgery flaw of
ECIES. A per-service encapsulation that fits reduces to a DPAPI-protected
secret, since CNG can't persist ML-KEM keys. Payload authenticity already
comes from AES-GCM, so ML-DSA has no role in the payload.

### Option D: The PCP's persisted HMAC key through NCrypt

**Rejected.** It is undocumented. It would be the same TPM operation as
Option A's, but reached through behavior Microsoft could change, with no
known-answer test (the PCP won't import a known key).

### Option E: A DPAPI-protected HMAC secret for the software provider

**Rejected.** It would match Linux's software PRF exactly. But the raw KEK
would enter the application's memory on every call, and non-exportability
would be a convention: any key-use account could decrypt the file and keep
the key. At rest it is no stronger than the KSP, which also uses machine
DPAPI.

### Option F: An existing TPM stack (TSS.MSR, tpm2-tss with its TBS transport)

**Not chosen.** Both work on Windows. The library needs eight commands and
one session type. A minimal in-tree layer is smaller to review, has no
dependency, and can be fuzzed with the rest of the parsers. Revisit if the
command set grows.

## Evidence

Probed on the development host (AMD firmware TPM, firmware `0x00060018`
`0x00000006`, Windows 11) on 2026-10-28 and 2026-10-29, with a standalone
probe (`tbs_probe`) run elevated, unelevated, and as a newly created
standard account:

| Question | Result |
|---|---|
| TBS reachable by a standard account | Yes: context creation, `GetCapability`, `ReadPublic` |
| Storage root key | `0x81000001`, RSA-2048, attributes `0x00030472`, empty authValue; Name unchanged across accounts and a reboot |
| `TPM2_Create` / `Load` / `HMAC` | Work for a standard account. 210-byte key file, `Load` about 5 ms, `HMAC` about 1.3 to 1.7 ms, repeatable per input, different across inputs. A key file made before a reboot loads and gives the same output after it. |
| Known-answer test | `LoadExternal` + `HMAC` matches BCrypt HMAC-SHA-256 at every length from 0 to 1,024 bytes. 1,025 bytes is refused (`0x95`), not truncated. |
| Repeated one-shot `HMAC` | 50 calls at 1,024 bytes, all equal and correct. Self-test still passing afterwards (checked elevated). |
| Salted, encrypted session | RSA-OAEP salt, AES-128-CFB both ways, two rounds with rolled nonces. The TPM's response HMACs verify, and the decrypted output equals the plain-session output. |
| Blocked commands | None of the needed commands is blocked for a standard account. Only `GetTestResult` is (`0x80280400`), which the design doesn't need. The registry's default block list holds only TPM 1.2 ordinals. |
| Who can use a key file | A standard account loaded a key file the administrator created and got identical output. The file's ACL is the only control. |

The Software KSP path was probed the same way (`cmac_probe`), elevated, as a
key-use account in a new local group, and as an account outside it, on
2026-10-29:

| Question | Result |
|---|---|
| CMAC composition | Matches the NIST SP 800-38B AES-256 examples (0, 16, 40 and 64 bytes) and BCrypt AES-CMAC at 1, 15, 17, 31, 33 and 196 bytes |
| Chaining mode | A fresh handle opens in CBC mode. Setting ECB changes only that handle: another handle already open, and one opened later, both stay CBC |
| State across calls | None: ECB gives the same block twice, and CBC with an explicit zero IV gives the same output for the same message |
| Compositions agree | For both 196-byte KDF blocks, one CBC call per block = one ECB call per AES block = the result from a freshly opened handle. A different header gives a different CMAC |
| Cost | A full `K_wrap` (two blocks): 0.10 ms by CBC (4 calls), 0.61 ms by ECB per block (28 calls). Open key + set mode + one block: 0.76 ms |
| Export | `KeyDataBlob` and `OpaqueKeyBlob` export refused |
| Key-use account, machine key with HkdfGuard's ACL | Opens it, sets ECB on its own handle and gets the administrator's CMAC. Widening the DACL (`0x80090010`), making it exportable (`0x8009000B`), exporting (`0x80090029`) and deleting it (`0x80070005`) are all refused |
| Account outside the group | Can't open the key (`0x80090016`), as with today's ECDH KEK |

## Consequences

**Easier:**

- Describing payloads as safe against a quantum computer by default,
  including payloads harvested today together with the host's key files.
- A FIPS story for version 2: only approved functions (SP 800-108 with HMAC
  or CMAC, AES-GCM). The remaining work is validated modules and validated
  TPMs.
- One construction across Linux and Windows, pinned by shared vectors.

**Harder:**

- A TPM 2.0 command layer and session cryptography to maintain and fuzz,
  which CNG used to own.
- The TPM key file is now this library's to protect: its ACL is the
  access control. That is weaker than version 1's TPM KEK, which the PCP
  checks on every use: the file is a bearer credential, so an account
  that reads it once can use the KEK on this host until the TPM is
  cleared, and access can't be revoked short of retiring the KEK and
  re-wrapping. Accepted as an administrator's choice (2026-10-29), since
  quantum exposure of stored payloads can't be fixed later and this can.
  The planned fix is a broker service that alone reads the key files and
  performs `TPM2_HMAC` for callers it checks against the KEK's ACL.
  `SecurityAssumptions.md` section 17 and the admin guide state the trade.
- Two key types per provider while version 1 is supported. `retire` and
  `status` handle both.
- Hosts provisioned under version 1 must set `ClassicalMode` to `1` before
  upgrading, or be re-provisioned and re-wrapped.

**Still classical:**

- On a discrete TPM, the session salt is exchanged with the storage root
  key's RSA key, as the TPM specification defines. Someone recording the bus
  today who can later break RSA-2048 could recover what crossed it. Firmware
  and virtual TPMs have no bus. Only the TCG can change this.
- Version 1, on hosts that choose it.

## Follow-up

- Run `tbs_probe` on a discrete TPM and a Hyper-V virtual TPM before
  release. Done for an Intel PTT firmware TPM (manufacturer `INTC`,
  firmware 500.14.0.0): the version 2 TPM path worked there on 2026-10-29.
- Reserve -13 (`PAYLOAD_VERSION_REFUSED`) in the Linux status table.
- Document `ClassicalMode`, event 2008 and the TBS block list in
  `docs/admin-guide.md`.
