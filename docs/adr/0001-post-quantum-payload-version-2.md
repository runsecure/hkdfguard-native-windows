# ADR-0001: Add a post-quantum wrapping suite as payload version 2

**Status:** Accepted, implemented
**Date:** 2026-10-29, revised 2026-10-30
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

The macOS library took a different route (ML-KEM-1024 in the Secure
Enclave, with one stored encapsulation per KEK), because the Secure Enclave
holds only asymmetric keys. Windows' providers can hold symmetric keys, so
that constraint doesn't apply here.

Windows has constraints of its own:

- **Version 1 must stay available.** Hosts already provisioned under it,
  and hosts whose TPM can't do version 2, need a way to keep running it, but
  only by an explicit administrator decision.
- **The KEK must stay an NCrypt key.** Version 1's access control is the
  key's own DACL, checked by the provider on every use, and its creation,
  verification, ACL and retirement code is all NCrypt. Version 2 should keep
  that model rather than take on key storage of its own.

## Decision

### 1. Two payload versions, selected by policy alone

| Version | Suite | KEK |
|---|---|---|
| 1 | Today's ECDH P-256 + HKDF-SHA512 + AES-256-GCM, byte for byte unchanged | ECDH P-256 key in the PCP or the Software KSP, as today |
| 2 | SP 800-108 counter-mode KDF with HMAC-SHA-256 keyed by the KEK, then AES-256-GCM | HMAC-SHA-256 key in the PCP, or SP800_108_CTR_HMAC key in the Software KSP |

Both versions use the same 132-byte layout (`src/wire_format.h`), so
payload sizes and `HKDFGUARD_WRAPPED_MAX_LEN` don't change. The
ProviderType byte keeps its meaning (1 = TPM, 2 = software).

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
  before any key is opened. Any other version fails with
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
K_wrap      = HMAC-SHA-256(KEK, [1]_32 || "hkdfguard-wrap-v1" || 0x00 || Context || [256]_32)
Context     = u16_le(len(service)) || service || header
fingerprint = HMAC-SHA-256(KEK, [1]_32 || "hkdfguard-kek-fingerprint-v1" || 0x00 || [256]_32)
```

`header` is payload bytes 0..39 (Version, ProviderType, Reserved, KeyId,
Salt). `service` is the normalized service name. `K_wrap` is the AES-256-GCM
key directly, with no HKDF step. The AAD is `header || fingerprint`, as in
version 1. The labels and framing are byte-identical to Linux's (`-v1`
there names the construction, not the Windows payload version), so the
same known-answer vectors pin both implementations. One HMAC block is the
whole 32-byte output. The longest input block is 196 bytes (128-byte
service name).

The fingerprint replaces version 1's SHA-256 of the public key. A version 2
KEK has no public key, and the fingerprint is still public and reveals
nothing about the KEK. `provision` prints it and `retire` requires it, as
today.

### 3. Both KEKs are NCrypt machine keys

Both are persisted, non-exportable machine keys (`NCRYPT_MACHINE_KEY_FLAG`),
created only by `hkdfguard_create_kek`, with version 1's ACL: SYSTEM,
Administrators and `HkdfGuardAdmins` full control, the key-use and deployer
groups use. The provider checks the caller against that ACL on every use,
exactly as for a version 1 KEK. Their names are version 1's with a suffix
naming the key type, so the two versions never collide:

| Provider | Name | Key | PRF call |
|---|---|---|---|
| Platform Crypto Provider | `hkdfguardwin_<service>_v1_hmac` | `HMAC-SHA256`, key usage `NCRYPT_PCP_SIGNATURE_KEY` | `NCryptSignHash` over the block |
| Software KSP | `hkdfguardwin_<service>_v1_kdf` | `SP800_108_CTR_HMAC`, length 256 | `NCryptKeyDerivation` with label, context and SHA-256 |

- **TPM.** `ncrypt.h` names `HMAC-SHA256` for persisted HMAC keys in the
  TPM KSP. The PCP finalizes one only with the signature key usage; with it,
  `NCryptSignHash` returns the 32-byte HMAC of its input, computed in the
  TPM, for inputs up to 1,024 bytes.
- **Software.** `NCryptKeyDerivation` builds the SP 800-108 block itself
  from the label and context, and returns HMAC-SHA-256 of it under the key.
  For the fingerprint the context is left out, which the KSP frames exactly
  as an empty one.
- **Every open checks** the algorithm name (the PCP reports no algorithm
  group for its HMAC key), on the TPM the signature usage and hardware
  backing, the export policy, and the ACL. A key of another type under a
  version 2 name is `HKDFGUARD_ERR_KEK_INVALID` and is never used.
- **Exactly 32 bytes.** Given a shorter output buffer, the PCP's
  `NCryptSignHash` reports success and 32 bytes without writing the result,
  so every call passes 32 bytes and requires 32 back.

### 4. Checking the providers' PRF

- **Software:** once per process, before first use, a throwaway exportable
  `SP800_108_CTR_HMAC` key made the same way must export as 32 bytes, and
  its derivation must equal BCrypt's HMAC-SHA-256 over the fingerprint block
  and a wrap block (`CheckSoftwareKdfImplementation`).
- **TPM:** the PCP won't import a known HMAC key, so its output can't be
  checked against a known answer. The fingerprint, itself a PRF output, pins
  it instead: a TPM whose output changed would no longer match any payload's
  fingerprint, and unwrap fails with `HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH`
  before any decryption.

### 5. Provider selection, and hosts that can't do version 2

`KeyStoragePolicy` keeps its meaning (`PreferTpm`, `RequireTpm`,
`SoftwareOnly`), with version 1's rules. The TPM is unusable for version 2
when the PCP can't be opened, reports no TPM device, or can't create the
HMAC key (with anything the call made deleted first).

- `PreferTpm`: an unusable TPM falls back to the Software KSP at
  provisioning, with event 1001, and wrap uses the software KEK when the TPM
  has none. A TPM KEK that exists but fails its checks, or that the caller
  may not open, fails the call: a software KEK beside it would split the
  service.
- `RequireTpm`, or a TPM payload or KEK with an unusable TPM: the call fails
  with `HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` (-3) and logs **event 2008**
  (Error) with the reason. The event's text names the remedies: fix the TPM,
  change `KeyStoragePolicy`, or set `ClassicalMode` to `1`.

Version 2 never falls back to version 1, whatever the policy.

### 6. Events, status codes and the CLI

- **Event 2008** (new, Error): this host can't do version 2. Raised on every
  failing call, not once per process, so it can't be missed.
- **Events 1000, 1002, 1003:** also record the payload version.
- **Event 2003:** also covers `PAYLOAD_VERSION_REFUSED`.
- **Event 2004:** also covers an invalid `ClassicalMode`.
- **`HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED` (-13):** new, shared with Linux.
  Linux has one version and never returns it, but reserves the code.
- **CLI:** `provision` and `status` show the version and the provider.
  `retire` handles both versions' keys; `retire --corrupt` removes a key of
  the wrong type under a version 2 name.

## Options considered

### Option A: Linux's symmetric suite as version 2, on NCrypt keys (chosen)

Quantum-safe with no public-key step, forgery-resistant, built only from
approved functions, and byte-identical to Linux. The KEKs stay NCrypt keys,
so access control, creation, verification and retirement work as for
version 1, with the provider checking the ACL on every use. It costs two
key types per provider while version 1 is supported, and on the TPM a key
type Microsoft documents only in part (section 3).

### Option B: Hybrid (`HKDF(Z_ecdh || S_symmetric)`) as version 2

**Rejected.** Twice the keys and device calls, to hedge against
HMAC-SHA-256 failing, which nothing suggests. Linux rejected it for the
same reason.

### Option C: ML-KEM-1024, as on macOS

**Rejected.** The Software KSP can persist a non-exportable ML-KEM-1024 key
and use it with `NCryptEncapsulate`/`NCryptDecapsulate` (probed below), but
the PCP can't (`NTE_NOT_SUPPORTED`), so the TPM would have no version 2 KEK
at all. To keep payloads at 132 bytes and unforgeable, macOS encapsulates
once per KEK and stores the ciphertext, so one secret per KEK passes
through the process on every call; captured once, it opens every payload
and allows forging. The symmetric suite derives a fresh wrapping key per
payload instead. The ciphertext would also need storage of its own (the KSP
won't persist custom properties), and whoever can write that file could
substitute an encapsulation they know the secret of. A fresh encapsulation
per payload, with ML-DSA to keep payloads unforgeable, makes every payload
about 4.5 KB.

### Option D: A DPAPI-protected HMAC secret for the software provider

**Rejected.** It would match Linux's software PRF exactly. But the raw KEK
would enter the application's memory on every call, and non-exportability
would be a convention: any key-use account could decrypt the file and keep
the key. The KSP's SP 800-108 key gives the same construction with the key
inside the KSP.

## Evidence

Probed on the development host (AMD firmware TPM, Windows 11 build
26300.9818) on 2026-10-30, with standalone probes, unelevated and elevated:

| Question | Result |
|---|---|
| Software KSP, `SP800_108_CTR_HMAC` | Generated, persisted and reopened as a non-exportable key; export refused. `NCryptKeyDerivation` equals a hand-built HMAC-SHA-256 SP 800-108 block, Linux's framing, for service names of 0 to 128 bytes (68- to 196-byte inputs). An absent context is framed as an empty one. A 256-bit length gives a 32-byte key. |
| PCP, `HMAC-SHA256` | Finalizes only with `NCRYPT_PCP_SIGNATURE_KEY` usage (bare: `NTE_NOT_SUPPORTED`). `NCryptSignHash` gives 32 bytes, deterministic, different for two keys and from SHA-256 or an unkeyed HMAC of the input, for inputs of 1 to 1,024 bytes; 1,025 is refused. Persisted, reopened, same output; export refused. |
| Machine keys, created elevated with a DACL like HkdfGuard's | Both key types: an unelevated key-use account opens them and gets the administrator's output. Export, making the key exportable, widening its DACL and deleting it are all refused to that account. |
| Key properties | Both report `NCRYPT_LENGTH_PROPERTY` as 0. The KSP key's algorithm is `SP800_108_CTR_HMAC` (group `KEY_DERIVATION`); the PCP key's is `HMAC-SHA256`, with no group. |
| `NCRYPT_SILENT_FLAG` | Accepted by create, finalize, open, `NCryptSignHash` and `NCryptKeyDerivation`. Refused by the PCP's `NCryptDeleteKey` (`NTE_BAD_FLAGS`). |
| ML-KEM-1024 (Option C) | Software KSP: persisted, non-exportable, encapsulate and decapsulate work (ciphertext 1,568 bytes, secret 32). PCP: not supported. |

The library's own tests then passed elevated on the same host: both KEKs
end to end through the DLL and the CLI (`tests/test_v2_kek.cpp`,
`tests/test_cli_v2.ps1`), and a key-use account and an outsider under
version 2 (`tests/test_roles.ps1`).

## Consequences

**Easier:**

- Describing payloads as safe against a quantum computer by default,
  including payloads harvested today together with the host's key store.
- The same access control as version 1: the provider checks the KEK's ACL
  on every use, and removing an account from it takes effect immediately.
- A FIPS story for version 2: only approved functions (SP 800-108 with
  HMAC, AES-GCM). The remaining work is validated modules and validated
  TPMs.
- One construction across Linux and Windows, pinned by shared vectors.

**Harder:**

- The TPM's HMAC key is documented only in part: the signature usage it
  needs, and that signing means HMAC, are observed behavior. A Windows
  update could change either; a changed output is caught by the
  fingerprint, and a refused one fails closed.
- The TPM's PRF can't be checked against a known answer, only shown to be a
  keyed function of its input that stays the same.
- Two key types per provider while version 1 is supported. `retire` and
  `status` handle both.
- Hosts provisioned under version 1 must set `ClassicalMode` to `1` before
  upgrading, or be re-provisioned and re-wrapped.

**Still open:**

- Whether the PCP encrypts the HMAC response between the TPM and the host.
  On a discrete TPM, someone recording the bus might capture wrapping keys.
  Firmware and virtual TPMs have no bus.
- Version 1, on hosts that choose it, remains classical.

## Follow-up

- Run the probes on an Intel PTT firmware TPM, a discrete TPM, a Hyper-V
  virtual TPM, and Windows 11 24H2 (build 26100) before relying on version 2
  there.
- Reserve -13 (`PAYLOAD_VERSION_REFUSED`) in the Linux status table.
