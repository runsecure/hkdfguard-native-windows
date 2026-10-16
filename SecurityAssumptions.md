# Security Assumptions

What this library's security relies on that is *not* guaranteed by public
vendor documentation, how each point was established, and what residual risk
remains. Organized so an auditor can check each claim against the code
(`src/`) and the tests (`tests/test_roundtrip.cpp`) without re-deriving it.

Each entry states its status:

- **Verified** - established experimentally, on real hardware/OS, in this
  repository's own history; the test or procedure is named.
- **Documented** - relied upon because Microsoft documents it; not
  independently tested here.
- **Design decision** - a deliberate choice about the trust model, made by
  the project owner, not a property of Windows.
- **Assumed / not verified** - relied upon without direct evidence. These are
  the items most worth attention.

---

## 1. Threat model (design decision)

The KEK protects Data Encryption Keys that are *deployment secrets*: a DEK is
minted fresh on every release, wrapped under a stable service name, and
unwrapped later by a lower-privileged service account on the same host. The
KEK is long-lived and host-bound. Consequences that are accepted, not
defended against:

- **No rotation, escrow or recovery.** A TPM clear, motherboard swap or OS
  reinstall destroys every KEK on the host, and with it every DEK wrapped
  there. Recovery is by re-deployment (a new DEK under the same service
  name), never by recovering the old one. A genuinely new KEK is obtained by
  versioning the service name (`myapp.v2`), so `KeyId` is pinned to `1`
  forever and `ParseWrappedDek` rejects any other value.
- **Deployment rollback is supported, so there is no anti-rollback
  binding.** A payload is bound to the service name and the KEK's
  fingerprint, and to nothing release-specific. Every DEK ever wrapped
  under a service's KEK keeps unwrapping, which is what lets a deployment
  roll back to a previous release and still recover that release's DEK.
  The consequence is accepted: anyone who can replace the wrapped-key file
  can substitute an older payload for the same service, and unwrap will
  return that older DEK. The defense is the wrapped file's ACL, which `hkdfguard_open_file` enforces (section 15) (owner
  read/write, one group read-only - see the CLI's `--group`), not the
  payload format. An application that needs to refuse old DEKs must check
  that itself, after unwrapping.
- **Only the KEK's authorized users can create payloads - and all of them
  can.** The wrapping key comes from `Z = ECDH(KEK private key, H(salt))`
  (section 13), so making a payload needs a live use of the KEK's private
  key, governed by its ACL. Knowing the KEK's *public* key is not enough:
  a payload built from it is rejected (verified, test section 24b). This
  replaced, before the first release, an ECIES construction in which the
  public key alone sufficed - so anyone who had ever obtained it (a former
  key-use principal, a copy taken off the host) could forge payloads
  offline, indefinitely, without touching the KEK. Now removing an account
  from the key-use groups really ends its ability to create payloads.
  What remains is accepted: every principal currently granted key use
  (`KeyUseGroups`, `HkdfGuardUsers`) can wrap, and so can mint a valid
  payload around a DEK of its own choosing. The payload is authenticated as
  "made for this service by a holder of this KEK", never as "made by the
  deployment step". A key-use principal that can also write the
  wrapped-key file can make the service run with a DEK it picked. The audit
  trail only partly helps: a wrap through `hkdfguard_wrap_dek` leaves an
  event (1002) under the caller's account, but one that calls
  `NCryptSecretAgreement` itself leaves none - an unwrap event (1003) whose
  payload SHA-256 matches no wrap event by the deployment account is the
  sign of that. The defenses: keep key-use groups narrow, and keep the
  wrapped file writable only by the deployment account. An application that
  must know a DEK came from its own deployment needs a separate signature
  over the payload.
- **Local Administrators and SYSTEM are fully trusted.** They always hold
  full control of every KEK, can change the registry policy, and can alter a
  key's ACL. Nothing here defends the KEK against a host administrator.
- **The host process is trusted to load the right DLL.** Loading by bare
  filename lets the OS search order pick a planted library; README.md's
  "Consuming from other languages" section is the mitigation, not code.

## 2. Public-key point validation (verified)

**Claim.** No point that is not on P-256 is ever combined with the KEK's
private key.

**Why it matters.** `NCryptSecretAgreement` multiplies the KEK's private key
by whatever point it is given - the classic invalid-curve / small-subgroup
setup if that point were off the curve. P-256 has cofactor 1, so an
on-curve check is sufficient.

**How it holds now.** The point is no longer taken from the payload at all:
it is `H(salt)`, computed by `src/hash_to_curve.cpp` from the salt, and
lies on the curve by construction - the payload's only input to it is 32
bytes of salt, which have no invalid value. As defense in depth, every
`H(salt)` still goes through `IsValidP256Point` (`src/ecdh_hkdf.cpp`)
before any KSP sees it, so an arithmetic bug in the hash-to-curve could
only fail closed (`HKDFGUARD_ERR_CRYPTO_ERROR`). The salt is copied out of
the caller's buffer exactly once, so the point and HKDF's salt are always
derived from the same bytes, whatever a hostile thread does to the buffer.

**Verified how.** `BCryptImportKeyPair(BCRYPT_ECCPUBLIC_BLOB)` was fuzzed
with valid keys, all-zero and all-0xFF coordinates, random coordinates,
single-bit mutations of valid keys, and 100 fuzzed valid keys: every valid
point imported, every malformed point was rejected. `tests/test_roundtrip.cpp`
re-checks the gate on every run (valid, all-zero, all-0xFF, single-bit
mutations of X and Y) and checks 32 random salts all hash to valid,
distinct points. Underneath, the providers refuse bad points themselves
(section 13): the Software KSP and the Platform Crypto Provider both reject
off-curve, (0,0), out-of-range and all-0xFF points at `NCryptImportKey`,
and the PCP does so in software before the TPM.

**Residual risk.** None known.
## 3. Raw ECDH secret byte order (verified)

**Claim.** The shared secret fed to HKDF is the shared point's X coordinate,
**big-endian** - the same bytes the Linux implementation (RustCrypto's
`raw_secret_bytes`) feeds HKDF.

**Why it matters.** `BCRYPT_KDF_RAW_SECRET` returns the secret
**little-endian** (byte-reversed X). Feeding it as-is would derive a
different key from the Linux construction for the same inputs.

**Verified how.** The proof of concept behind section 13 compared
`NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)` against an independent
`BigInteger` computation of `d·H(salt)` on the Software KSP, and against
`x(KEK public)` / `x(2·KEK public)` for the generator and its double on the
Platform Crypto Provider (AMD fTPM): RAW_SECRET is little-endian on both.
`DeriveWrappingKey` reverses it. Wrap and unwrap now run the same code on
the same provider, so the earlier concern - BCrypt on wrap and NCrypt on
unwrap agreeing on byte order - no longer arises.

**The construction is pinned.** Section 29 of `tests/test_roundtrip.cpp`
rebuilds a frozen golden payload from the documented construction,
independently of `src/` - with `H(salt)` taken from the Linux crate's own
output, not this project's hash-to-curve - and checks the shipped DLL
unwraps it to a known DEK. Any change to the hash-to-curve, the IKM byte
order, the HKDF salt, hash or info string, the AAD, or the wire layout fails
that test while ordinary round trips still pass.

**Residual risk.** The PCP path was verified on one TPM vendor/firmware only.
## 4. Platform Crypto Provider quirks on an AMD fTPM (verified)

All observed on `Microsoft Platform Crypto Provider` over an AMD fTPM
(firmware 6.24.0.6), by isolating each call with standalone P/Invoke repros.
Each drove a specific accommodation in `src/kek_store.cpp`. Every
accommodation is written so that the security property is still enforced
by a check that *does* work on that provider.

| Observation | Accommodation | Property still enforced by |
|---|---|---|
| `NCRYPT_ALGORITHM_PROPERTY` ("Algorithm Name") reports `"ECDH"`, not the curve-qualified `"ECDH_P256"` the key was created with. Software KSP reports `"ECDH_P256"`. | `VerifyAlgorithm` checks `NCRYPT_ALGORITHM_GROUP_PROPERTY` (`"ECDH"` on both). | The curve is pinned by `VerifyCurve`: the exported public blob must carry `BCRYPT_ECDH_PUBLIC_P256_MAGIC`, and a reported curve name must be `nistP256`. `VerifyKeyLength` (256) alone would not do it: a brainpoolP256r1 key also reports 256, but exports with the generic ECC magic. **Verified** by probe on this AMD fTPM (PCP reports `nistP256`, exports the P-256 magic) and the Software KSP (no curve-name property for an `ECDH_P256` key, exports the P-256 magic; a brainpoolP256r1 key exports the generic magic). |
| `NCryptSetProperty(NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_KEY_AGREEMENT_FLAG)` returns `NTE_NOT_SUPPORTED` (also for `4\|1`); the key's usage stays pinned at `NCRYPT_ALLOW_DECRYPT_FLAG` (`0x1`). | The set is best-effort; `VerifyUsage` accepts `DECRYPT` as well as `KEY_AGREEMENT`. | `VerifyAlgorithm` runs first, so only a key already proven to be ECDH can pass; an ECDH key has no distinct "decrypt" operation on CNG. **Verified** that `NCryptSecretAgreement` succeeds against such a key and yields a correct 32-byte secret - the label is a provider quirk, not a capability limit. |
| On the creation handle, immediately after `NCryptFinalizeKey`, `NCRYPT_LENGTH_PROPERTY` reads `0`; on a freshly reopened handle it reads `256`. | Post-finalize verification runs on a freshly reopened handle. | `VerifyKeyLength` is unchanged and strict. |
| `NCRYPT_IMPL_TYPE_PROPERTY` returns `NTE_NOT_SUPPORTED` on every *key* handle (creation or reopened); on the *provider* handle it succeeds and reports `NCRYPT_IMPL_HARDWARE_FLAG`. | `VerifyHardwareBacked` falls back to the provider handle only when the key-level query returns exactly `NTE_NOT_SUPPORTED`. | Any other failure, or a non-hardware answer from either handle, still throws. |

**Residual risk.** The provider-level `Impl Type` fallback is weaker than a
per-key check: it asserts the *provider* is hardware-backed, not the
specific key. For the Microsoft Platform Crypto Provider every key is
TPM-resident, so this is acceptable there; a hybrid third-party KSP could
in principle hold software keys behind a hardware-flagged provider. Also,
`VerifyUsage`'s acceptance of `DECRYPT` depends on `VerifyAlgorithm` having
run first inside `VerifyKeyProperties` - that ordering is load-bearing.

## 5. Where elevation is actually enforced (verified)

**Claim.** Creating a machine-scoped (`NCRYPT_MACHINE_KEY_FLAG`) key without
Administrator rights fails at `NCryptFinalizeKey` with `NTE_PERM`
(`0x80090010`, documented by Microsoft as "Access is denied");
`NCryptCreatePersistedKey` and the property-setting calls before it all
succeed regardless of elevation.

**Verified how.** Standalone repro, non-elevated, Software KSP.

**Consequence.** That failure is reported as `HKDFGUARD_ERR_KEK_ACCESS_DENIED`
(not the generic `HKDFGUARD_ERR_PROVIDER_ERROR`), and the CLI's "requires an
elevated process" hint keys on that code. Opening and using an existing
key does not require elevation - only the key's ACL governs it.

## 6. `NCRYPT_SILENT_FLAG` is accepted where it is passed (verified)

**Claim.** `NCryptOpenKey`, `NCryptCreatePersistedKey`, `NCryptFinalizeKey`,
`NCryptImportKey` and `NCryptSecretAgreement` all accept `NCRYPT_SILENT_FLAG`
(none returns `NTE_BAD_FLAGS`), so a key that carries a UI-requiring
protection policy fails instead of displaying a prompt - or blocking on one
- inside a non-interactive service process.

**Verified how.** Standalone repro, each call exercised with the flag;
opening a nonexistent key returned `NTE_BAD_KEYSET`, everything else
succeeded. The flag is not passed to `NCryptOpenStorageProvider`,
`NCryptExportKey` or the property calls, which were not tested.

**Residual risk.** Only our own keys are created here and they set no UI
policy; the flag defends against a pre-planted key, which requires an
administrator.

## 7. Registry policy reads (documented + design decision)

- `HKLM\Software\Policies` is documented by Microsoft as excluded from WOW64
  registry redirection, so 32- and 64-bit consumers read the same values.
  `KEY_WOW64_64KEY` is passed anyway so the code does not depend on that
  exclusion. **Documented, not tested.**
- A missing `KeyStoragePolicy` value means "never configured" and yields the
  default (`PreferTpm`). A value that is present but unrecognized yields
  `KeyStoragePolicy::Invalid`, and every reader fails closed with
  `HKDFGUARD_ERR_POLICY_INVALID`. **Verified** by test
  (`test_roundtrip.cpp` section 25b) via the test-only override.
- `KeyUseGroups` read failures of any kind yield an empty list (no
  additional principals), never an exception. Entries are trimmed; a bad
  entry fails `hkdfguard_create_kek` before any key is touched.
- `AuditUnwrapSuccess` fails toward auditing: only an explicit REG_DWORD 0
  turns off the unwrap-success event (1003), and absent, non-zero,
  wrong-type or unreadable all leave it on. It never affects failure
  events or wrap events. **Verified** for the value-to-setting rule by
  test (`test_roundtrip.cpp` section -2); the switch's effect on a real
  unwrap is not exercised, since that would mean changing this machine's
  HKLM policy during a test run.
- `SetupMinDelayMs` is the floor on `hkdfguard_create_kek` /
  `hkdfguard_kek_exists`: 1000 ms when absent, a REG_DWORD of 0..60000 used
  as is (0 disables it), and anything else, including above 60000, also
  1000 ms. This is the Linux build's `setup_min_delay_ms`, with the same
  numbers. Setup calls are serialized by a process-wide mutex. The floor is
  waited out by a scope guard, so a throwing call pays it too. Argument
  errors return before the gate. **Verified** by test section 0c2:
  - the value-to-setting rule;
  - both calls take at least the floor, with and without a KEK and on a
    failing `create_kek`;
  - argument errors and `hkdfguard_wrap_dek` return in under half the floor;
  - two concurrent calls take at least twice it.

  This is a **design decision** about load, not secrecy:
  `hkdfguard_wrap_dek` still answers `KEK_NOT_FOUND` at once. The floor
  bounds the rate per process, not per machine: separate processes each
  have their own gate.
- The default `PreferTpm` fallback to software is a **design decision**:
  the policy is the administrator's to set. It falls back only when the TPM
  is provably unusable for the service: the TPM provider cannot be opened,
  the TPM reports no device (`TBS_E_TPM_NOT_FOUND`, `NTE_DEVICE_NOT_FOUND`),
  or the TPM key was confirmed absent (`NTE_BAD_KEYSET`) and creating it
  failed, with the partly-created key successfully deleted. Internally these
  are the only failures thrown as `TpmUnusableError`; the public code is
  still `HKDFGUARD_ERR_PROVIDER_ERROR`. Everything else propagates, including an
  *existing* TPM KEK that fails property verification, any other error while
  probing for the TPM key (a busy, locked-out or not-ready TPM), a
  concurrent creation (`NTE_EXISTS`), `KEK_ACCESS_DENIED` and `KEK_INVALID`.
  Each of those may sit in front of a TPM KEK that is in use, and creating a
  second, software KEK beside it would split the service and permanently
  route new wraps to the weaker key. `OpenKekForWrap` (which also falls back
  on `KEK_NOT_FOUND`) and `KekExists` follow the same rule, so an
  unauthorized caller is told `KEK_ACCESS_DENIED`, never `KEK_NOT_FOUND`.
  **Assumed / not verified**: that a host with no TPM fails at
  `NCryptOpenStorageProvider` or reports one of the two "no device" codes.
  If some host instead reports a different code when probing for the key,
  `PreferTpm` there now fails with `HKDFGUARD_ERR_PROVIDER_ERROR` rather than
  falling back. Exercise the default policy on a VM without a vTPM before
  relying on it. The test suite simulates the provider-open failure (section
  25c) and, through a test-only fault-injection seam, a TPM probe error, a
  "no device" report, and an existing TPM KEK failing verification (section
  26); it cannot show what a real TPM-less host reports.
- If any post-finalize step fails (reopen, property verification, ACL
  verification), `CreateKekOnProvider` deletes the key *it just created*,
  on its own creation handle, before rethrowing, under every policy. That
  is the only KEK deletion outside test cleanup. An earlier version did
  this in `PreferTpm`'s fallback handler instead, which could also delete
  an *existing*, in-use TPM KEK whose verification failed, destroying every
  DEK wrapped under it; it no longer can. The post-finalize failure path
  itself has no deterministic test (it needs a post-finalize fault).

## 8. Key-use principals are host-local (verified)

**Claim.** A `KeyUseGroups` entry is accepted only if `LookupAccountName` /
`LookupAccountSid` report its domain as this machine's NetBIOS name,
`BUILTIN`, `NT AUTHORITY` or `NT SERVICE`, and its type is a group
(`SidTypeGroup`/`SidTypeAlias`/`SidTypeWellKnownGroup`), and it is not an
over-broad well-known principal (Everyone, Authenticated Users, Anonymous,
NULL, INTERACTIVE/NETWORK/BATCH/SERVICE/REMOTE INTERACTIVE LOGON,
BUILTIN\Users, BUILTIN\Guests, Local account (S-1-5-113), This Organization
(S-1-5-15), NT SERVICE\ALL SERVICES (S-1-5-80-0), LOCAL (S-1-2-0), CONSOLE
LOGON (S-1-2-1)). Local account, This Organization, ALL SERVICES and REMOTE
INTERACTIVE LOGON resolve as `SidTypeWellKnownGroup` in an accepted domain
(`NT AUTHORITY` or `NT SERVICE`), so the denylist alone excludes them.
Policy validation and the existing-key ACL check share one implementation
(`IsOverBroadSid` in `src/key_acl.cpp`).

**Verified how.** Tests (section 0d) cover Everyone by name and as
`S-1-1-0`, Authenticated Users, BUILTIN\Users, the six broad groups added
above by SID string (Local account and ALL SERVICES by name too), a user
account, an
unresolvable name, a foreign-domain-qualified name, and every branch of
`IsHostLocalAccountDomain`. Facts established while building it, all by
repro on this host: well-known SIDs such as Everyone report an *empty*
domain (treated as non-local); default local groups live in `BUILTIN` and
`COMPUTERNAME\<builtin alias>` does not resolve at all; SAM accounts are
reported with the computer name in mixed case (`OlympusMons` vs
`OLYMPUSMONS`), hence the case-insensitive comparison; an unqualified name
that has no local match is resolved against the domain by Windows, which
is why the check is on the *resolved* domain and not on spelling.

**Residual risk.** On a domain controller the local SAM *is* the domain, so
only BUILTIN/NT AUTHORITY/NT SERVICE principals qualify there. `NT
AUTHORITY\NETWORK SERVICE` and `LOCAL SERVICE` are permitted; on a server
that is many services at once - an administrator's choice. The two fixed
optional groups (`HkdfGuardAdmins` -> full control, `HkdfGuardUsers` ->
use) are still granted by *name*, now restricted to local groups.

## 9. ACL enforcement and `GENERIC_READ` (design decision + verified)

- The KEK's ACL is applied once, at creation, and never re-verified on open:
  the OS enforces the DACL on every use, so an unauthorized caller gets
  `NTE_PERM` (surfaced as `HKDFGUARD_ERR_KEK_ACCESS_DENIED`). **Design
  decision.** A fresh key's ACL is checked for the presence of every
  principal it was granted. An *existing* key found by
  `hkdfguard_create_kek` is checked against policy-independent invariants
  instead: a real (non-NULL) DACL, SYSTEM and Administrators present, and
  no grant of any kind to an over-broad principal, whether through a plain
  or a conditional (callback) allow ACE. An object or compound allow ACE,
  which this library never writes, or an unreadable ACE fails the check
  outright rather than being skipped. Failing that returns
  `HKDFGUARD_ERR_KEK_INVALID` and leaves the key untouched. This
  catches a pre-planted key or one later widened to e.g. Everyone. It does
  not catch a widening to some other specific account, and it does not run
  on wrap or unwrap, which never re-verify the ACL. **Verified** by test
  sections 25d (plain grant to Everyone) and 28 (conditional allow ACE for
  Everyone, grants to ALL SERVICES and Local account), elevated. Section 27
  covers pre-planted keys that fail property verification instead: wrong
  curve, P-384, and exportable.
- Key-use access is granted as `GENERIC_READ` on the key object, on the
  understanding that for CNG KSP keys read access permits using the private
  key (`NCryptSecretAgreement`) while `GENERIC_WRITE`/`GENERIC_ALL` are
  needed to modify or delete it. **Verified.** A genuinely non-administrator
  local account - a member of the local `HkdfGuardUsers` group and nothing
  else (confirmed not in `Administrators`) - successfully wrapped a DEK via
  the CLI and unwrapped it via a direct call into the DLL, with no
  elevation, on the strength of that `GENERIC_READ` grant alone. The same
  account's attempt to *provision* a brand-new KEK failed as expected
  (`HKDFGUARD_ERR_KEK_ACCESS_DENIED`, elevation required), confirming creation
  and use are genuinely governed by separate mechanisms (elevation vs.
  ACL). Both the KEK and the test account/group were removed afterward.

## 10. Payload integrity and the KEK fingerprint (verified where noted)

- The payload's *authenticated bytes* are `header || SHA-256(KEK public
  key, raw X||Y)`, where the header is payload bytes 0..39 (`Version`,
  `ProviderType`, `Reserved`, `KeyId`, `Salt`). They are the AES-256-GCM
  AAD, **and** they end HKDF's info: `"hkdfguard-wrap-v1:" ||
  u16le(len(service)) || normalized service || authenticated bytes`. This
  is the Linux build's construction (`derive_wrapping_key`,
  `Payload::authenticated_bytes`), adopted so both builds have one spec.
  Every field a parser reads or routes on, the KEK, and the service are
  therefore bound into the wrapping key itself, not only checked by the
  tag. AES-GCM doesn't commit to its key, but here a payload's context
  selects its own key: no context can be swapped and still find a key the
  tag accepts. The service is bound through the key alone, so a wrong
  service fails at the tag. Unwrap builds the authenticated bytes once,
  from the header exactly as received, and DeriveWrappingKey reads the salt
  from that same copy. The `Nonce` is not authenticated bytes - it is
  generated inside the encrypt call, after they are fixed - and needs no
  coverage: GCM authenticates it inherently. **Verified** in three ways:
  - The golden-payload test (section 29 of `tests/test_roundtrip.cpp`)
    reproduces the frozen payload from an implementation of the spec written
    in the test, independent of `src/`.
  - The frozen value was computed separately with .NET's `HKDF` and `AesGcm`.
  - Its wrapping key (`4de2f10c...`) is what the Linux crate's own
    `derive_wrapping_key` returns for the same Z, salt, service and
    authenticated bytes.

  The library's `DeriveWrappingKey` is checked against that key without
  elevation, on the golden KEK imported as an in-memory Software KSP key.
  The fingerprint also travels in the payload and is
  compared, before any ECDH, against the fingerprint of the KEK the
  payload's routing fields select; mismatch is `HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH`.
  It is a check on the selected key, never a lookup - searching for a key
  matching an attacker-supplied fingerprint would let the payload steer
  key selection. **Verified** by tests for the mismatch path (elevated).
- The comparison is a plain `memcmp`, deliberately: both operands are
  hashes of *public* keys, so timing reveals nothing secret.
- `Reserved` is required to be zero, `Version` to be `1` and `KeyId` to be
  `1`, so none can currently be varied in a payload that still parses. They
  are authenticated anyway, so that introducing a second version later can
  never let an existing payload be relabelled as it.
- Each wrap draws a fresh random 32-byte salt, which yields a fresh `Z` and
  is HKDF's salt, and therefore a fresh AES key; the random 96-bit nonce
  would have to repeat under the *same* salt to matter (probability of a
  salt collision: about 2^-128 per pair of wraps).
- Concurrent mutation of nonce/ciphertext/tag by a hostile in-process thread
  is not a check-then-use problem: `BCryptDecrypt` reads them in one call
  and GCM authenticates whatever it reads.

## 11. Things established about the build, not the crypto (verified)

- The test-only override seams (`SetTestPolicyOverride`,
  `SetTestKeyUseGroupsOverride`, `SetTestTpmProviderNameOverride`) exist
  only when `HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE` is defined, which only
  `tests/CMakeLists.txt` does; a `strings` scan of the built DLL finds no
  trace of them.
- No `NCRYPT_OVERWRITE_KEY_FLAG` is ever passed, so a concurrent
  `hkdfguard_create_kek` race cannot clobber an existing key - the second
  finalize is expected to fail with `NTE_EXISTS` and the caller to retry.
  **Assumed / not verified**: the race itself has not been exercised.
- Service names are restricted to ASCII letters, digits and `.` (no leading
  `.`, no `..`), lowercased,
  and used inside a fixed prefix/suffix to form the persisted key name. The
  Software KSP and PCP store keys under a hash of the container name, so
  `.` cannot form a path. **Assumed / not verified** beyond standard
  provider behaviour.

## 12. Known gaps (not yet addressed)

- The audit trail (Application event log, source
  `hkdfguard-native-windows`; see README.md "Audit logging") is best
  effort and not tamper-evident. Any local user can write events under
  that source name, and an administrator can clear the log. Treat it as an
  operational aid, not as evidence. The event's User field is supplied by
  the writing process and not validated by Windows, so a forged event can
  name any user.
- Hardening flags: the DLL and CLI are built with `/sdl`, `/Qspectre`,
  Control Flow Guard and, on x64, `/CETCOMPAT` and `/guard:ehcont`
  (`hkdfguard_apply_hardening` in `CMakeLists.txt`); `scripts/Build-Dist.ps1`
  fails a release build whose binaries lack the PE markers for these. The
  statically linked runtime is Spectre-mitigated when the Visual Studio
  component "MSVC Spectre-mitigated libs (Latest)" is installed for the
  target architecture; CMake links it from `lib\spectre\<arch>`, warns when
  it is missing, and fails instead when `HKDFGUARD_REQUIRE_SPECTRE_LIBS` is
  set. The release workflow sets it and installs both architectures'
  components on the runner first, so a release cannot ship an unmitigated
  runtime. Verified on the development machine for x64 and ARM64
  (2026-10-07: the same source gains speculation barriers in the linked
  runtime on both). The workflow's install branch has not yet run on a
  hosted runner. ARM64 builds still get no shadow-stack or EH-continuation
  equivalent.
- Only one TPM vendor/firmware has been exercised (section 4); other
  Platform Crypto Provider backends may exhibit different quirks.
- Release binaries are Authenticode-signed only when the repository has
  the `WINDOWS_SIGNING_CERT_PFX_BASE64` and `WINDOWS_SIGNING_CERT_PASSWORD`
  secrets; otherwise the release workflow builds them unsigned and flags
  that with a warning. Every release does get a GitHub build provenance
  attestation for the zip, DLL and CLI (`gh attestation verify`), which
  needs a public repository or GitHub Enterprise Cloud. Workflow actions
  are pinned to commit SHAs.

## 13. ECDH with a computed point on the Windows providers (verified)

**Claim.** Both KSPs can compute `Z = ECDH(KEK private key, H(salt))` for a
point the library constructs, deterministically, with the private key
staying inside the TPM for a Platform Crypto Provider KEK, and with the
same authorization as any other use of the KEK.

**Verified how.** A standalone proof of concept (not part of the
repository), run on 2026-10-14 on the Microsoft Platform Crypto Provider
over an AMD fTPM (firmware 6.24.0.6) and on the Software KSP, with per-user
keys and, elevated, machine keys:

- `NCryptImportKey` of a constructed `BCRYPT_ECCPUBLIC_BLOB` and
  `NCryptSecretAgreement` succeed on both. On the PCP, ECDH with the
  generator G and with 2G returned exactly `x(KEK public)` and
  `x(2·KEK public)` - computed from the public key alone - so the TPM
  performs genuine scalar multiplication on a supplied point. No key flags
  beyond today's: the PCP refuses `NCRYPT_ALLOW_KEY_AGREEMENT_FLAG` and
  keeps usage `DECRYPT` (section 4), yet the agreement works.
- `NCryptDeriveKey` KDFs: `BCRYPT_KDF_RAW_SECRET`, `HASH`, `HMAC` and
  `SP800_56A_CONCAT` work on both providers; `TLS_PRF` and `HKDF` return
  `NTE_INVALID_PARAMETER`. Passing `NCRYPT_SILENT_FLAG` to `NCryptDeriveKey`
  makes every KDF fail with `NTE_INVALID_PARAMETER`; the library passes 0.
- Deterministic: the same KEK and salt twice give identical output;
  different salts or different KEKs give different output (all four KDFs,
  both providers).
- Independent maths (Software KSP, exportable test key): `d·H(salt)`
  computed with `System.Numerics.BigInteger` matched the provider for two
  salts and three KDFs. The hash-to-curve re-implementation matched the
  Linux implementation's `payload_ecdh_point` on the RustCrypto p256 0.14
  crate for three salts.
- The private key stays in the TPM: exporting the PCP key's private blob is
  refused (`0x8009000A`), as is changing its export policy; the provider
  reports `NCRYPT_IMPL_HARDWARE_FLAG`; one agreement takes ~8.9 ms on the
  PCP against ~0.09 ms in software. A `TPM` ETW trace recorded no command
  events, and Microsoft does not document which TPM command the PCP issues,
  so `TPM2_ECDH_ZGen` is inferred from this evidence, not observed.
- Bad points are refused at import: off-curve, (0,0), X = p and all-0xFF
  points by `BCryptImportKeyPair` (`STATUS_INVALID_PARAMETER`), the Software
  KSP (`NTE_INVALID_PARAMETER`) and the PCP (`TPM_E_PCP_INTERNAL_ERROR`,
  `0x80290407`) - the PCP in 0.07 ms, as fast as a successful import, i.e.
  in software before the TPM.
- Authorization: with a machine KEK whose DACL admits only SYSTEM and
  Administrators, a non-elevated account fails at `NCryptOpenKey`
  (`NTE_PERM` on the PCP, `NTE_BAD_KEYSET` on the Software KSP) and cannot
  read the key file directly, so it can neither run the agreement nor read
  the public key; the elevated administrator can do both. 52 denied
  attempts left the TPM's `LockoutCount` at 0 of 32: the refusal happens at
  the key's ACL, and these keys have no TPM authorization value to fail.
- Cost: import + agreement + raw derive averaged 9.8 ms on the PCP
  (median 9.5, p95 11.0, 100 runs) and 0.17 ms on the Software KSP. Every
  wrap is now one such operation.

**Residual risk.** One TPM vendor/firmware only; a Hyper-V vTPM was not
tested (no Windows guest was available). Note for diagnostics: on the
Software KSP an unauthorized caller gets `NTE_BAD_KEYSET`, the same status
as a missing key.

## 14. Process hardening keeps same-user processes out (verified)

**Claim.** After `hkdfguard_harden_process`, another process running as the
same account cannot read or write the caller's memory, dump it, inject a
thread or duplicate its handles. It also cannot read or change the context
of any thread that existed at the time of the call, and it cannot undo any
of this by rewriting the DACLs. Windows Error Reporting leaves the heap out
of the crash reports it collects. This is the counterpart of the Linux
build's `RLIMIT_CORE = 0` plus `PR_SET_DUMPABLE = 0`. It is opt-in, because
it changes process-wide state that belongs to the host.

**How.** `src/process_hardening.cpp`:

- It calls `WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`.
- It sets a protected DACL on the process and on every thread in a Toolhelp
  snapshot. SYSTEM is granted the object type's all-access mask. The
  account's SID and OWNER RIGHTS (`S-1-3-4`) are both granted query,
  synchronize and, for the process, terminate. The threads also keep
  `READ_CONTROL`.
- The OWNER RIGHTS ACE replaces the owner's implicit `READ_CONTROL | WRITE_DAC`.
  Without it, a same-user process could simply restore the old DACL.
- The masks are explicit rather than generic `GA`, because the kernel stores
  `GA` mapped to specific rights.
- A repeat call cannot reopen an already-hardened thread for `WRITE_DAC`.
  It reads that thread's DACL back and accepts it only if it is protected
  and matches ACE for ACE, which is what makes the call idempotent.

**Verified how.** `tests/test_harden_process.cpp` starts a copy of itself as a
child process. The child starts a worker thread, calls the function twice
(both calls must return `HKDFGUARD_OK`) and confirms `WerGetFlags` reports
NOHEAP. It then confirms it still works from the inside: it starts another
thread and runs `hkdfguard_kek_exists` against the key storage provider. The
parent, with `SeDebugPrivilege` explicitly disabled, then probes the child:

- These process rights are refused with `ERROR_ACCESS_DENIED`:
  - `PROCESS_VM_READ`;
  - `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`;
  - `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE`, `PROCESS_SET_INFORMATION` and `PROCESS_SUSPEND_RESUME`;
  - `READ_CONTROL`, `WRITE_DAC` and `WRITE_OWNER`;
  - `PROCESS_ALL_ACCESS`.
- These process rights still succeed: query (plain and limited),
  `SYNCHRONIZE` and `PROCESS_TERMINATE`.
- A full-memory `MiniDumpWriteDump` fails.
- On both pre-existing threads, `THREAD_GET_CONTEXT`, `THREAD_SET_CONTEXT`,
  suspend/resume, terminate, `WRITE_DAC` and `WRITE_OWNER` are refused.
  Limited query and `SYNCHRONIZE` still succeed.

The test passed non-elevated at Medium integrity on the development machine
on 2026-10-15. The first run caught the `GA` mapping above, which had made
the second call fail. The test exits with ctest's skip code when run as
SYSTEM.

**Residual risk.** This is a same-user barrier. Under section 1,
administrators and SYSTEM are trusted anyway. Specifically:

- **Bypasses:** an administrator with `SeDebugPrivilege` enabled, SYSTEM and
  kernel code all get past it.
- **Later threads:** a thread created after the call gets the token's
  default DACL, so its registers are readable by the same account; the
  process memory is not. The test pins this. The token default DACL is
  deliberately left alone, because it applies to every unnamed object the
  host creates. Hosts should call the function again after starting worker
  threads.
- **Existing handles:** handles opened before the call keep their granted
  access.
- **Outside its reach:** memory paged out or written to `hiberfil.sys`, and
  machine-wide dump configuration (WER `LocalDumps`, kernel and live kernel
  dumps).
- **Not yet run:** elevated, in the Server 2022/2025 containers and on
  ARM64.
- **Window hooks:** a GUI process can be injected into by a same-user
  process on the same desktop through `SetWindowsHookEx`. No process or
  thread DACL covers that, with or without the strict flag below.

**Strict mode: `hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE)`
(verified).**

**Claim.** With this flag, the "later threads" gap above is closed too. A same-user
process can't read or redirect any thread of the process, including ones started
after the call, and can't undo that through the process token. It is the same
cross-platform flag the Linux and macOS builds take (bit `0x1`, unknown bits
refused with `INVALID_ARGUMENT` before anything changes). On Linux
`PR_SET_DUMPABLE` already guarantees it; on Windows it takes two more steps.

**How** (`HardenToken` in `src/process_hardening.cpp`, run before the steps
above):

- **Default DACL.** The token's default DACL becomes `SY: 0x1FFFFF`,
  `OW: 0x120000`, user `0x120000`: SYSTEM all rights, and the account and OWNER
  RIGHTS only `SYNCHRONIZE | READ_CONTROL`. The account gets only standard
  rights, because a specific bit means something different per object type.
- **Token DACL.** The token's own DACL becomes protected: SYSTEM gets
  `TOKEN_ALL_ACCESS`, and the account and OWNER RIGHTS get `TOKEN_QUERY |
  TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | READ_CONTROL`.
- **Why `TOKEN_DUPLICATE` stays.** The Platform Crypto Provider duplicates its
  own process token on every key open and returns `NTE_PERM` without it. This
  was found by a probe on the development machine, granting rights one at a
  time. The Software KSP needs nothing.
- **Idempotency.** A repeat call can't open the token to change it any more.
  It verifies both DACLs instead. The thread sweep accepts a thread created
  under the strict default DACL, which also denies it `WRITE_DAC`, as already
  hardened. So strict and non-strict calls can follow each other in any order.

**Verified how.** `tests/test_harden_process.cpp` runs the child twice, in
default and in strict mode. Both children first confirm that unknown flag bits
return `INVALID_ARGUMENT` and leave WER's NOHEAP off. The strict child then:

- hardens itself;
- starts a thread;
- hardens again, strict and then non-strict, with all calls returning OK;
- starts another thread;
- runs `hkdfguard_kek_exists` against the real providers.

The parent then checks both later threads, and the token:

- **Later threads:** `GET_CONTEXT`, `SET_CONTEXT`, suspend, terminate,
  `WRITE_DAC`, `WRITE_OWNER` and even `QUERY_LIMITED` are denied;
  `SYNCHRONIZE` is allowed.
- **Token:** `TOKEN_ADJUST_DEFAULT`, `WRITE_DAC`, `WRITE_OWNER` and
  `TOKEN_ADJUST_PRIVILEGES` are denied; `TOKEN_QUERY` and `TOKEN_DUPLICATE`
  are allowed.

In default mode it pins the documented gaps: a later thread allows
`GET_CONTEXT`, and the token allows `TOKEN_ADJUST_DEFAULT`. This passed
non-elevated on the development machine on 2026-10-15.

**The CLI uses it.** `hkdfguard.exe` calls the strict form first thing in
`main`, before parsing arguments, and exits with "refusing to handle key
material" if it fails, matching the Linux CLI. Every copy of the DEK the CLI makes lives in
one `VirtualAlloc` buffer (`DekScratch`): the stdin text, read with
`ReadFile` rather than the CRT's buffered `fread`, and the decoded bytes,
decoded straight into it. The buffer is locked with `VirtualLock` and wiped
before it is freed. If the lock fails, the CLI prints a warning, as on Linux.
`tests/test_cli.ps1` passes non-elevated with this in place, through to
the `hkdfguard_wrap_dek` call. **Not yet run elevated:** `provision` and a
full `wrap` against a real KEK under strict hardening still need that run.

**Residual risk (strict).** These are the cost of the flag, documented in the
header:

- **Same-user access is lost:** everything the process creates afterwards
  without an explicit security descriptor is closed to its own account. That
  includes child processes, named pipes and other named objects.
- **Process-scoped:** an impersonating thread's objects follow the
  impersonation token's default DACL, not this one.
- **Not yet run:** elevated, in containers, and with hosts (.NET, JVM) that
  open their own threads or processes by ID.

## 15. `hkdfguard_open_file`: who could have written the key file (design decision + verified)

**Claim.** `hkdfguard_open_file` refuses a key file with
`HKDFGUARD_ERR_FILE_UNTRUSTED` (-39) unless the file and every folder above it,
up to the drive root, are owned by SYSTEM, BUILTIN\Administrators,
TrustedInstaller or the process's own account, and no other account holds a
right that would let it change what the path names. This is the Linux build's
owner and mode check (`key_file.rs`: owned by root or this user, not group- or
other-writable, sticky folders allowed), in ACL form. It also refuses a DEK
saved as text, in the same forms the Linux build does, with
`HKDFGUARD_ERR_FILE_PLAINTEXT_KEY` (-37).

**Why.** A wrapped DEK is ciphertext, so reading it gains nothing, and read
access for other accounts is never refused. *Replacing* it does gain
something. Any key-use principal can wrap (section 1). One that can also put a
file at the key's path can make the service run with a DEK it chose.

**How.** `src/key_file.cpp`. These checks run on the open handle, after the
link, short-name and local-drive checks, so the file that is judged is the
file that is read:

- **Owner.** It must be SYSTEM, Administrators, TrustedInstaller (which owns
  `C:\`) or the process token's user. Administrators is included because an
  elevated administrator's files are owned by the group. That is how the CLI's
  `wrap` writes them when run elevated (TokenOwner).
- **File rights.** No ACE for another principal may grant write data, append,
  write EA or attributes, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`,
  `GENERIC_WRITE` or `GENERIC_ALL`.
- **Folder rights.** No ACE for another principal may grant
  `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER` or `GENERIC_ALL`.
  Creating entries is allowed. A new entry can't displace an existing one: that
  takes `DELETE` on the entry, or `FILE_DELETE_CHILD` on its folder. This is the
  Windows counterpart of the sticky-folder allowance, and it is why
  `C:\ProgramData` (Users: `WD,AD,WEA,WA`) and `C:\` (Authenticated Users: `AD`)
  pass.
- **Ignored ACEs.** Deny ACEs and inherit-only ACEs are skipped. A conditional
  (callback) allow ACE is judged as if its condition held. Any other
  allow-ACE type is refused, as one this code can't read.
- **Special principals.** OWNER RIGHTS counts as the (already checked)
  owner. CREATOR OWNER and CREATOR GROUP match nobody outside an inherit-only
  ACE.
- **Missing DACL.** A missing or NULL DACL is refused, since it means
  unrestricted access.
- **Folder walk.** Each folder is opened without following reparse points and
  must still be a plain folder. Any folder whose security can't be read is
  refused (the file itself being unreadable is still -33).
- **Text keys.** A file of 96 bytes or fewer, other than 32, is read into a
  `SecureBuffer` that is wiped when it goes out of scope. After trimming
  whitespace the way Rust's `trim_ascii` does, it is a plaintext key if it is
  64 hex digits, or 43 characters of standard or URL-safe base64 (not mixed,
  with zero trailing bits, optionally followed by one `=`). That matches what
  the Rust base64 decoders the Linux build uses accept. It is decided without
  decoding, so the key is never rebuilt. None of it reaches the caller. A
  32-byte file is still refused unread.

**Verified how.** Test sections 24c and 24d:

- **Real files and folders.** A file Everyone may write is refused, while one
  Everyone may only read opens. A folder granting Everyone
  `FILE_DELETE_CHILD`, or `DELETE` on itself, is refused, while one granting
  only create rights (`0x116`) opens.
- **Synthetic descriptors** (`CheckKeyFileSecurity` on SDDL):
  - **Owners:** Users, Everyone and LocalService are refused; SYSTEM,
    Administrators, TrustedInstaller and this account pass.
  - **DACLs:** a missing or NULL DACL is refused.
  - **Rights:** each forbidden right is refused one at a time, on files and
    on folders.
  - **ACE kinds:** deny, inherit-only and conditional ACEs are handled as
    described above.
  - **Shipped ACLs:** the system drive root's ACL passes, and the
    `Authenticated Users: Modify` that a new folder under `C:\` inherits is
    refused.
- **Plaintext detector.** All six text forms (base64 padded or not, URL-safe
  padded or not, hex in either case) are refused, each with five whitespace
  variants. These near misses are refused as merely too short: 31 or 33 bytes
  as base64, 63 hex digits, a non-hex character, a newline inside the hex,
  mixed alphabets, set trailing bits, `==`, more than 96 bytes, and a
  vertical tab, which Rust doesn't trim either.

These passed non-elevated on the development machine on 2026-10-15. The
positive cases use the golden payload, so they don't depend on a KEK.

**Residual risk.**

- **What isn't checked.** Folders that intermediate links point into are not
  walked: links anywhere in the path are refused outright. Neither are
  hard-link siblings: they share the file's own ACL, which is checked.
- **Window between check and read.** A folder's ACL could in principle be
  widened between the check and the read, but only by someone who already
  holds `WRITE_DAC` on it, which is what was just checked for.
- **Configurations now refused.** Anything already in place that grants other
  accounts delete rights is refused, by design, including a folder created
  directly under `C:\`. `docs/admin-guide.md` shows how to narrow it.
- **Not yet run:** elevated, and in the Server 2022/2025 containers, where
  ContainerAdministrator's ownership of `C:\` needs to be confirmed.
