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
  return that older DEK. The defense is the wrapped file's ACL (owner
  read/write, one group read-only - see the CLI's `--group`), not the
  payload format. An application that needs to refuse old DEKs must check
  that itself, after unwrapping.
- **Anyone who can unwrap can also forge.** Wrapping needs only the KEK's
  *public* key, which any key-use principal can export. So every principal
  granted key use (`KeyUseGroups`, `HkdfGuardUsers`) can mint a brand-new,
  fully valid payload for the service around a DEK of its own choosing, and
  unwrap will accept it exactly like a genuine one. The payload is
  authenticated as "made for this service under this KEK", never as "made
  by the deployment step". Consequences: a key-use principal that can also
  write the wrapped-key file can make the service run with a DEK it picked,
  not just an older genuine one. The audit trail only partly helps: a
  forger who calls `hkdfguard_wrap_dek` leaves a wrap event (1002) under its
  own account, but one who builds the payload itself, from the public key,
  leaves none - and an unwrap event (1003) whose payload SHA-256 matches no
  wrap event by the deployment account is the sign of that.
  The defenses are the same as for rollback: keep key-use groups narrow, and
  keep the wrapped file writable only by the deployment account. An
  application that must know a DEK came from its own deployment needs a
  separate signature over the payload, made with a key the service can only
  verify.
- **Local Administrators and SYSTEM are fully trusted.** They always hold
  full control of every KEK, can change the registry policy, and can alter a
  key's ACL. Nothing here defends the KEK against a host administrator.
- **The host process is trusted to load the right DLL.** Loading by bare
  filename lets the OS search order pick a planted library; README.md's
  "Consuming from other languages" section is the mitigation, not code.

## 2. Public-key point validation (verified)

**Claim.** An attacker-supplied P-256 point that is not on the curve is
rejected before it is ever combined with the long-term KEK private key.

**Why it matters.** The ephemeral public key in a wrapped payload is the one
input an attacker controls outright, and `NCryptSecretAgreement` combines it
with the KEK's private key - the classic invalid-curve / small-subgroup
setup. P-256 has cofactor 1, so an on-curve check is sufficient.

**Verified how.** `BCryptImportKeyPair(BCRYPT_ECCPUBLIC_BLOB)` was fuzzed
with valid keys, all-zero and all-0xFF coordinates, random coordinates,
single-bit mutations of valid keys, and 100 fuzzed valid keys: every valid
point imported, every malformed point was rejected, no mutated point
imported. `tests/test_roundtrip.cpp` re-checks the gate on every run with
valid, all-zero, all-0xFF and single-bit-mutated (X and Y) points.

**Where it is applied.** `ValidateEphemeralPublicKey` (`src/ecdh_hkdf.cpp`)
runs on the unwrap path *before* `NCryptImportKey`, for every provider. The
fuzzing covered only the software provider's import; the Platform Crypto
Provider's own import validation was never tested and is no longer relied
upon. The point is copied out of the caller's payload buffer exactly once
and both the validation and the later import read that copy, so a hostile
thread in the host process cannot swap the bytes between check and use.

**Residual risk.** None known for this input. The wrap side imports the
KEK's *own* public key (not attacker-controlled) through the same fuzzed
path.

## 3. Raw ECDH secret byte order agrees across providers (verified, pre-fingerprint)

**Claim.** `BCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)` on the software
ephemeral key (wrap side) and `NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)` on a
TPM-resident KEK via the Platform Crypto Provider (unwrap side) return the
shared secret in the same byte order, so both sides feed identical bytes to
HKDF.

**Why it matters.** Microsoft documents `BCRYPT_KDF_RAW_SECRET` as returning
the secret little-endian for BCrypt, and says nothing about whether every
KSP's `NCryptDeriveKey` does the same. If they disagreed, every TPM-backed
unwrap would fail authentication.

**Verified how.** A full wrap (BCrypt) / unwrap (NCrypt, provider_type = 1,
AMD fTPM) round-trip succeeded in the elevated test suite, most recently on
2026-10-06 after the curve-pinning change to `src/ecdh_hkdf.cpp`. Re-run the
elevated suite after any change to that file to keep this claim current.

**The byte order itself is pinned.** The library uses the raw secret exactly
as `BCRYPT_KDF_RAW_SECRET` returns it - little-endian, i.e. the shared
point's X coordinate byte-reversed - as the HKDF input. Section 29 of
`tests/test_roundtrip.cpp` rebuilds a frozen golden payload from the
documented construction, independently of `src/`, and checks the shipped DLL
unwraps it to a known DEK. Any change to the IKM byte order, the HKDF salt,
hash or info string, the AAD, or the wire layout fails that test while
ordinary round trips still pass (verified by deliberately changing the HKDF
context string). Note for cross-platform work: an implementation that feeds
HKDF the conventional big-endian X coordinate derives a different key, so
claims of matching another platform's construction hold only if that
platform reverses the bytes too.

**Residual risk.** Verified on one TPM vendor/firmware only.

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

**Consequence.** That failure is reported as `HKDFGUARD_ERR_ACCESS_DENIED`
(not the generic `HKDFGUARD_ERR_PROVIDER`), and the CLI's "requires an
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
  `HKDFGUARD_ERR_INVALID_POLICY`. **Verified** by test
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
- The default `PreferTpm` fallback to software is a **design decision**:
  the policy is the administrator's to set. It falls back only when the TPM
  is provably unusable for the service: the TPM provider cannot be opened,
  the TPM reports no device (`TBS_E_TPM_NOT_FOUND`, `NTE_DEVICE_NOT_FOUND`),
  or the TPM key was confirmed absent (`NTE_BAD_KEYSET`) and creating it
  failed, with the partly-created key successfully deleted. Internally these
  are the only failures thrown as `TpmUnusableError`; the public code is
  still `HKDFGUARD_ERR_PROVIDER`. Everything else propagates, including an
  *existing* TPM KEK that fails property verification, any other error while
  probing for the TPM key (a busy, locked-out or not-ready TPM), a
  concurrent creation (`NTE_EXISTS`), `ACCESS_DENIED` and `KEK_ACL_INVALID`.
  Each of those may sit in front of a TPM KEK that is in use, and creating a
  second, software KEK beside it would split the service and permanently
  route new wraps to the weaker key. `OpenKekForWrap` (which also falls back
  on `KEK_NOT_FOUND`) and `KekExists` follow the same rule, so an
  unauthorized caller is told `ACCESS_DENIED`, never `KEK_NOT_FOUND`.
  **Assumed / not verified**: that a host with no TPM fails at
  `NCryptOpenStorageProvider` or reports one of the two "no device" codes.
  If some host instead reports a different code when probing for the key,
  `PreferTpm` there now fails with `HKDFGUARD_ERR_PROVIDER` rather than
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
  `NTE_PERM` (surfaced as `HKDFGUARD_ERR_ACCESS_DENIED`). **Design
  decision.** A fresh key's ACL is checked for the presence of every
  principal it was granted. An *existing* key found by
  `hkdfguard_create_kek` is checked against policy-independent invariants
  instead: a real (non-NULL) DACL, SYSTEM and Administrators present, and
  no grant of any kind to an over-broad principal, whether through a plain
  or a conditional (callback) allow ACE. An object or compound allow ACE,
  which this library never writes, or an unreadable ACE fails the check
  outright rather than being skipped. Failing that returns
  `HKDFGUARD_ERR_KEK_ACL_INVALID` and leaves the key untouched. This
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
  (`HKDFGUARD_ERR_ACCESS_DENIED`, elevation required), confirming creation
  and use are genuinely governed by separate mechanisms (elevation vs.
  ACL). Both the KEK and the test account/group were removed afterward.

## 10. Payload integrity and the KEK fingerprint (verified where noted)

- AES-256-GCM authenticates `normalized service name || SHA-256(KEK public
  key, raw X||Y)`. The fingerprint also travels in the payload and is
  compared, before any ECDH, against the fingerprint of the KEK the
  payload's routing fields select; mismatch is `HKDFGUARD_ERR_KEK_MISMATCH`.
  It is a check on the selected key, never a lookup - searching for a key
  matching an attacker-supplied fingerprint would let the payload steer
  key selection. **Verified** by tests for the mismatch path (elevated).
- The comparison is a plain `memcmp`, deliberately: both operands are
  hashes of *public* keys, so timing reveals nothing secret.
- `Version` and `Reserved` are not in the AAD. `Reserved` is required to be
  zero and `Version` to be `1`, so neither can currently be varied at all;
  if a second version is ever introduced, `Version` should be added to the
  AAD at that point.
- Each wrap uses a fresh ephemeral ECDH key and therefore a fresh AES key,
  so the random 96-bit nonce can never repeat under a key.
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
- Service names are restricted to ASCII letters, digits and `.`, lowercased,
  and used inside a fixed prefix/suffix to form the persisted key name. The
  Software KSP and PCP store keys under a hash of the container name, so
  `.` cannot form a path. **Assumed / not verified** beyond standard
  provider behaviour.

## 12. Known gaps (not yet addressed)

- The audit trail (Application event log, source
  `HkdfGuard.Kms.Windows.v1`; see README.md "Audit logging") is best
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
