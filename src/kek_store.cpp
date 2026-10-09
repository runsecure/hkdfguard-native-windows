#include "kek_store.h"
#include "errors.h"
#include "event_log.h"
#include <optional>
#include <string>
#include "policy.h"
#include "key_acl.h"

namespace hkdfguard {
    namespace {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        // See SetTestTpmProviderNameOverride in kek_store.h. Empty by
        // default, so a test binary that never sets it behaves exactly like
        // the DLL.
        std::optional<std::wstring> g_testTpmProviderNameOverride;

        // See SetTestTpmFaults in kek_store.h. Empty by default.
        TestTpmFaults g_testTpmFaults;
#endif

        // The NCrypt provider name used for everything "TPM" in this file.
        // Always MS_PLATFORM_CRYPTO_PROVIDER in HkdfGuardV1.dll; a test build
        // may point it at a nonexistent provider to exercise the "no TPM on
        // this machine" paths deterministically on hardware that has one.
        LPCWSTR TpmProviderName()
        {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
            if (g_testTpmProviderNameOverride.has_value())
            {
                return g_testTpmProviderNameOverride->c_str();
            }
#endif
            return MS_PLATFORM_CRYPTO_PROVIDER;
        }

        // Test seam hooks (see TestTpmFaults in kek_store.h). In
        // HkdfGuardV1.dll these compile to "return the real status" and
        // "never fail", so the shipped library behaves exactly as without
        // them.
        SECURITY_STATUS ApplyTestTpmOpenStatus(LPCWSTR providerName, SECURITY_STATUS actual)
        {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
            if (g_testTpmFaults.openKeyStatus.has_value() &&
                wcscmp(providerName, TpmProviderName()) == 0)
            {
                return *g_testTpmFaults.openKeyStatus;
            }
#endif
            (void)providerName;
            return actual;
        }

        bool TestTpmVerificationFails(uint8_t providerType)
        {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
            return g_testTpmFaults.failVerification && providerType == kProviderTypeTpm;
#else
            (void)providerType;
            return false;
#endif
        }

        // Builds the actual name a KEK is persisted under in Windows' key storage:
        // e.g. service "myapp" and key_id 1 becomes L"hkdfguardwin_myapp_v1". The
        // `L"..."` prefix on each string literal marks it as a *wide* string literal
        // (an array of wchar_t, UTF-16 on Windows) rather than the narrow (char,
        // typically UTF-8/ASCII) literals used elsewhere in the project (like
        // hkdfguard.cpp's UTF-8 `service` parameter) - matching what
        // std::wstring/NCrypt's LPCWSTR key-name parameters need. `operator+` on
        // std::wstring concatenates, same as it does for std::string, so this whole
        // expression builds up the final name piece by piece into one new string.
        //
        // Every literal piece here is deliberately lowercase, matching
        // hkdfguard.cpp's NormalizeService, which lowercases `service` itself
        // before it ever reaches this function - so the fully-assembled name
        // is lowercase end to end, not just the caller-supplied portion of
        // it.
        //
        // FROZEN - do not rename the "hkdfguardwin_" prefix. It comes from
        // this project's former name, but it is the persisted name of every
        // KEK already provisioned on every host: changing it makes the
        // library look for keys that don't exist, so every existing KEK -
        // and every DEK wrapped under it - becomes unreachable.
        std::wstring KeyName(const std::wstring &service, uint32_t key_id) {
            return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id);
        }

        // Maps a provider_type byte (see wire_format.h's kProviderTypeTpm /
        // kProviderTypeSoftware) to the actual provider name string NCrypt expects.
        // The `?:` ternary operator here is just a compact `if/else` that produces a
        // value: "if provider_type equals kProviderTypeTpm, the result is
        // TpmProviderName(), otherwise it's MS_KEY_STORAGE_PROVIDER."
        // LPCWSTR ("long pointer to constant wide string" - Windows' own typedef
        // for `const wchar_t*`) is the type both of those provider-name constants
        // have.
        LPCWSTR ProviderName(
            uint8_t provider_type)
        {
            switch (provider_type)
            {
                case kProviderTypeTpm:
                    return TpmProviderName();

                case kProviderTypeSoftware:
                    return MS_KEY_STORAGE_PROVIDER;

                default:
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_PROVIDER,
                        "invalid provider type");
            }
        }

        // The one failure PreferTpm may answer by falling back to the
        // software provider: the TPM cannot be used for this service at all,
        // and no TPM KEK for it can be in use. Thrown only when
        //
        //   - the TPM provider cannot even be opened (no TPM/vTPM, PCP not
        //     available),
        //   - the TPM reports that no device exists (TBS_E_TPM_NOT_FOUND,
        //     NTE_DEVICE_NOT_FOUND), or
        //   - the TPM key was confirmed absent (NTE_BAD_KEYSET) and creating
        //     it then failed, with any partly-created key already deleted.
        //
        // Everything else - an existing TPM KEK failing property
        // verification, an unexpected error while probing for one, a
        // concurrent creation - is a plain HkdfGuardError and propagates.
        // Falling back on those would put a second, software KEK beside a
        // TPM KEK that may be in use, permanently downgrading the service.
        // The public status code is unchanged (HKDFGUARD_ERR_PROVIDER or
        // HKDFGUARD_ERR_CRYPTO); only PreferTpm's fallback logic looks at
        // the type.
        class TpmUnusableError : public HkdfGuardError {
        public:
            using HkdfGuardError::HkdfGuardError;
        };

        bool IsTpmUnusable(const HkdfGuardError& e)
        {
            return dynamic_cast<const TpmUnusableError*>(&e) != nullptr;
        }

#ifndef TBS_E_TPM_NOT_FOUND
#define TBS_E_TPM_NOT_FOUND ((SECURITY_STATUS)0x8028400FL)
#endif

        // Thrown when NCryptOpenStorageProvider fails. Eligible for the
        // PreferTpm fallback (see TpmUnusableError); harmless on the software
        // provider, where nothing catches the distinction.
        [[noreturn]] void ThrowProviderOpenFailure()
        {
            throw TpmUnusableError(
                HKDFGUARD_ERR_PROVIDER,
                "NCryptOpenStorageProvider failed");
        }

        // Throws the most specific HkdfGuardError an NCrypt failure
        // warrants, rather than the generic HKDFGUARD_ERR_PROVIDER every
        // such failure used to collapse into. Used at every NCryptOpenKey
        // call site (open-for-wrap, open-for-unwrap, the exists check, and
        // create's "does it already exist" probe) and at
        // NCryptFinalizeKey's - empirically confirmed to be the call that
        // actually fails, with this exact status, when a process without
        // Administrator rights tries to create a *machine-scoped*
        // (NCRYPT_MACHINE_KEY_FLAG) key: NCryptCreatePersistedKey and the
        // property-setting calls before it all succeed regardless of
        // elevation; only finalizing the persisted key enforces it.
        //
        //   - NTE_BAD_KEYSET  -> HKDFGUARD_ERR_KEK_NOT_FOUND: no key by
        //     this name exists yet (the service has never been
        //     provisioned, or a payload names a provider/key id this
        //     service never used). Only meaningful at the NCryptOpenKey
        //     call sites; NCryptFinalizeKey never returns it.
        //   - NTE_PERM (Microsoft's own documented meaning is literally
        //     "Access is denied"), or the Win32 ERROR_ACCESS_DENIED some
        //     providers surface instead -> HKDFGUARD_ERR_ACCESS_DENIED: the
        //     key exists (or, at NCryptFinalizeKey, is about to) but this
        //     caller's token isn't authorized for the operation - which
        //     includes "not elevated enough to finalize a machine-scoped
        //     key," the single most common real-world cause of this whole
        //     function throwing.
        //   - anything else -> HKDFGUARD_ERR_PROVIDER (`genericMessage`): a
        //     genuine provider malfunction, unrelated to who's asking.
        //
        // Distinguishing these lets both a program (which can retry/report
        // differently) and an operator reading logs tell "nothing has been
        // provisioned yet" apart from "this account/process isn't
        // authorized" apart from "the provider itself is broken" -
        // previously all three were the same opaque code.
        [[noreturn]] void ThrowForNCryptFailure(
            SECURITY_STATUS status,
            const char* genericMessage)
        {
            if (status == NTE_BAD_KEYSET)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_KEK_NOT_FOUND,
                    "no KEK is provisioned for this service/provider/key id");
            }

            if (status == NTE_PERM ||
                status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_ACCESS_DENIED,
                    "access to the KEK was denied");
            }

            // No TPM device at all: the one probe-time error that proves no
            // TPM KEK can be in use, so PreferTpm may fall back. A TPM that
            // is merely busy, locked out or not ready is deliberately NOT
            // here - a TPM KEK may well exist behind it.
            if (status == TBS_E_TPM_NOT_FOUND || status == NTE_DEVICE_NOT_FOUND)
            {
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER,
                    "no TPM device is present");
            }

            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                genericMessage);
        }

        // Verifies the key is an ECDH key. Checks NCRYPT_ALGORITHM_GROUP_PROPERTY
        // ("Algorithm Group", e.g. "ECDH") rather than NCRYPT_ALGORITHM_PROPERTY
        // ("Algorithm Name", the curve-qualified AlgId originally passed to
        // NCryptCreatePersistedKey, e.g. "ECDH_P256"): at least one real TPM KSP
        // (an AMD fTPM's Microsoft Platform Crypto Provider) has been observed
        // reporting "Algorithm Name" as the bare algorithm family ("ECDH")
        // rather than the curve-qualified name it was created with, even though
        // the key genuinely is a P-256 key - the Software KSP, and presumably
        // other TPM KSPs, do preserve the curve-qualified name, but this
        // project can't assume every provider does. "Algorithm Group" is
        // consistently "ECDH" for an ECDH key on every provider observed
        // (curve-independent by definition), so checking it instead is
        // portable across providers without weakening this check: the curve
        // itself (P-256 specifically, not P-384/P-521) is independently
        // pinned by VerifyKeyLength below.
        void VerifyAlgorithm(
            NCRYPT_KEY_HANDLE key)
        {
            wchar_t algorithmGroup[64] = {};

            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_ALGORITHM_GROUP_PROPERTY,
                    reinterpret_cast<PBYTE>(algorithmGroup),
                    sizeof(algorithmGroup),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key algorithm group");
            }

            if (wcscmp(
                    algorithmGroup,
                    NCRYPT_ECDH_ALGORITHM_GROUP) != 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "unexpected key algorithm");
            }
        }

        // Additional verification that key length is 256
        void VerifyKeyLength(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD length = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_LENGTH_PROPERTY,
                    reinterpret_cast<PBYTE>(&length),
                    sizeof(length),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key length");
            }

            if (length != 256)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "unexpected key length");
            }
        }

        // Pins the curve to NIST P-256 specifically. VerifyKeyLength alone
        // does not: brainpoolP256r1, secp256k1 and other 256-bit named curves
        // CNG supports would pass it, and VerifyAlgorithm only checks the
        // "ECDH" family.
        //
        // Two checks, chosen from what both providers were observed to
        // support (a per-user ECDH_P256 key probed on an AMD fTPM's Platform
        // Crypto Provider and on the Software KSP):
        //
        //   1. The exported public blob's magic must be
        //      BCRYPT_ECDH_PUBLIC_P256_MAGIC with 32-byte coordinates. Both
        //      providers export a P-256 key this way; a key on any other
        //      named curve exports with the generic ECC magic instead.
        //      Exporting the public half is always permitted, whatever the
        //      key's export policy.
        //   2. If the provider reports NCRYPT_ECC_CURVE_NAME_PROPERTY, it
        //      must be "nistP256". The PCP reports it; the Software KSP
        //      returns NTE_NOT_FOUND for a key created with the
        //      curve-specific ECDH_P256 algorithm, so absence is accepted
        //      and check 1 carries the guarantee there.
        void VerifyCurve(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD cb = 0;
            SECURITY_STATUS status =
                NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &cb, 0);

            if (status != ERROR_SUCCESS || cb < sizeof(BCRYPT_ECCKEY_BLOB))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot export key public blob");
            }

            std::vector<BYTE> blob(cb);
            status =
                NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), cb, &cb, 0);

            if (status != ERROR_SUCCESS || cb < sizeof(BCRYPT_ECCKEY_BLOB))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot export key public blob");
            }

            const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());

            if (header->dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || header->cbKey != 32)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key is not on the NIST P-256 curve");
            }

            wchar_t curveName[64] = {};
            DWORD cbResult = 0;

            status =
                NCryptGetProperty(
                    key,
                    NCRYPT_ECC_CURVE_NAME_PROPERTY,
                    reinterpret_cast<PBYTE>(curveName),
                    sizeof(curveName) - sizeof(wchar_t), // keep a terminator
                    &cbResult,
                    0);

            if (status == ERROR_SUCCESS)
            {
                if (wcscmp(curveName, BCRYPT_ECC_CURVE_NISTP256) != 0)
                {
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_PROVIDER,
                        "key is not on the NIST P-256 curve");
                }
            }
            else if (status != NTE_NOT_FOUND && status != NTE_NOT_SUPPORTED)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key curve name");
            }
        }

        // Verifies the key's reported usage permits the key-agreement
        // operation this project actually performs (NCryptSecretAgreement -
        // see ecdh_hkdf.cpp's DeriveWrappingKeyForUnwrap).
        //
        // Accepts NCRYPT_ALLOW_DECRYPT_FLAG as well as
        // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG: at least one real TPM KSP (an AMD
        // fTPM's Microsoft Platform Crypto Provider) has been observed
        // hard-pinning every freshly-created ECDH_P256 key's usage to
        // NCRYPT_ALLOW_DECRYPT_FLAG and rejecting any attempt to set
        // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG instead (NCryptSetProperty
        // returns NTE_NOT_SUPPORTED - see CreateKekOnProvider's comment on
        // that same call). Verified empirically that this is a labeling
        // quirk, not an actual capability restriction: a genuine
        // NCryptSecretAgreement call against such a key, using a real
        // ephemeral peer public key, succeeds and produces a correct shared
        // secret. An ECDH key has no meaningful "decrypt" operation of its
        // own on Windows CNG (NCryptDecrypt is for RSA-family keys) - by the
        // time this function runs, VerifyAlgorithm has already confirmed
        // the key's algorithm group genuinely is ECDH, so accepting the
        // Decrypt flag here only accommodates this provider's mislabeling
        // of a key already known to be ECDH; it does not admit any
        // different, unintended key type.
        void VerifyUsage(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD usage = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    reinterpret_cast<PBYTE>(&usage),
                    sizeof(usage),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key usage");
            }

            if ((usage &
                 (NCRYPT_ALLOW_KEY_AGREEMENT_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG)) == 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key agreement usage missing");
            }
        }

        // Verifies there is no export agreement
        void VerifyExportPolicy(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD policy = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    reinterpret_cast<PBYTE>(&policy),
                    sizeof(policy),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query export policy");
            }

            if (policy &
                (NCRYPT_ALLOW_EXPORT_FLAG |
                 NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key unexpectedly exportable");
            }
        }

        // Verify the key is hardware backed when we set the TpmRequired policy.
        //
        // Takes `provider` in addition to `key` because at least one real TPM
        // KSP (an AMD fTPM's Microsoft Platform Crypto Provider) has been
        // observed returning NTE_NOT_SUPPORTED for NCRYPT_IMPL_TYPE_PROPERTY
        // on every *key* handle it hands out (creation handle or freshly
        // reopened, doesn't matter) - the property is simply not implemented
        // at the key level on that provider - while the identical property
        // queried on the *provider* handle itself succeeds and correctly
        // reports NCRYPT_IMPL_HARDWARE_FLAG. Falling back to the provider
        // handle only when the key-level query specifically reports
        // NTE_NOT_SUPPORTED preserves the more precise per-key check on
        // providers that support it, while still failing closed (a genuine
        // query error, or a provider/key that isn't actually hardware
        // backed, still throws either way).
        void VerifyHardwareBacked(
            NCRYPT_KEY_HANDLE key,
            NCRYPT_PROV_HANDLE provider)
        {
            DWORD implType = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_IMPL_TYPE_PROPERTY,
                    reinterpret_cast<PBYTE>(&implType),
                    sizeof(implType),
                    &cbResult,
                    0);

            if (status == NTE_NOT_SUPPORTED)
            {
                status =
                    NCryptGetProperty(
                        provider,
                        NCRYPT_IMPL_TYPE_PROPERTY,
                        reinterpret_cast<PBYTE>(&implType),
                        sizeof(implType),
                        &cbResult,
                        0);
            }

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query implementation type");
            }

            if ((implType & NCRYPT_IMPL_HARDWARE_FLAG) == 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key is not hardware backed");
            }
        }

        void VerifyKeyProperties(
            NCRYPT_KEY_HANDLE key,
            NCRYPT_PROV_HANDLE provider,
            KeyStoragePolicy policy,
            uint8_t provider_type)
        {
            if (TestTpmVerificationFails(provider_type))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "injected test fault: TPM key failed verification");
            }

            VerifyAlgorithm(key);
            VerifyKeyLength(key);
            VerifyCurve(key);
            VerifyUsage(key);
            VerifyExportPolicy(key);

            if (policy == KeyStoragePolicy::RequireTpm ||
                provider_type == kProviderTypeTpm)
            {
                VerifyHardwareBacked(key, provider);
            }
        }

        ResolvedKek OpenKekOnProvider(
            const std::wstring& service,
            LPCWSTR provider_name,
            uint8_t provider_type,
            uint32_t key_id,
            KeyStoragePolicy policy)
        {
            ResolvedKek result;

            result.provider_type = provider_type;
            result.key_id = key_id;

            SECURITY_STATUS status =
                NCryptOpenStorageProvider(
                    result.provider.put(),
                    provider_name,
                    0);

            if (status != ERROR_SUCCESS)
            {
                ThrowProviderOpenFailure();
            }

            std::wstring name =
                KeyName(service, key_id);

            status =
                NCryptOpenKey(
                    result.provider.get(),
                    result.key.put(),
                    name.c_str(),
                    0,
                    // NCRYPT_SILENT_FLAG: fail instead of showing UI (or
                    // blocking indefinitely waiting for it) if this key ever
                    // carried a UI-requiring protection policy - empirically
                    // confirmed accepted (not NTE_BAD_FLAGS) by NCryptOpenKey.
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);

            status = ApplyTestTpmOpenStatus(provider_name, status);

            if (status != ERROR_SUCCESS)
            {
                ThrowForNCryptFailure(status, "NCryptOpenKey failed");
            }

            VerifyKeyProperties(
                result.key.get(),
                result.provider.get(),
                policy,
                provider_type);

            return result;
        }

        // Opens the storage provider and reports whether the service's key
        // already exists there, without creating or modifying anything.
        // Throws HkdfGuardError for a genuine provider error; a missing key
        // (NTE_BAD_KEYSET) is reported via the return value, not an
        // exception.
        bool KekExistsOnProvider(
            const std::wstring& service,
            LPCWSTR providerName,
            uint32_t key_id)
        {
            ScopedNCryptProv provider;

            SECURITY_STATUS status =
                NCryptOpenStorageProvider(
                    provider.put(),
                    providerName,
                    0);

            if (status != ERROR_SUCCESS)
            {
                ThrowProviderOpenFailure();
            }

            std::wstring name =
                KeyName(service, key_id);

            ScopedNCryptKey key;

            status =
                NCryptOpenKey(
                    provider.get(),
                    key.put(),
                    name.c_str(),
                    0,
                    // See OpenKekOnProvider's identical NCryptOpenKey call
                    // above for why NCRYPT_SILENT_FLAG is added here too.
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);

            status = ApplyTestTpmOpenStatus(providerName, status);

            if (status == ERROR_SUCCESS)
            {
                return true;
            }

            if (status == NTE_BAD_KEYSET)
            {
                return false;
            }

            // Notably: NTE_PERM here means this caller can't even confirm
            // whether the key exists (reported as HKDFGUARD_ERR_ACCESS_DENIED,
            // not as `false`) - a permissions problem must never be
            // misreported as "no KEK provisioned."
            ThrowForNCryptFailure(status, "NCryptOpenKey failed");
        }

        // Returns true if this call created (and fully verified) a new KEK,
        // false if a valid one already existed - so the caller logs a
        // creation event only for an actual creation.
        bool CreateKekOnProvider(
            const std::wstring& service,
            LPCWSTR providerName,
            uint8_t providerType,
            const std::vector<std::wstring>& aclGroups,
            KeyStoragePolicy policy)
        {
            //
            // Open provider.
            //

            ScopedNCryptProv provider;

            SECURITY_STATUS status =
                NCryptOpenStorageProvider(
                    provider.put(),
                    providerName,
                    0);

            if (status != ERROR_SUCCESS)
            {
                ThrowProviderOpenFailure();
            }

            //
            // Open existing key.
            //

            std::wstring name =
                KeyName(
                    service,
                    kCurrentKeyId);

            ScopedNCryptKey key;

            status =
                NCryptOpenKey(
                    provider.get(),
                    key.put(),
                    name.c_str(),
                    0,
                    // See OpenKekOnProvider's identical NCryptOpenKey call
                    // above for why NCRYPT_SILENT_FLAG is added here too.
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);

            status = ApplyTestTpmOpenStatus(providerName, status);

            if (status == ERROR_SUCCESS)
            {
                VerifyKeyProperties(
                    key.get(),
                    provider.get(),
                    policy,
                    providerType);

                // An existing key under this service's name is not
                // necessarily one this library made - anyone with admin
                // rights could have pre-planted it, or widened its ACL since.
                // Accepting it as "using existing KEK" without looking would
                // hand DEKs to whoever that ACL admits. Checked against
                // policy-independent invariants only (see key_acl.h), so a
                // KeyUseGroups change since creation - documented as leaving
                // the existing ACL alone - is still accepted.
                VerifyExistingKeyAcl(key.get());

                return false;
            }

            if (status != NTE_BAD_KEYSET)
            {
                // NTE_BAD_KEYSET (handled above, by falling through to
                // create the key below) is the only outcome of this open
                // that ISN'T an error here; anything else - notably
                // NTE_PERM, if this key already exists but this caller
                // can't open it - is.
                ThrowForNCryptFailure(status, "NCryptOpenKey failed");
            }

            //
            // Create missing key.
            //
            // The key is now confirmed absent, so a failure from here on is
            // "this provider cannot create the KEK" and is eligible for the
            // PreferTpm fallback (TpmUnusableError) - except a concurrent
            // creation (NTE_EXISTS: another provisioner just made it, so a
            // KEK now exists here and falling back would split the service)
            // and ACCESS_DENIED, which would fail on the software provider
            // just the same.
            //

            status =
                NCryptCreatePersistedKey(
                    provider.get(),
                    key.put(),
                    NCRYPT_ECDH_P256_ALGORITHM,
                    name.c_str(),
                    0,
                    // NCRYPT_SILENT_FLAG - see OpenKekOnProvider's comment on
                    // the identical addition there; empirically confirmed
                    // accepted (not NTE_BAD_FLAGS) by NCryptCreatePersistedKey
                    // too.
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);

            if (status == NTE_EXISTS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "the KEK was created concurrently by another caller; retry");
            }

            if (status != ERROR_SUCCESS)
            {
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptCreatePersistedKey failed");
            }

            DWORD exportPolicy = 0;

            status =
                NCryptSetProperty(
                    key.get(),
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    reinterpret_cast<PBYTE>(&exportPolicy),
                    sizeof(exportPolicy),
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER,
                    "setting export policy failed");
            }

            DWORD keyUsage =
                NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;

            // Best-effort, and deliberately NOT fatal if the provider
            // rejects it outright: at least one real TPM KSP (an AMD
            // fTPM's Microsoft Platform Crypto Provider) has been observed
            // returning NTE_NOT_SUPPORTED for this exact call on an
            // ECDH_P256 key, hard-pinning every such key's usage to
            // NCRYPT_ALLOW_DECRYPT_FLAG instead and refusing to change it -
            // even though the key is still fully functional for a genuine
            // NCryptSecretAgreement (verified empirically against real TPM
            // hardware: the "Decrypt" label is a provider quirk, not an
            // actual capability restriction). Treating this call's failure
            // as fatal made RequireTpm/PreferTpm unable to ever use a real
            // TPM on that class of hardware, with PreferTpm silently
            // falling back to the software provider instead of surfacing
            // the problem. VerifyKeyProperties below (via VerifyUsage,
            // which accepts NCRYPT_ALLOW_DECRYPT_FLAG as well as
            // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG for exactly this reason)
            // re-reads the key's *actual* resulting usage after
            // NCryptFinalizeKey and still fails closed if it's ever
            // genuinely missing both - that check, not this call's own
            // status, is what keeps the security guarantee intact.
            NCryptSetProperty(
                key.get(),
                NCRYPT_KEY_USAGE_PROPERTY,
                reinterpret_cast<PBYTE>(&keyUsage),
                sizeof(keyUsage),
                0);

            //
            // Grant the supplied groups unwrap/use access. Must happen before
            // NCryptFinalizeKey below - NCrypt key properties (including the
            // security descriptor) are only settable while the key is still
            // in its unfinalized, "provisional" state.
            //

            try
            {
                ApplyKeyAcl(
                    key.get(),
                    aclGroups);
            }
            catch (const HkdfGuardError& e)
            {
                // Only the provider refusing the security descriptor is a
                // provider-capability failure; anything else (a key-use
                // group that stopped resolving, say) would fail on the
                // software provider just the same.
                if (e.code() == HKDFGUARD_ERR_PROVIDER)
                {
                    throw TpmUnusableError(e.code(), e.what());
                }
                throw;
            }

            status =
                NCryptFinalizeKey(
                    key.get(),
                    // NCRYPT_SILENT_FLAG - empirically confirmed accepted
                    // (not NTE_BAD_FLAGS) by NCryptFinalizeKey; see
                    // OpenKekOnProvider's comment on the same addition.
                    NCRYPT_SILENT_FLAG);

            if (status != ERROR_SUCCESS)
            {
                // Empirically confirmed (see ThrowForNCryptFailure's
                // comment): this is the call that actually enforces
                // elevation for a machine-scoped key, and it reports that
                // as NTE_PERM - mapped below to HKDFGUARD_ERR_ACCESS_DENIED,
                // not the generic HKDFGUARD_ERR_PROVIDER a caller could
                // otherwise mistake for "the TPM/KSP itself is broken."
                if (status == NTE_PERM ||
                    status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED))
                {
                    ThrowForNCryptFailure(status, "NCryptFinalizeKey failed");
                }

                if (status == NTE_EXISTS)
                {
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_PROVIDER,
                        "the KEK was created concurrently by another caller; retry");
                }

                // Anything else: this provider could not create the key
                // (for example a TPM that cannot hold an ECDH P-256 key).
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptFinalizeKey failed");
            }

            // From here on, a real persisted key exists that *this call*
            // created. If any post-finalize step below fails, that key has
            // never been verified and must not be left behind for a later
            // OpenKekForWrap to pick up - so it is deleted right here, by
            // this call, on its own creation handle. This is the only place
            // in the library that deletes a KEK outside of test cleanup, and
            // it is deliberately scoped to a key this same call finalized
            // moments earlier: an *existing* key that fails verification
            // (the early-return path above) is never touched.
            try
            {
                // Verify against a *freshly-reopened* handle, not `key` (the
                // one still held from creation/finalization): at least one
                // real TPM KSP (an AMD fTPM's Microsoft Platform Crypto
                // Provider) has been observed reporting stale/incomplete
                // property values - NCRYPT_LENGTH_PROPERTY as 0 rather than
                // 256 - when queried on the creation handle immediately after
                // NCryptFinalizeKey, while the exact same property on a
                // freshly-opened handle for the identical, already-finalized
                // key correctly reports 256. The Software KSP doesn't exhibit
                // this (its creation handle already reports accurate values),
                // but reopening costs little and this is what makes
                // verification reliable on both.
                ScopedNCryptKey verifyKey;

                status =
                    NCryptOpenKey(
                        provider.get(),
                        verifyKey.put(),
                        name.c_str(),
                        0,
                        // See OpenKekOnProvider's identical NCryptOpenKey call
                        // above for why NCRYPT_SILENT_FLAG is added here too.
                        NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);

                if (status != ERROR_SUCCESS)
                {
                    ThrowForNCryptFailure(status, "NCryptOpenKey (post-finalize verification) failed");
                }

                VerifyKeyProperties(
                    verifyKey.get(),
                    provider.get(),
                    policy,
                    providerType);

                VerifyKeyAcl(
                    verifyKey.get(),
                    aclGroups);
            }
            catch (const HkdfGuardError& e)
            {
                // NCryptDeleteKey invalidates the handle even on failure, so
                // `key` must forget it rather than also free it.
                SECURITY_STATUS deleteStatus = NCryptDeleteKey(key.get(), 0);
                key.release();

                // If the unverified key could not be removed, it is still
                // here, and a software KEK must not be created beside it.
                // The verification error is reported, but as non-fallback.
                if (deleteStatus != ERROR_SUCCESS)
                {
                    throw HkdfGuardError(e.code(), e.what());
                }

                // The key this call created is gone, so the provider simply
                // could not produce a verifiable KEK: fallback-eligible.
                // ACCESS_DENIED and the like stay as they are.
                if (e.code() == HKDFGUARD_ERR_PROVIDER ||
                    e.code() == HKDFGUARD_ERR_CRYPTO)
                {
                    throw TpmUnusableError(e.code(), e.what());
                }
                throw;
            }

            return true;
        }
    } // namespace

    bool KekExists(
        const std::wstring& service)
    {
        KeyStoragePolicy policy =
            LoadEffectivePolicy();

        switch (policy)
        {
            case KeyStoragePolicy::RequireTpm:
                return KekExistsOnProvider(
                    service,
                    TpmProviderName(),
                    kCurrentKeyId);

            case KeyStoragePolicy::SoftwareOnly:
                return KekExistsOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kCurrentKeyId);

            case KeyStoragePolicy::PreferTpm:
                try
                {
                    if (KekExistsOnProvider(
                            service,
                            TpmProviderName(),
                            kCurrentKeyId))
                    {
                        return true;
                    }
                }
                catch (const HkdfGuardError& e)
                {
                    // Mirror CreateKek's and OpenKekForWrap's PreferTpm
                    // behavior: if the TPM is unusable (no TPM/vTPM on this
                    // machine - see TpmUnusableError), that's a reason to look
                    // at the software provider instead, not a reason to fail
                    // the whole call - otherwise hkdfguard_kek_exists would
                    // fail outright on exactly the TPM-less hosts PreferTpm's
                    // fallback exists for.
                    //
                    // Anything else propagates as-is: ACCESS_DENIED means a TPM
                    // key *does* exist and this caller may not open it, and an
                    // unexpected probe error means one might. Answering from
                    // the software provider in either case could report "no
                    // KEK" for a service whose TPM KEK is in use.
                    if (!IsTpmUnusable(e))
                    {
                        throw;
                    }
                }

                return KekExistsOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kCurrentKeyId);
        }

        throw HkdfGuardError(
            HKDFGUARD_ERR_INVALID_POLICY,
            "invalid key storage policy");
    }

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestTpmProviderNameOverride(std::optional<std::wstring> providerName)
    {
        g_testTpmProviderNameOverride = std::move(providerName);
    }

    void SetTestTpmFaults(const TestTpmFaults &faults)
    {
        g_testTpmFaults = faults;
    }
#endif

    void CreateKek(
        const std::wstring& service)
    {
        // Machine policy decides who may use the key (see hkdfguard.h).
        // Validated first, before any provider is opened: a policy entry
        // that isn't a real, non-over-broad group must fail the call
        // outright rather than leave a key behind that was created and then
        // abandoned part-way through ACL application.
        std::vector<std::wstring> aclGroups =
            LoadKeyUseGroupsPolicy();

        ValidateKeyUseGroups(aclGroups);

        KeyStoragePolicy policy =
            LoadEffectivePolicy();

        switch (policy)
        {
            case KeyStoragePolicy::RequireTpm:
            {
                if (CreateKekOnProvider(
                        service,
                        TpmProviderName(),
                        kProviderTypeTpm,
                        aclGroups,
                        policy))
                {
                    LogKekCreated(service, kProviderTypeTpm, HKDFGUARD_OK);
                }

                return;
            }

            case KeyStoragePolicy::SoftwareOnly:
            {
                if (CreateKekOnProvider(
                        service,
                        MS_KEY_STORAGE_PROVIDER,
                        kProviderTypeSoftware,
                        aclGroups,
                        policy))
                {
                    LogKekCreated(service, kProviderTypeSoftware, HKDFGUARD_OK);
                }

                return;
            }

            case KeyStoragePolicy::PreferTpm:
            {
                try
                {
                    if (CreateKekOnProvider(
                            service,
                            TpmProviderName(),
                            kProviderTypeTpm,
                            aclGroups,
                            policy))
                    {
                        LogKekCreated(service, kProviderTypeTpm, HKDFGUARD_OK);
                    }
                }
                catch (const HkdfGuardError& e)
                {
                    // Fall back to the software provider only when the TPM is
                    // genuinely unusable for this service (TpmUnusableError):
                    // no TPM, or the TPM key was confirmed absent and creating
                    // it failed. Any key this attempt itself created and
                    // couldn't verify has already been deleted inside
                    // CreateKekOnProvider (and if that delete failed, the
                    // error is not fallback-eligible), so nothing unverified
                    // is left on the TPM for a later OpenKekForWrap to find.
                    //
                    // In particular, an *existing* TPM KEK that fails property
                    // verification, or an unexpected error while probing for
                    // one, does NOT fall back. Either may be a transient TPM
                    // fault or a provider quirk in front of a KEK that is in
                    // use; creating a software KEK beside it would split the
                    // service and permanently route new wraps to the weaker
                    // key.
                    //
                    // This handler used to delete the TPM key itself on *any*
                    // failure. That was dangerous: CreateKekOnProvider also
                    // handles a TPM KEK that already exists and is in use,
                    // and a failure verifying it would have deleted it -
                    // destroying every DEK wrapped under it. Nothing here
                    // deletes anything now.
                    //
                    // Everything else propagates: ACCESS_DENIED (not elevated
                    // - the software attempt would fail the same way - or a
                    // TPM KEK exists that this caller may not open) and
                    // KEK_ACL_INVALID (a TPM KEK exists with an unacceptable
                    // ACL). In both "exists" cases, quietly creating a second,
                    // software KEK beside it would split the service across
                    // two keys.
                    if (!IsTpmUnusable(e))
                    {
                        throw;
                    }

                    // Logged only if this actually creates the software KEK -
                    // on a TPM-less host every later re-provision also takes
                    // this branch, but finds the software KEK already there.
                    if (CreateKekOnProvider(
                            service,
                            MS_KEY_STORAGE_PROVIDER,
                            kProviderTypeSoftware,
                            aclGroups,
                            policy))
                    {
                        LogKekCreated(service, kProviderTypeSoftware, e.code());
                    }
                }

                return;
            }
        }

        throw HkdfGuardError(
            HKDFGUARD_ERR_INVALID_POLICY,
            "invalid key storage policy");
    }

    ResolvedKek OpenKekForWrap(
        const std::wstring& service)
    {
        KeyStoragePolicy policy = LoadEffectivePolicy();

        switch (policy) {

            case KeyStoragePolicy::RequireTpm:
                return OpenKekOnProvider(
                    service,
                    TpmProviderName(),
                    kProviderTypeTpm,
                    kCurrentKeyId,
                    policy);

            case KeyStoragePolicy::SoftwareOnly:
                return OpenKekOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kProviderTypeSoftware,
                    kCurrentKeyId,
                    policy);

            case KeyStoragePolicy::PreferTpm:
                try {
                    return OpenKekOnProvider(
                        service,
                        TpmProviderName(),
                        kProviderTypeTpm,
                        kCurrentKeyId,
                        policy);
                }
                catch (const HkdfGuardError& e) {
                    // Fall through to the software provider only when the TPM
                    // side genuinely has nothing for us: no KEK there
                    // (KEK_NOT_FOUND - the normal case for a PreferTpm KEK that
                    // was created on the software fallback), or no usable TPM
                    // at all (TpmUnusableError).
                    //
                    // A TPM KEK that exists but fails verification, or an
                    // unexpected error opening it, propagates. Falling back
                    // would quietly wrap new DEKs under a software KEK (if one
                    // exists) instead of surfacing that the service's TPM KEK
                    // has a problem.
                    //
                    // ACCESS_DENIED - and anything else - propagates as-is: it
                    // means a TPM KEK exists and this caller may not use it.
                    // Swallowing it would make the software probe below answer
                    // instead, so an unauthorized caller would be told
                    // KEK_NOT_FOUND ("nothing provisioned") rather than
                    // ACCESS_DENIED - the same misreport KekExists is careful
                    // to avoid. A caller in that position also never has a
                    // software KEK legitimately waiting for it: PreferTpm only
                    // creates one when the TPM attempt failed outright.
                    if (e.code() != HKDFGUARD_ERR_KEK_NOT_FOUND &&
                        !IsTpmUnusable(e))
                    {
                        throw;
                    }

                    return OpenKekOnProvider(
                        service,
                        MS_KEY_STORAGE_PROVIDER,
                        kProviderTypeSoftware,
                        kCurrentKeyId,
                        policy);
                }
        }

        throw HkdfGuardError(
            HKDFGUARD_ERR_INVALID_POLICY,
            "invalid key storage policy");
    }

    ResolvedKek OpenKekForUnwrap(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        ResolvedKek result;
        result.provider_type = provider_type;
        result.key_id = key_id;

        SECURITY_STATUS status = NCryptOpenStorageProvider(result.provider.put(), ProviderName(provider_type), 0);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenStorageProvider failed");
        }

        // Unlike CreateKekOnProvider, this function only ever *opens* -
        // if NCryptOpenKey fails for any reason (including "doesn't exist"),
        // that's treated as an unconditional failure; unwrap must never create
        // a new KEK, since a newly-created key could never actually decrypt
        // anything wrapped under whatever KEK originally produced this payload.
        // NCRYPT_MACHINE_KEY_FLAG must match what the key was created with
        // (see CreateKekOnProvider) - this is exactly what lets an
        // account other than the one that wrapped the DEK successfully find
        // and use this key: opening without the flag would search that
        // account's own per-user key store instead, where this key was never
        // created, and fail with NTE_BAD_KEYSET regardless of privileges.
        std::wstring name = KeyName(service, key_id);
        // NCRYPT_SILENT_FLAG - see OpenKekOnProvider's comment on the
        // identical addition there.
        status = NCryptOpenKey(
            result.provider.get(), result.key.put(), name.c_str(), 0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            ThrowForNCryptFailure(status, "NCryptOpenKey failed");
        }

        KeyStoragePolicy policy = LoadEffectivePolicy();

        // Unwrap doesn't switch over `policy` the way KekExists/CreateKek/
        // OpenKekForWrap do (its provider/key selection comes entirely from
        // the payload's own fields, not from policy), so it has no
        // switch-with-trailing-throw to fall through into automatically.
        // Checked explicitly instead: an invalid policy must not silently
        // skip the RequireTpm-only hardware-backed check VerifyKeyProperties
        // performs just below - that would let a misconfigured registry
        // value quietly weaken verification on every unwrap.
        if (policy == KeyStoragePolicy::Invalid) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_POLICY, "invalid key storage policy");
        }

        VerifyKeyProperties(
            result.key.get(),
            result.provider.get(),
            policy,
            result.provider_type);

        return result;
    }

    void DeleteKek(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        ScopedNCryptProv provider;
        SECURITY_STATUS status = NCryptOpenStorageProvider(provider.put(), ProviderName(provider_type), 0);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenStorageProvider failed");
        }

        std::wstring name = KeyName(service, key_id);
        ScopedNCryptKey key;
        // Same NCRYPT_MACHINE_KEY_FLAG requirement as OpenKekForUnwrap above -
        // this key was created machine-wide, so it must also be opened (in
        // order to then be deleted) machine-wide. NCRYPT_SILENT_FLAG too -
        // see OpenKekOnProvider's comment on the identical addition there;
        // no reason test cleanup should be able to block on a UI prompt
        // either.
        status = NCryptOpenKey(
            provider.get(), key.put(), name.c_str(), 0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenKey failed");
        }

        // NCryptDeleteKey both removes the persisted key from storage *and*
        // invalidates the handle it's called with, as part of one operation -
        // unlike every other NCrypt function used in this project, which only
        // ever *uses* a handle and leaves closing it to us (via ScopedNCryptKey
        // later, or explicitly).
        status = NCryptDeleteKey(key.get(), 0);
        // Because NCryptDeleteKey already invalidated `key`'s handle above
        // (this is true even if the delete failed), we must not let
        // ScopedNCryptKey's destructor also try to close it - that would be a
        // double-close on an already-invalid handle. `key.release()` (see
        // handle_traits.h) tells `key` to forget the handle without closing it,
        // exactly for this situation.
        key.release(); // NCryptDeleteKey invalidates the handle even on failure; do not also free it
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptDeleteKey failed");
        }
    }
} // namespace hkdfguard
