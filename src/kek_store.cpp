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
        // Always MS_PLATFORM_CRYPTO_PROVIDER in HkdfGuard.dll; a test build
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
        // HkdfGuard.dll these compile to "return the real status" and
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

        // Builds the name a KEK is persisted under in Windows key storage:
        // e.g. service "myapp" and key_id 1 becomes L"hkdfguardwin_myapp_v1".
        //
        // Every literal piece is lowercase, matching hkdfguard.cpp's
        // NormalizeService (which lowercases `service`), so the whole name is
        // lowercase.
        //
        // FROZEN - do not rename the "hkdfguardwin_" prefix. It is the
        // persisted name of every KEK already provisioned on every host:
        // changing it makes the library look for keys that don't exist, so
        // every existing KEK - and every DEK wrapped under it - becomes
        // unreachable.
        std::wstring KeyName(const std::wstring &service, uint32_t key_id) {
            return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id);
        }

        // Maps a provider_type byte (see wire_format.h's kProviderTypeTpm /
        // kProviderTypeSoftware) to the NCrypt provider name. An unknown
        // value throws HKDFGUARD_ERR_PROVIDER_ERROR.
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
                        HKDFGUARD_ERR_PROVIDER_ERROR,
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
        // The public status code is unchanged (HKDFGUARD_ERR_PROVIDER_ERROR or
        // HKDFGUARD_ERR_CRYPTO_ERROR); only PreferTpm's fallback logic looks at
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
                HKDFGUARD_ERR_PROVIDER_ERROR,
                "NCryptOpenStorageProvider failed");
        }

        // Throws the most specific HkdfGuardError an NCrypt failure
        // warrants. Used at every NCryptOpenKey call site (open-for-wrap,
        // open-for-unwrap, the exists check, and create's existence probe)
        // and at NCryptFinalizeKey - empirically the call that fails, with
        // NTE_PERM, when a process without Administrator rights creates a
        // machine-scoped (NCRYPT_MACHINE_KEY_FLAG) key:
        // NCryptCreatePersistedKey and the property-setting calls before it
        // succeed regardless of elevation; only finalizing enforces it.
        //
        //   - NTE_BAD_KEYSET  -> HKDFGUARD_ERR_KEK_NOT_FOUND: no key by
        //     this name exists yet (the service has never been
        //     provisioned, or a payload names a provider/key id this
        //     service never used). Only meaningful at the NCryptOpenKey
        //     call sites; NCryptFinalizeKey never returns it.
        //   - NTE_PERM ("Access is denied"), or the Win32
        //     ERROR_ACCESS_DENIED some providers return instead ->
        //     HKDFGUARD_ERR_KEK_ACCESS_DENIED: the key exists (or, at
        //     NCryptFinalizeKey, is about to) but this caller's token isn't
        //     authorized - most commonly, not elevated enough to finalize a
        //     machine-scoped key.
        //   - TBS_E_TPM_NOT_FOUND / NTE_DEVICE_NOT_FOUND -> TpmUnusableError
        //     (HKDFGUARD_ERR_PROVIDER_ERROR, fallback-eligible).
        //   - anything else -> HKDFGUARD_ERR_PROVIDER_ERROR (`genericMessage`): a
        //     genuine provider malfunction, unrelated to who's asking.
        //
        // Distinguishing these lets programs and operators tell "nothing
        // provisioned yet" from "not authorized" from "provider broken".
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
                    HKDFGUARD_ERR_KEK_ACCESS_DENIED,
                    "access to the KEK was denied");
            }

            // No TPM device at all: the one probe-time error that proves no
            // TPM KEK can be in use, so PreferTpm may fall back. A TPM that
            // is merely busy, locked out or not ready is deliberately NOT
            // here - a TPM KEK may well exist behind it.
            if (status == TBS_E_TPM_NOT_FOUND || status == NTE_DEVICE_NOT_FOUND)
            {
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "no TPM device is present");
            }

            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER_ERROR,
                genericMessage);
        }

        // Verifies the key is an ECDH key. Checks NCRYPT_ALGORITHM_GROUP_PROPERTY
        // ("Algorithm Group", e.g. "ECDH") rather than NCRYPT_ALGORITHM_PROPERTY
        // ("Algorithm Name", the curve-qualified AlgId passed to
        // NCryptCreatePersistedKey, e.g. "ECDH_P256"): at least one TPM KSP
        // (an AMD fTPM's Microsoft Platform Crypto Provider) reports
        // "Algorithm Name" as the bare family ("ECDH") for a genuine P-256
        // key, while the Software KSP keeps the curve-qualified name.
        // "Algorithm Group" is "ECDH" on every provider observed, so checking
        // it is portable without weakening the check: the curve itself is
        // pinned by VerifyKeyLength and VerifyCurve below.
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
                    sizeof(algorithmGroup) - sizeof(wchar_t), // keep a terminator
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot query key algorithm group");
            }

            if (wcscmp(
                    algorithmGroup,
                    NCRYPT_ECDH_ALGORITHM_GROUP) != 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot query key length");
            }

            if (length != 256)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot export key public blob");
            }

            std::vector<BYTE> blob(cb);
            status =
                NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), cb, &cb, 0);

            if (status != ERROR_SUCCESS || cb < sizeof(BCRYPT_ECCKEY_BLOB))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot export key public blob");
            }

            const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());

            if (header->dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || header->cbKey != 32)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
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
                        HKDFGUARD_ERR_PROVIDER_ERROR,
                        "key is not on the NIST P-256 curve");
                }
            }
            else if (status != NTE_NOT_FOUND && status != NTE_NOT_SUPPORTED)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot query key curve name");
            }
        }

        // Verifies the key's reported usage permits key agreement
        // (NCryptSecretAgreement - see ecdh_hkdf.cpp's
        // DeriveWrappingKeyForUnwrap).
        //
        // Accepts NCRYPT_ALLOW_DECRYPT_FLAG as well as
        // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG: at least one TPM KSP (an AMD
        // fTPM's Microsoft Platform Crypto Provider) pins every new
        // ECDH_P256 key's usage to NCRYPT_ALLOW_DECRYPT_FLAG and rejects
        // setting NCRYPT_ALLOW_KEY_AGREEMENT_FLAG (NTE_NOT_SUPPORTED - see
        // CreateKekOnProvider). Empirically this is a labeling quirk:
        // NCryptSecretAgreement with a supplied peer point (as
        // DeriveWrappingKey does with H(salt)) succeeds and yields a correct
        // shared secret. An ECDH key has no "decrypt" operation in CNG, and
        // VerifyAlgorithm has already confirmed the key is ECDH, so
        // accepting the Decrypt flag admits no other key type.
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot query key usage");
            }

            if ((usage &
                 (NCRYPT_ALLOW_KEY_AGREEMENT_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG)) == 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "key agreement usage missing");
            }
        }

        // Verifies the key's export policy forbids export.
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot query export policy");
            }

            if (policy &
                (NCRYPT_ALLOW_EXPORT_FLAG |
                 NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "key unexpectedly exportable");
            }
        }

        // Verifies the key is hardware backed (checked under RequireTpm and
        // for any TPM-provider key; see VerifyKeyProperties).
        //
        // Takes `provider` too because at least one TPM KSP (an AMD fTPM's
        // Microsoft Platform Crypto Provider) returns NTE_NOT_SUPPORTED for
        // NCRYPT_IMPL_TYPE_PROPERTY on every key handle, while the same
        // property on the provider handle correctly reports
        // NCRYPT_IMPL_HARDWARE_FLAG. Falling back to the provider handle only
        // on NTE_NOT_SUPPORTED keeps the per-key check where it is supported
        // and still fails closed: any other query error, or a result that
        // isn't hardware backed, throws.
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "cannot query implementation type");
            }

            if ((implType & NCRYPT_IMPL_HARDWARE_FLAG) == 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
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

        // The ACL invariants hkdfguard_create_kek enforces (VerifyExistingKeyAcl:
        // a real DACL, SYSTEM and Administrators on it, nothing over-broad),
        // checked again on every wrap, unwrap and fingerprint - but only when
        // the caller can read the ACL. Reading it needs READ_CONTROL. Key use
        // is granted as GENERIC_READ (key_acl.cpp), which under the standard
        // generic mapping includes READ_CONTROL, so a key-use account may
        // well be able to read it and get the check too; whether the KSP maps
        // it that way is untested (the tests ran elevated). If it can't, the
        // provisioning-time check stands for that account. Either way is
        // safe: the check can only refuse. So a KEK whose ACL was widened
        // after provisioning is refused with KEK_INVALID (event 2002) as soon
        // as any caller that can read the ACL uses it, without ever failing
        // an application that merely can't look. Any read failure other than
        // a violation is ignored here.
        void VerifyAclIfReadable(NCRYPT_KEY_HANDLE key)
        {
            try
            {
                VerifyExistingKeyAcl(key);
            }
            catch (const HkdfGuardError& e)
            {
                if (e.code() == HKDFGUARD_ERR_KEK_INVALID)
                {
                    throw;
                }
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
                    // blocking waiting for it) if the key carries a
                    // UI-requiring protection policy. Empirically accepted
                    // (not NTE_BAD_FLAGS) by NCryptOpenKey.
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
            VerifyAclIfReadable(result.key.get());

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
                    // NCRYPT_SILENT_FLAG: see OpenKekOnProvider.
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

            // NTE_PERM means this caller can't confirm whether the key
            // exists; it is reported as HKDFGUARD_ERR_KEK_ACCESS_DENIED, never
            // as `false` ("no KEK provisioned").
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
                    // NCRYPT_SILENT_FLAG: see OpenKekOnProvider.
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
                // necessarily one this library made - an admin could have
                // pre-planted it or widened its ACL. Accepting it unchecked
                // would hand DEKs to whoever that ACL admits. Checked against
                // policy-independent invariants only (see key_acl.h), so a
                // KeyUseGroups change since creation (which leaves the
                // existing ACL alone, by design) is still accepted.
                VerifyExistingKeyAcl(key.get());

                return false;
            }

            if (status != NTE_BAD_KEYSET)
            {
                // Only NTE_BAD_KEYSET (key absent) proceeds to creation;
                // anything else - notably NTE_PERM, when the key exists but
                // this caller can't open it - is an error.
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
            // and KEK_ACCESS_DENIED, which would fail on the software provider
            // just the same.
            //

            status =
                NCryptCreatePersistedKey(
                    provider.get(),
                    key.put(),
                    NCRYPT_ECDH_P256_ALGORITHM,
                    name.c_str(),
                    0,
                    // NCRYPT_SILENT_FLAG: see OpenKekOnProvider. Empirically
                    // accepted by NCryptCreatePersistedKey too.
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);

            if (status == NTE_EXISTS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "the KEK was created concurrently by another caller; retry");
            }

            if (status != ERROR_SUCCESS)
            {
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
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
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "setting export policy failed");
            }

            DWORD keyUsage =
                NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;

            // Best-effort, deliberately not fatal: at least one TPM KSP (an
            // AMD fTPM's Microsoft Platform Crypto Provider) returns
            // NTE_NOT_SUPPORTED here and pins ECDH_P256 key usage to
            // NCRYPT_ALLOW_DECRYPT_FLAG, though the key still performs
            // NCryptSecretAgreement correctly. Failing here would make
            // RequireTpm/PreferTpm unable to use a TPM on that hardware.
            // The security guarantee comes from VerifyKeyProperties below:
            // VerifyUsage re-reads the key's actual usage after
            // NCryptFinalizeKey and fails closed if neither flag is set.
            NCryptSetProperty(
                key.get(),
                NCRYPT_KEY_USAGE_PROPERTY,
                reinterpret_cast<PBYTE>(&keyUsage),
                sizeof(keyUsage),
                0);

            //
            // Grant the supplied groups unwrap/use access. Must happen before
            // NCryptFinalizeKey: key properties (including the security
            // descriptor) are only settable while the key is unfinalized.
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
                if (e.code() == HKDFGUARD_ERR_PROVIDER_ERROR)
                {
                    throw TpmUnusableError(e.code(), e.what());
                }
                throw;
            }

            status =
                NCryptFinalizeKey(
                    key.get(),
                    // NCRYPT_SILENT_FLAG: see OpenKekOnProvider. Empirically
                    // accepted by NCryptFinalizeKey.
                    NCRYPT_SILENT_FLAG);

            if (status != ERROR_SUCCESS)
            {
                // This call enforces elevation for a machine-scoped key and
                // reports a refusal as NTE_PERM (see ThrowForNCryptFailure),
                // mapped to HKDFGUARD_ERR_KEK_ACCESS_DENIED so it isn't
                // mistaken for a broken TPM/KSP.
                if (status == NTE_PERM ||
                    status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED))
                {
                    ThrowForNCryptFailure(status, "NCryptFinalizeKey failed");
                }

                if (status == NTE_EXISTS)
                {
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_PROVIDER_ERROR,
                        "the KEK was created concurrently by another caller; retry");
                }

                // Anything else: this provider could not create the key
                // (for example a TPM that cannot hold an ECDH P-256 key).
                throw TpmUnusableError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "NCryptFinalizeKey failed");
            }

            // A persisted key created by this call now exists. If any
            // post-finalize step fails, that unverified key must not be left
            // for a later OpenKekForWrap, so it is deleted here on its own
            // creation handle. This is the only place outside test cleanup
            // that deletes a KEK, and it is scoped to a key this call just
            // finalized: an existing key that fails verification (the
            // early-return path above) is never touched.
            try
            {
                // Verify on a freshly reopened handle, not `key`: at least
                // one TPM KSP (an AMD fTPM's Microsoft Platform Crypto
                // Provider) reports stale values on the creation handle right
                // after NCryptFinalizeKey (NCRYPT_LENGTH_PROPERTY as 0 rather
                // than 256), while a reopened handle reports them correctly.
                // The Software KSP is accurate either way.
                ScopedNCryptKey verifyKey;

                status =
                    NCryptOpenKey(
                        provider.get(),
                        verifyKey.put(),
                        name.c_str(),
                        0,
                        // NCRYPT_SILENT_FLAG: see OpenKekOnProvider.
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
                // KEK_ACCESS_DENIED and the like stay as they are.
                if (e.code() == HKDFGUARD_ERR_PROVIDER_ERROR ||
                    e.code() == HKDFGUARD_ERR_CRYPTO_ERROR)
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
                    // Same PreferTpm rule as CreateKek and OpenKekForWrap: an
                    // unusable TPM (see TpmUnusableError) means checking the
                    // software provider instead, so hkdfguard_kek_exists works
                    // on the TPM-less hosts the fallback exists for.
                    //
                    // Anything else propagates as-is: KEK_ACCESS_DENIED means a TPM
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
            HKDFGUARD_ERR_POLICY_INVALID,
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
        // Deployers wrap, so every deployer group gets key use as well:
        // KeyUseGroups and DeployerGroups are vetted and granted together.
        std::vector<std::wstring> aclGroups =
            LoadKeyUseGroupsPolicy();
        for (std::wstring &deployer: LoadDeployerGroupsPolicy())
        {
            aclGroups.push_back(std::move(deployer));
        }

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
                    // This handler never deletes a key: CreateKekOnProvider
                    // may have been verifying an existing, in-use TPM KEK, and
                    // deleting it would destroy every DEK wrapped under it.
                    //
                    // Everything else propagates: KEK_ACCESS_DENIED (not elevated
                    // - the software attempt would fail the same way - or a
                    // TPM KEK exists that this caller may not open) and
                    // KEK_INVALID (a TPM KEK exists with an unacceptable
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
            HKDFGUARD_ERR_POLICY_INVALID,
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
                    // KEK_ACCESS_DENIED - and anything else - propagates as-is: it
                    // means a TPM KEK exists and this caller may not use it.
                    // Swallowing it would let the software probe answer
                    // KEK_NOT_FOUND instead (the misreport KekExists also
                    // avoids). Such a caller never has a legitimate software
                    // KEK waiting: PreferTpm creates one only when the TPM
                    // attempt failed outright.
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
            HKDFGUARD_ERR_POLICY_INVALID,
            "invalid key storage policy");
    }

    ResolvedKek OpenKekForUnwrap(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        ResolvedKek result;
        result.provider_type = provider_type;
        result.key_id = key_id;

        SECURITY_STATUS status = NCryptOpenStorageProvider(result.provider.put(), ProviderName(provider_type), 0);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "NCryptOpenStorageProvider failed");
        }

        // Only ever opens: any NCryptOpenKey failure (including "doesn't
        // exist") is final. Unwrap must never create a KEK, since a new key
        // could never decrypt a payload wrapped under the original one.
        // NCRYPT_MACHINE_KEY_FLAG matches creation (see CreateKekOnProvider)
        // and is what lets an account other than the wrapping one find the
        // key: without it NCrypt searches the caller's per-user store and
        // fails with NTE_BAD_KEYSET regardless of privileges.
        std::wstring name = KeyName(service, key_id);
        // NCRYPT_SILENT_FLAG: see OpenKekOnProvider.
        status = NCryptOpenKey(
            result.provider.get(), result.key.put(), name.c_str(), 0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            ThrowForNCryptFailure(status, "NCryptOpenKey failed");
        }

        KeyStoragePolicy policy = LoadEffectivePolicy();

        // Unwrap takes its provider/key selection from the payload, not from
        // policy, so it has no policy switch with a trailing throw. Invalid
        // policy is rejected explicitly: otherwise it would silently skip
        // the RequireTpm hardware-backed check in VerifyKeyProperties below.
        if (policy == KeyStoragePolicy::Invalid) {
            throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
        }

        VerifyKeyProperties(
            result.key.get(),
            result.provider.get(),
            policy,
            result.provider_type);
        VerifyAclIfReadable(result.key.get());

        return result;
    }

    void DeleteKek(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        ScopedNCryptProv provider;
        SECURITY_STATUS status = NCryptOpenStorageProvider(provider.put(), ProviderName(provider_type), 0);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "NCryptOpenStorageProvider failed");
        }

        std::wstring name = KeyName(service, key_id);
        ScopedNCryptKey key;
        // Machine-scoped like every KEK (see OpenKekForUnwrap);
        // NCRYPT_SILENT_FLAG so test cleanup cannot block on a UI prompt.
        status = NCryptOpenKey(
            provider.get(), key.put(), name.c_str(), 0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "NCryptOpenKey failed");
        }

        status = NCryptDeleteKey(key.get(), 0);
        key.release(); // NCryptDeleteKey invalidates the handle even on failure; do not also free it
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "NCryptDeleteKey failed");
        }
    }
} // namespace hkdfguard
