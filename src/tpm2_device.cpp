#include "tpm2_device.h"

#include <windows.h>
#include <bcrypt.h>
#include <tbs.h>

namespace hkdfguard::tpm2 {
    namespace {
        [[noreturn]] void BadTpmData(const char *what) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, what);
        }

        void Random(uint8_t *out, size_t len) {
            if (BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenRandom failed");
            }
        }
    } // namespace

    Transport OpenTbsTransport() {
        TBS_CONTEXT_PARAMS2 params{};
        params.version = TPM_VERSION_20;
        params.includeTpm20 = 1;
        TBS_HCONTEXT raw = 0;
        const TBS_RESULT result = Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&params), &raw);
        if (result != TBS_SUCCESS) {
            throw TpmError(HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, result, "no TPM 2.0 reachable through TBS");
        }
        // Shared by every copy of the transport; the last one closes it.
        std::shared_ptr<void> context(reinterpret_cast<void *>(raw), [](void *c) {
            Tbsip_Context_Close(reinterpret_cast<TBS_HCONTEXT>(c));
        });
        return [context](const Bytes &command) {
            Bytes response(kMaxResponse);
            UINT32 len = static_cast<UINT32>(response.size());
            const TBS_RESULT submitted = Tbsip_Submit_Command(
                reinterpret_cast<TBS_HCONTEXT>(context.get()), TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                command.data(), static_cast<UINT32>(command.size()), response.data(), &len);
            if (submitted != TBS_SUCCESS) {
                throw TpmError(HKDFGUARD_ERR_PROVIDER_ERROR, submitted, "TBS could not submit a TPM command");
            }
            response.resize(len);
            return response;
        };
    }

    Tpm::Tpm() : Tpm(OpenTbsTransport()) {}

    Tpm::Tpm(Transport transport) : transport_(std::move(transport)) {}

    void Tpm::FlushQuietly(uint32_t handle) noexcept {
        try {
            FlushContext(handle);
        } catch (...) {
        }
    }

    Response Tpm::Execute(const Bytes &command, size_t handle_count, size_t auth_count) {
        Response response = ParseResponse(transport_(command), handle_count, auth_count);
        if (response.response_code != 0) {
            throw TpmError(HKDFGUARD_ERR_PROVIDER_ERROR, response.response_code, "TPM command failed");
        }
        return response;
    }

    ReadPublicResult Tpm::ReadPublic(uint32_t handle) {
        ReadPublicResult result = ParseReadPublic(Execute(ReadPublicCommand(handle), 0, 0));
        if (ComputeName(result.public_area) != result.name) {
            BadTpmData("TPM ReadPublic Name does not match the public area");
        }
        return result;
    }

    std::vector<uint32_t> Tpm::PersistentHandles() {
        constexpr uint32_t kPersistentFirst = 0x81000000;
        bool more = false;
        std::vector<uint32_t> handles = ParseCapabilityHandles(
            Execute(GetCapabilityCommand(kCapHandles, kPersistentFirst, static_cast<uint32_t>(kMaxCapabilityCount)), 0, 0),
            more);
        for (uint32_t h : handles) {
            if ((h >> 24) != 0x81) {
                BadTpmData("TPM listed a non-persistent handle as persistent");
            }
        }
        return handles;
    }

    uint32_t Tpm::Property(uint32_t property) {
        bool more = false;
        const auto properties =
            ParseCapabilityProperties(Execute(GetCapabilityCommand(kCapTpmProperties, property, 1), 0, 0), more);
        if (properties.size() != 1 || properties[0].first != property) {
            throw TpmError(HKDFGUARD_ERR_PROVIDER_ERROR, 0, "TPM does not report the property");
        }
        return properties[0].second;
    }

    std::unique_ptr<Session> Tpm::StartSaltedSession(uint32_t tpm_key, const PublicArea &tpm_key_public) {
        SecureBuffer<kSha256Len> salt;
        Bytes encrypted_salt;
        MakeSessionSalt(tpm_key_public, salt, encrypted_salt);
        Bytes nonce_caller(kNonceLen);
        Random(nonce_caller.data(), nonce_caller.size());
        const StartAuthSessionResult started = ParseStartAuthSession(Execute(
            StartAuthSessionCommand(tpm_key, kRhNull, nonce_caller, encrypted_salt,
                                    static_cast<uint16_t>(kSessionKeyBits), kAlgSha256),
            1, 0));
        // A Session that can't be constructed (a nonceTPM of the wrong size)
        // is flushed here; once constructed, ScopedSession owns flushing it.
        try {
            return std::make_unique<Session>(started.session_handle, salt, started.nonce_tpm, nonce_caller);
        } catch (...) {
            FlushQuietly(started.session_handle);
            throw;
        }
    }

    CreateResult Tpm::Create(uint32_t parent, const Bytes &public_template) {
        return ParseCreate(Execute(
            BuildCommand(kCcCreate, {parent}, {PasswordSession()}, CreateParameters(public_template)), 0, 1));
    }

    LoadResult Tpm::Load(uint32_t parent, const Bytes &private_blob, const Bytes &public_blob) {
        LoadResult result = ParseLoad(Execute(
            BuildCommand(kCcLoad, {parent}, {PasswordSession()}, LoadParameters(private_blob, public_blob)), 1, 1));
        // The TPM computes the Name from the public blob it loaded; it must
        // be the one this side computes from the same bytes.
        const Bytes public_area(public_blob.begin() + 2, public_blob.end());
        if (ComputeName(public_area) != result.name) {
            FlushQuietly(result.object_handle);
            BadTpmData("TPM Load Name does not match the public blob");
        }
        return result;
    }

    LoadResult Tpm::LoadExternal(const Bytes &sensitive, const Bytes &public_area, uint32_t hierarchy) {
        LoadResult result = ParseLoad(Execute(LoadExternalCommand(sensitive, public_area, hierarchy), 1, 0));
        if (ComputeName(public_area) != result.name) {
            FlushQuietly(result.object_handle);
            BadTpmData("TPM LoadExternal Name does not match the public area");
        }
        return result;
    }

    void Tpm::Hmac(Session &session, uint32_t key, const Bytes &key_name, const Bytes &data,
                   SecureBuffer<kSha256Len> &out, bool continue_session) {
        const Bytes command =
            session.Authorize(kCcHmac, {key}, {key_name}, HmacParameters(data, kAlgSha256), continue_session);
        Response response;
        try {
            response = ParseResponse(transport_(command), 0, 1);
            session.Verify(response);
        } catch (...) {
            session.Abandon();
            throw;
        }
        if (response.response_code != 0) {
            throw TpmError(HKDFGUARD_ERR_PROVIDER_ERROR, response.response_code, "TPM2_HMAC failed");
        }
        const Bytes encrypted = ParseHmac(response);
        if (encrypted.size() != kSha256Len) {
            BadTpmData("TPM2_HMAC result is not 32 bytes");
        }
        session.DecryptResponseParameter(encrypted, out.data(), out.size());
    }

    void Tpm::FlushContext(uint32_t handle) {
        Execute(FlushContextCommand(handle), 0, 0);
    }

    ScopedTpmObject::~ScopedTpmObject() {
        try {
            tpm_.FlushContext(handle_);
        } catch (...) {
        }
    }

    ScopedSession::~ScopedSession() {
        if (session_ && session_->open()) {
            try {
                tpm_.FlushContext(session_->handle());
            } catch (...) {
            }
        }
    }
} // namespace hkdfguard::tpm2
