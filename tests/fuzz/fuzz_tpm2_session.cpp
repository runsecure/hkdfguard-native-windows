// libFuzzer target for src/tpm2_session.cpp's handling of a TPM2_HMAC
// response: ParseResponse, Session::Verify and DecryptResponseParameter,
// as Tpm::Hmac runs them on the TPM's answer. Built only with
// -DHKDFGUARD_BUILD_FUZZERS=ON, with AddressSanitizer.
//
// The first input byte chooses the mode; the rest is the response.
//   bit 0 clear: the response as given. Verify must refuse anything that
//     parses as a success, since nobody without the session key can sign it.
//   bit 0 set: whatever parses with one authorization is re-signed here
//     with the session's own key (which the target knows: it chose the salt
//     and nonces), so the code past a verified response is reached too.
//   bit 1: whether the command asked for continueSession.
//
// Properties:
//   - No input crashes; only HkdfGuardError is ever thrown.
//   - An unsigned success response never verifies.
//   - After a verified response, open() is exactly the response's own
//     continueSession bit, whatever the command asked for (finding 7), and
//     a 32-byte result decrypts.
//
// Seeds: tests/fuzz/corpus/fuzz_tpm2_session.
#include "fuzz_common.h"
#include "errors.h"
#include "tpm2_marshal.h"
#include "tpm2_session.h"

#include <cstddef>
#include <cstdint>

using namespace hkdfguard;
using namespace hkdfguard::tpm2;

namespace {
    constexpr uint32_t kSessionHandle = 0x02000000;
    constexpr uint32_t kKeyHandle = 0x80000001;

    // The HMAC the TPM would put on `r`'s first authorization.
    Bytes SignResponse(const Bytes &session_key, const Response &r, const Bytes &nonce_caller) {
        Bytes rp_input = {0, 0, 0, 0}; // responseCode: success
        rp_input.insert(rp_input.end(), {0x00, 0x00, 0x01, 0x55}); // TPM_CC_HMAC
        rp_input.insert(rp_input.end(), r.parameters.begin(), r.parameters.end());
        uint8_t rp_hash[kSha256Len];
        Sha256(rp_input.data(), rp_input.size(), rp_hash);
        Bytes input(rp_hash, rp_hash + kSha256Len);
        input.insert(input.end(), r.auths[0].nonce.begin(), r.auths[0].nonce.end());
        input.insert(input.end(), nonce_caller.begin(), nonce_caller.end());
        input.push_back(r.auths[0].attributes);
        Bytes hmac(kSha256Len);
        HmacSha256(session_key.data(), session_key.size(), input.data(), input.size(), hmac.data());
        return hmac;
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    const bool sign = (data[0] & 1) != 0;
    const bool ask_continue = (data[0] & 2) != 0;
    const uint8_t *body = data + 1;
    const size_t body_size = size - 1;

    try {
        SecureBuffer<kSha256Len> salt;
        const Bytes initial(kNonceLen, 0x01);
        Bytes session_key(kSha256Len);
        KdfaSha256(salt.data(), salt.size(), "ATH", initial, initial, session_key.data(), session_key.size());

        Session session(kSessionHandle, salt, initial, initial);
        const Bytes command =
            session.Authorize(kCcHmac, {kKeyHandle}, {Bytes(34, 0x00)}, HmacParameters(Bytes(4, 0x09), kAlgSha256),
                              ask_continue);
        // nonceCaller: after the header, the handle, authorizationSize, the
        // session handle and the nonce's size.
        const Bytes nonce_caller(command.begin() + 24, command.begin() + 24 + kNonceLen);

        Response response;
        try {
            response = ParseResponse(body, body_size, 0, 1);
        } catch (const HkdfGuardError &) {
            session.Abandon();
            FUZZ_REQUIRE(!session.usable(), "an abandoned session authorizes nothing more");
            return 0;
        }
        if (sign && response.response_code == 0 && response.auths.size() == 1) {
            response.auths[0].hmac = SignResponse(session_key, response, nonce_caller);
        }

        bool verified = false;
        try {
            session.Verify(response);
            verified = response.response_code == 0;
        } catch (const HkdfGuardError &) {
            FUZZ_REQUIRE(!session.usable(), "a refused response leaves the session unusable");
            FUZZ_REQUIRE(session.open(), "a refused response leaves the session for its owner to flush");
            return 0;
        }
        if (response.response_code != 0) {
            FUZZ_REQUIRE(!session.usable(), "an error response leaves the session unusable");
            return 0;
        }
        FUZZ_REQUIRE(sign, "an unsigned success response never verifies");
        FUZZ_REQUIRE(verified && session.usable(), "a verified response leaves the session usable");
        FUZZ_REQUIRE(session.open() == ((response.auths[0].attributes & kSessionContinue) != 0),
                     "after a verified response, open() is the TPM's continueSession bit");

        Bytes encrypted;
        try {
            encrypted = ParseHmac(response);
        } catch (const HkdfGuardError &) {
            return 0;
        }
        if (encrypted.size() == kSha256Len) {
            SecureBuffer<kSha256Len> out;
            session.DecryptResponseParameter(encrypted, out.data(), out.size());
        }
    } catch (const HkdfGuardError &) {
    } catch (...) {
        FUZZ_REQUIRE(false, "the session code throws only HkdfGuardError");
    }
    return 0;
}
