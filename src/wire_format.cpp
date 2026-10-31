#include "wire_format.h"
#include "errors.h"
#include <cstring> // memcpy

namespace hkdfguard {
    // Writes the authenticated header - Version through Salt - at the
    // fields' offsets. Nothing in this file handles a secret, so nothing
    // here is wiped.
    void SerializeWrappedDekHeader(
        uint8_t version,
        uint8_t provider_type,
        uint32_t key_id,
        const uint8_t salt[kSaltLen],
        uint8_t out[kHeaderLen]) {
        out[kVersionOffset] = version;
        out[kProviderTypeOffset] = provider_type;
        // Reserved bytes are written as zero so the format is deterministic
        // and ParseWrappedDek can require zero.
        out[kReservedOffset] = 0;
        out[kReservedOffset + 1] = 0;

        // KeyId, little-endian, byte by byte so the encoding does not depend
        // on the host's endianness.
        out[kKeyIdOffset + 0] = static_cast<uint8_t>(key_id & 0xFF);
        out[kKeyIdOffset + 1] = static_cast<uint8_t>((key_id >> 8) & 0xFF);
        out[kKeyIdOffset + 2] = static_cast<uint8_t>((key_id >> 16) & 0xFF);
        out[kKeyIdOffset + 3] = static_cast<uint8_t>((key_id >> 24) & 0xFF);

        memcpy(out + kSaltOffset, salt, kSaltLen);
    }

    // Builds the 132-byte wire payload: the header first, through the same
    // function wrap used to build its AAD, so the bytes authenticated and the
    // bytes stored cannot drift apart; then the remaining fields at their
    // offsets.
    void SerializeWrappedDek(
        uint8_t version,
        uint8_t provider_type,
        uint32_t key_id,
        const uint8_t salt[kSaltLen],
        const uint8_t nonce[kNonceLen],
        const uint8_t ciphertext[kCiphertextLen],
        const uint8_t tag[kTagLen],
        const uint8_t fingerprint[kFingerprintLen],
        uint8_t out[kTotalLen]) {
        SerializeWrappedDekHeader(version, provider_type, key_id, salt, out);
        memcpy(out + kNonceOffset, nonce, kNonceLen);
        memcpy(out + kCiphertextOffset, ciphertext, kCiphertextLen);
        memcpy(out + kTagOffset, tag, kTagLen);
        memcpy(out + kFingerprintOffset, fingerprint, kFingerprintLen);
    }

    // header || fingerprint: both fixed-length, so the encoding is
    // unambiguous as it stands.
    std::vector<uint8_t> BuildWrappedDekAuthenticated(
        const uint8_t header[kHeaderLen],
        const uint8_t fingerprint[kFingerprintLen]) {
        std::vector<uint8_t> authenticated;
        authenticated.reserve(kAuthenticatedLen);
        authenticated.insert(authenticated.end(), header, header + kHeaderLen);
        authenticated.insert(authenticated.end(), fingerprint, fingerprint + kFingerprintLen);
        return authenticated;
    }

    // Validates a caller-supplied buffer really is a well-formed payload of
    // either version, then returns a ParsedWrappedDek whose pointer fields alias into
    // that same buffer (see wire_format.h's comment on ParsedWrappedDek).
    ParsedWrappedDek ParseWrappedDek(const uint8_t *wrapped, int32_t wrapped_len) {
        // The negative check comes first so the cast to size_t cannot wrap.
        if (wrapped == nullptr || wrapped_len < 0 ||
            static_cast<size_t>(wrapped_len) != kTotalLen) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_MALFORMED, "wrapped payload has wrong length");
        }

        // Reject anything other than the two versions this build
        // understands. A different version byte may be a newer format rather
        // than a broken payload, so it gets its own code,
        // HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED, distinct from the structural
        // HKDFGUARD_ERR_PAYLOAD_MALFORMED failures around it.
        const uint8_t version = wrapped[kVersionOffset];
        if (version != kFormatVersion1 && version != kFormatVersion2) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED, "unrecognized wrapped payload version");
        }

        // The reserved bytes carry no meaning, and are required to be zero
        // so that any meaning later assigned to them cannot be flipped
        // undetected in an existing payload.
        if (wrapped[kReservedOffset] != 0 || wrapped[kReservedOffset + 1] != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_MALFORMED, "reserved bytes must be zero");
        }

        uint8_t provider_type = wrapped[kProviderTypeOffset];
        if (provider_type != kProviderTypeTpm && provider_type != kProviderTypeSoftware) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unrecognized provider type");
        }

        // Little-endian KeyId, the mirror of SerializeWrappedDekHeader.
        uint32_t key_id =
                static_cast<uint32_t>(wrapped[kKeyIdOffset + 0]) |
                (static_cast<uint32_t>(wrapped[kKeyIdOffset + 1]) << 8) |
                (static_cast<uint32_t>(wrapped[kKeyIdOffset + 2]) << 16) |
                (static_cast<uint32_t>(wrapped[kKeyIdOffset + 3]) << 24);

        // Exactly one KeyId is legitimate (see kCurrentKeyId). Rejecting any
        // other here gives a precise HKDFGUARD_ERR_PAYLOAD_MALFORMED instead
        // of a less specific key-open failure in kek_store.cpp.
        if (key_id != kCurrentKeyId) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unrecognized key id");
        }

        // The pointer fields alias the caller's buffer; nothing is copied.
        ParsedWrappedDek parsed{};
        parsed.version = version;
        parsed.provider_type = provider_type;
        parsed.key_id = key_id;
        parsed.header = wrapped; // the header is the payload's first kHeaderLen bytes
        parsed.salt = wrapped + kSaltOffset;
        parsed.nonce = wrapped + kNonceOffset;
        parsed.ciphertext = wrapped + kCiphertextOffset;
        parsed.tag = wrapped + kTagOffset;
        parsed.fingerprint = wrapped + kFingerprintOffset;
        return parsed;
    }
} // namespace hkdfguard
