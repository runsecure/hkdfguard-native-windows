#include "wire_format.h"
#include "errors.h"
// <cstring> declares memcpy, used repeatedly below to copy fixed-size
// blocks of bytes (this is the C++ header for C's <string.h>; despite the
// name it has nothing to do with std::string).
#include <cstring>

namespace hkdfguard {
    // Builds the 164-byte wire payload by writing each field at its known
    // offset. Every field here is public information (metadata, a public
    // ephemeral key, ciphertext, and an auth tag) - nothing in this function
    // handles a secret, so there's no zeroing concern in this file.
    void SerializeWrappedDek(
        uint8_t provider_type,
        uint32_t key_id,
        const uint8_t ephemeral_pub[kEphemeralPubLen],
        const uint8_t nonce[kNonceLen],
        const uint8_t ciphertext[kCiphertextLen],
        const uint8_t tag[kTagLen],
        const uint8_t fingerprint[kFingerprintLen],
        uint8_t out[kTotalLen]) {
        // Single-byte fields: just assign directly at their offset.
        out[kVersionOffset] = kFormatVersion1;
        out[kProviderTypeOffset] = provider_type;
        // The 2 reserved bytes are explicitly zeroed (rather than left
        // whatever the caller's buffer happened to contain) so the format is
        // fully deterministic and future format versions have well-defined
        // "was this ever set" bytes to check.
        out[kReservedOffset] = 0;
        out[kReservedOffset + 1] = 0;

        // KeyId is written out one byte at a time, least-significant byte
        // first, i.e. little-endian - matching the format documented in
        // wire_format.h. `key_id & 0xFF` masks off everything but the lowest 8
        // bits; `(key_id >> 8) & 0xFF` shifts the next byte down into that same
        // low position before masking it out, and so on. Doing it manually like
        // this (instead of e.g. reinterpret-casting a uint32_t* over the bytes)
        // means the on-disk/on-the-wire format is identical no matter what CPU
        // architecture compiled this code, since some CPUs are natively
        // little-endian and others are big-endian.
        out[kKeyIdOffset + 0] = static_cast<uint8_t>(key_id & 0xFF);
        out[kKeyIdOffset + 1] = static_cast<uint8_t>((key_id >> 8) & 0xFF);
        out[kKeyIdOffset + 2] = static_cast<uint8_t>((key_id >> 16) & 0xFF);
        out[kKeyIdOffset + 3] = static_cast<uint8_t>((key_id >> 24) & 0xFF);

        // The remaining fields are already raw byte arrays of the right length,
        // so they're just block-copied into place: destination pointer
        // (`out + <offset>`, i.e. pointer arithmetic - "the address `offset`
        // bytes past the start of `out`"), source pointer, and byte count.
        memcpy(out + kEphemeralPubOffset, ephemeral_pub, kEphemeralPubLen);
        memcpy(out + kNonceOffset, nonce, kNonceLen);
        memcpy(out + kCiphertextOffset, ciphertext, kCiphertextLen);
        memcpy(out + kTagOffset, tag, kTagLen);
        memcpy(out + kFingerprintOffset, fingerprint, kFingerprintLen);
    }

    // Validates a caller-supplied buffer really is a well-formed WrappedDekV1
    // payload, then returns a ParsedWrappedDek whose pointer fields alias into
    // that same buffer (see wire_format.h's comment on ParsedWrappedDek).
    ParsedWrappedDek ParseWrappedDek(const uint8_t *wrapped, int32_t wrapped_len) {
        // Three checks combined with `||` (logical OR - true if *any* one of
        // them is true): null pointer, negative length (which would make the
        // cast below wrap around to a huge unsigned value and defeat the length
        // check entirely if we didn't catch it first), or a length that simply
        // isn't exactly kTotalLen. `static_cast<size_t>(wrapped_len)` performs
        // an explicit, intentional type conversion from the signed int32_t to
        // the unsigned size_t that kTotalLen is - "static_cast" is C++'s
        // compiler-checked replacement for a C-style `(size_t)wrapped_len` cast.
        if (wrapped == nullptr || wrapped_len < 0 ||
            static_cast<size_t>(wrapped_len) != kTotalLen) {
            // `throw` raises a C++ exception, immediately unwinding the call
            // stack (running destructors along the way) until something
            // catches it - here, that's the `try`/`catch` in hkdfguard.cpp's
            // hkdfguard_unwrap_dek. See errors.h for the full explanation of
            // why this codebase uses exceptions internally.
            throw HkdfGuardError(HKDFGUARD_ERR_MALFORMED, "wrapped payload has wrong length");
        }

        // Reject anything other than the one version this build understands.
        if (wrapped[kVersionOffset] != kFormatVersion1) {
            throw HkdfGuardError(HKDFGUARD_ERR_MALFORMED, "unrecognized wrapped payload version");
        }

        // The reserved bytes must be exactly what SerializeWrappedDek wrote.
        // They carry no meaning today, but leaving them unchecked would mean
        // any future meaning assigned to them could be flipped undetected in
        // an existing payload - so they're pinned to zero now, while nothing
        // depends on them.
        if (wrapped[kReservedOffset] != 0 || wrapped[kReservedOffset + 1] != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_MALFORMED, "reserved bytes must be zero");
        }

        uint8_t provider_type = wrapped[kProviderTypeOffset];
        if (provider_type != kProviderTypeTpm && provider_type != kProviderTypeSoftware) {
            throw HkdfGuardError(HKDFGUARD_ERR_MALFORMED, "unrecognized provider type");
        }

        // Reassemble the little-endian KeyId bytes back into a uint32_t - the
        // exact mirror image of the encoding in SerializeWrappedDek above.
        // Each byte is first widened to uint32_t (via static_cast) *before*
        // being shifted, because shifting a uint8_t left by 24 bits would
        // overflow that 8-bit type; widening first ensures the shift happens in
        // 32-bit arithmetic. The `|` (bitwise OR) then combines the four
        // shifted bytes, each occupying its own non-overlapping 8-bit lane,
        // into one complete 32-bit value.
        uint32_t key_id =
                static_cast<uint32_t>(wrapped[kKeyIdOffset + 0]) |
                (static_cast<uint32_t>(wrapped[kKeyIdOffset + 1]) << 8) |
                (static_cast<uint32_t>(wrapped[kKeyIdOffset + 2]) << 16) |
                (static_cast<uint32_t>(wrapped[kKeyIdOffset + 3]) << 24);

        // See kCurrentKeyId's comment: this format version has no rotation
        // mechanism, so exactly one KeyId value is ever legitimate. Rejecting
        // anything else here - rather than letting it flow through to
        // kek_store.cpp's KeyName, which would just build a persisted-key
        // name for a key that, by design, was never created - turns a
        // payload with a tampered or simply wrong KeyId into an immediate,
        // precise HKDFGUARD_ERR_MALFORMED instead of a less specific
        // "provider/key open failed" further down the call chain.
        if (key_id != kCurrentKeyId) {
            throw HkdfGuardError(HKDFGUARD_ERR_MALFORMED, "unrecognized key id");
        }

        // `ParsedWrappedDek parsed{};` default-constructs the struct with every
        // member zero-initialized (the `{}` is "empty brace-init"), then each
        // field is filled in explicitly below. The four pointer fields are set
        // to `wrapped + <offset>` - pointer arithmetic again, computing the
        // address of each field *inside* the caller's original buffer, rather
        // than copying those bytes anywhere new.
        ParsedWrappedDek parsed{};
        parsed.provider_type = provider_type;
        parsed.key_id = key_id;
        parsed.ephemeral_pub = wrapped + kEphemeralPubOffset;
        parsed.nonce = wrapped + kNonceOffset;
        parsed.ciphertext = wrapped + kCiphertextOffset;
        parsed.tag = wrapped + kTagOffset;
        parsed.fingerprint = wrapped + kFingerprintOffset;
        // Returned by value - see the "returning by value" note on this
        // function's declaration in wire_format.h.
        return parsed;
    }
} // namespace hkdfguard
