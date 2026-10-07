#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t

namespace hkdfguard {
    // WrappedDekV1 layout (all integers little-endian; total 164 bytes,
    // identical regardless of which KEK provider produced it):
    //
    //   offset  size  field
    //   0       1     Version            (= kFormatVersion1)
    //   1       1     ProviderType       (1 = Platform Crypto Provider, 2 = Software KSP)
    //   2       2     Reserved           (must be 0; rejected otherwise)
    //   4       4     KeyId              (little-endian; = 1 for this format version)
    //   8       64    EphemeralPublicKey (raw P-256 point, X || Y)
    //   72      12    Nonce              (AES-GCM IV)
    //   84      32    Ciphertext         (AES-256-GCM ciphertext of the 32-byte DEK)
    //   116     16    Tag                (AES-GCM authentication tag)
    //   132     32    KekFingerprint     (SHA-256 of the KEK's public key, raw X || Y)
    //
    // KekFingerprint identifies which KEK produced the payload. It is both
    // (a) authenticated - it is part of the AES-GCM AAD, alongside the
    // service name - and (b) checked explicitly on unwrap, before any ECDH
    // or decryption: the KEK selected by (service, ProviderType, KeyId) is
    // opened, its public key fingerprinted the same way, and a mismatch is
    // rejected as HKDFGUARD_ERR_KEK_MISMATCH. That turns "wrong key" into a
    // precise, cheap failure (no TPM operation spent on it) instead of an
    // authentication failure indistinguishable from tampering. It is a
    // check, never a lookup: key selection is always by the routing fields,
    // and the fingerprint is compared against the result - searching keys
    // for a matching fingerprint would let an attacker-controlled field
    // steer key selection.
    //
    // The input hashed is the raw 64-byte X || Y - the same bytes this
    // project's macOS implementation hashes (CryptoKit's rawRepresentation),
    // so the two produce identical fingerprints for identical keys, though
    // cross-platform payload parity is not otherwise a goal.
    //
    // Deliberately serialized field-by-field rather than via a packed C struct,
    // so the wire format has no dependency on compiler struct-packing rules.

    // `constexpr` (as opposed to plain `const`) tells the compiler this value
    // must be computable at compile time, not just "never reassigned at
    // runtime." That matters here because these constants are used as array
    // sizes and template arguments below (e.g. `SecureBuffer<kSharedSecretLen>`
    // elsewhere in the project) - positions where the language requires a
    // compile-time constant, not merely a read-only variable.
    //
    // Compared to hkdfguard.h's `#define` macros, `constexpr` values are real,
    // typed C++ constants: the compiler checks their type (uint8_t vs size_t
    // here) and they show up as named symbols in a debugger, whereas a `#define`
    // is just blind text substitution performed before the compiler even sees
    // the code. Internal-only code in src/ uses constexpr for this reason; the
    // public hkdfguard.h uses #define instead specifically because plain C (and
    // the non-C++ language bindings the ABI targets) has no constexpr at all.
    constexpr uint8_t kFormatVersion1 = 1;

    // The only KeyId value this format version ever produces or accepts.
    // HkdfGuard has no key-rotation mechanism by design: a KEK is meant to
    // be long-lived, and the DEKs it protects are re-minted on every
    // release under the same service name; if a genuinely new KEK is ever
    // wanted, that is done by versioning the *service name* (e.g.
    // "myapp.v2" gets its own, independent KEK), not by rotating KeyId
    // under a fixed service name. ParseWrappedDek below therefore rejects
    // any other KeyId as malformed, rather than accepting an arbitrary
    // uint32_t from the payload and letting kek_store.cpp's KeyName go
    // looking for a persisted key that was never meant to exist.
    constexpr uint32_t kCurrentKeyId = 1;

    constexpr uint8_t kProviderTypeTpm = 1; // Microsoft Platform Crypto Provider
    constexpr uint8_t kProviderTypeSoftware = 2; // Microsoft Software Key Storage Provider

    constexpr size_t kEphemeralPubLen = 64;
    constexpr size_t kNonceLen = 12;
    constexpr size_t kCiphertextLen = 32; // == HKDFGUARD_DEK_LEN
    constexpr size_t kTagLen = 16;
    constexpr size_t kFingerprintLen = 32; // SHA-256 output

    // Byte offsets of each field within the 164-byte payload. Each one is
    // defined in terms of the previous field's offset and length, so if a field
    // length above ever changed, every later offset would automatically recompute
    // correctly at compile time rather than needing to be hand-edited.
    constexpr size_t kVersionOffset = 0;
    constexpr size_t kProviderTypeOffset = 1;
    constexpr size_t kReservedOffset = 2;
    constexpr size_t kKeyIdOffset = 4;
    constexpr size_t kEphemeralPubOffset = 8;
    constexpr size_t kNonceOffset = kEphemeralPubOffset + kEphemeralPubLen; // 72
    constexpr size_t kCiphertextOffset = kNonceOffset + kNonceLen; // 84
    constexpr size_t kTagOffset = kCiphertextOffset + kCiphertextLen; // 116
    constexpr size_t kFingerprintOffset = kTagOffset + kTagLen; // 132
    constexpr size_t kTotalLen = kFingerprintOffset + kFingerprintLen; // 164

    // A plain C++ `struct` (equivalent to a `class` whose members default to
    // `public`) used purely to bundle the parsed-out pieces of a wrapped
    // payload for easy return from ParseWrappedDek below. None of these fields
    // are secret (they're either public metadata, a public ephemeral key, or
    // AES-GCM ciphertext/tag bytes that are meant to be stored/transmitted), so
    // unlike SecureBuffer there's no zero-on-destruction behavior needed here.
    //
    // The four pointer fields don't own their own memory - they simply point
    // into the middle of the caller's original `wrapped` byte buffer (see
    // ParseWrappedDek's implementation in wire_format.cpp, which sets each one
    // to `wrapped + <offset>`). That's why the comment below warns they're only
    // valid as long as the original buffer is; if the caller's `wrapped` array
    // were destroyed or reused while a ParsedWrappedDek pointing into it was
    // still alive, those pointers would dangle.
    struct ParsedWrappedDek {
        uint8_t provider_type;
        uint32_t key_id;
        const uint8_t *ephemeral_pub; // kEphemeralPubLen bytes
        const uint8_t *nonce; // kNonceLen bytes
        const uint8_t *ciphertext; // kCiphertextLen bytes
        const uint8_t *tag; // kTagLen bytes
        const uint8_t *fingerprint; // kFingerprintLen bytes
    };

    // Only the function *declarations* (signatures) live in this header; their
    // bodies are in wire_format.cpp. This is the ordinary C/C++ header/source
    // split: any .cpp file that #includes this header knows enough (the name,
    // parameter types, and return type) to *call* these functions, even though
    // the compiler compiles wire_format.cpp separately and the linker stitches
    // the two together afterward.
    //
    // Writes a kTotalLen-byte WrappedDekV1 payload into out. The parameter
    // types like `const uint8_t ephemeral_pub[kEphemeralPubLen]` are a bit of
    // C/C++ notation worth knowing: as a *function parameter*, an array type
    // always silently decays to a plain pointer (`const uint8_t*`) - the
    // `[kEphemeralPubLen]` here is purely documentation for a human reader of
    // exactly how many bytes the function expects to find at that pointer; the
    // compiler does not actually check the caller passed an array of that
    // length.
    void SerializeWrappedDek(
        uint8_t provider_type,
        uint32_t key_id,
        const uint8_t ephemeral_pub[kEphemeralPubLen],
        const uint8_t nonce[kNonceLen],
        const uint8_t ciphertext[kCiphertextLen],
        const uint8_t tag[kTagLen],
        const uint8_t fingerprint[kFingerprintLen],
        uint8_t out[kTotalLen]);

    // Validates and parses a wrapped payload. Throws HkdfGuardError with
    // HKDFGUARD_ERR_MALFORMED if wrapped_len != kTotalLen, the version is not
    // recognized, the reserved bytes are not zero, the provider type is not
    // recognized, or KeyId is not kCurrentKeyId - see that constant's
    // comment for why a payload naming any other KeyId is rejected outright
    // rather than passed through to look up a key that, by design, could
    // never legitimately exist. (The fingerprint is *not* checked here -
    // that needs the KEK opened, which is hkdfguard.cpp's job.) Returning a
    // ParsedWrappedDek *by value* (rather than through an out-parameter) is
    // idiomatic modern C++: the compiler builds the struct directly in the
    // caller's variable (no separate temporary gets copied), and if parsing
    // fails, throwing an exception instead of returning a special "invalid"
    // value means the caller can never accidentally forget to check for
    // failure and use a garbage result.
    ParsedWrappedDek ParseWrappedDek(const uint8_t *wrapped, int32_t wrapped_len);
} // namespace hkdfguard
