#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <vector> // std::vector (BuildWrappedDekAuthenticated's result)

namespace hkdfguard {
    // WrappedDekV1 layout (all integers little-endian; total 132 bytes,
    // identical regardless of which KEK provider produced it):
    //
    //   offset  size  field
    //   0       1     Version            (= kFormatVersion1)
    //   1       1     ProviderType       (1 = Platform Crypto Provider, 2 = Software KSP)
    //   2       2     Reserved           (must be 0; rejected otherwise)
    //   4       4     KeyId              (little-endian; = 1 for this format version)
    //   8       32    Salt               (random per payload; see below)
    //   40      12    Nonce              (AES-GCM IV)
    //   52      32    Ciphertext         (AES-256-GCM ciphertext of the 32-byte DEK)
    //   84      16    Tag                (AES-GCM authentication tag)
    //   100     32    KekFingerprint     (SHA-256 of the KEK's public key, raw X || Y)
    //
    // The wrapping key is Z = ECDH(KEK private key, H(Salt)), where H hashes
    // the salt to a P-256 point (hash_to_curve.h). Nobody knows the discrete
    // log of H(Salt), so computing Z needs the KEK's *private* key: only an
    // account authorized to use the KEK can create a payload, and knowing
    // the KEK's public key is not enough to forge one. The salt is also
    // HKDF's salt, and is otherwise unstructured - any 32 bytes are a
    // well-formed salt.
    //
    // The payload's *authenticated bytes* are header || KekFingerprint (see
    // BuildWrappedDekAuthenticated) - every byte except the Nonce,
    // Ciphertext and Tag - and they are used twice: as the AES-GCM AAD, and
    // inside HKDF's info, after the normalized
    // service name (see ecdh_hkdf.h). So every field is bound into the
    // wrapping key itself, not only checked by the tag. The header is bytes
    // 0..39 - Version, ProviderType, Reserved, KeyId and Salt - so every
    // field a parser reads or routes on is authenticated: a payload whose
    // version, provider type or KeyId was rewritten fails even when the
    // rewritten value would itself parse, so a future format version cannot
    // relabel a payload as this one. The service name is bound through the key (HKDF info), not the
    // AAD: unwrapped under the wrong service, the key is wrong and the tag
    // fails. The Nonce is not authenticated bytes: AesGcmEncrypt generates
    // it, so it does not exist yet when they are fixed, and GCM
    // authenticates it inherently (a different nonce changes both the
    // keystream and the tag). The Ciphertext and Tag are what everything
    // else is authenticated *with*.
    //
    // KekFingerprint identifies which KEK produced the payload. It is both
    // (a) authenticated - it is part of the authenticated bytes, alongside
    // the header - and (b) checked explicitly on unwrap, before any ECDH
    // or decryption: the KEK selected by (service, ProviderType, KeyId) is
    // opened, its public key fingerprinted the same way, and a mismatch is
    // rejected as HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH. That turns "wrong key" into a
    // precise, cheap failure (no TPM operation spent on it) instead of an
    // authentication failure indistinguishable from tampering. It is a
    // check, never a lookup: key selection is always by the routing fields,
    // and the fingerprint is compared against the result - searching keys
    // for a matching fingerprint would let an attacker-controlled field
    // steer key selection.
    //
    // The input hashed is the raw 64-byte X || Y, with no 0x04 prefix. Other
    // platforms hash the SEC1 encoding (0x04 || X || Y), so a fingerprint is
    // only meaningful on the platform that produced it; payloads are only
    // opened on the host that wrapped them.
    //
    // Serialized field-by-field rather than via a packed C struct, so the
    // wire format has no dependency on compiler struct-packing rules.

    constexpr uint8_t kFormatVersion1 = 1;

    // The only KeyId value this format version ever produces or accepts.
    // HkdfGuard has no key-rotation mechanism by design: a KEK is meant to
    // be long-lived, and a new KEK is obtained by versioning the *service
    // name* (e.g. "myapp.v2" gets its own, independent KEK), not by rotating
    // KeyId. ParseWrappedDek therefore rejects any other KeyId as malformed
    // rather than letting kek_store.cpp's KeyName look for a persisted key
    // that cannot exist.
    constexpr uint32_t kCurrentKeyId = 1;

    constexpr uint8_t kProviderTypeTpm = 1; // Microsoft Platform Crypto Provider
    constexpr uint8_t kProviderTypeSoftware = 2; // Microsoft Software Key Storage Provider

    constexpr size_t kSaltLen = 32;
    // A raw P-256 public point, X || Y - the KEK's public key and H(Salt).
    // Not part of the payload.
    constexpr size_t kPublicPointLen = 64;
    constexpr size_t kNonceLen = 12;
    constexpr size_t kCiphertextLen = 32; // == HKDFGUARD_DEK_LEN
    constexpr size_t kTagLen = 16;
    constexpr size_t kFingerprintLen = 32; // SHA-256 output

    // Byte offsets of each field within the 132-byte payload.
    constexpr size_t kVersionOffset = 0;
    constexpr size_t kProviderTypeOffset = 1;
    constexpr size_t kReservedOffset = 2;
    constexpr size_t kKeyIdOffset = 4;
    constexpr size_t kSaltOffset = 8;
    constexpr size_t kNonceOffset = kSaltOffset + kSaltLen; // 40
    constexpr size_t kCiphertextOffset = kNonceOffset + kNonceLen; // 52
    constexpr size_t kTagOffset = kCiphertextOffset + kCiphertextLen; // 84
    constexpr size_t kFingerprintOffset = kTagOffset + kTagLen; // 100
    constexpr size_t kTotalLen = kFingerprintOffset + kFingerprintLen; // 132

    // The authenticated header: every byte before the Nonce (Version through
    // Salt). It is a prefix of the payload, so on unwrap the AAD is built
    // from the received bytes themselves, never from a re-serialization of
    // what was parsed out of them.
    constexpr size_t kHeaderLen = kNonceOffset; // 40

    // header || KekFingerprint: the AES-GCM AAD, and the tail of HKDF's info.
    constexpr size_t kAuthenticatedLen = kHeaderLen + kFingerprintLen; // 72

    // The parsed-out fields of a wrapped payload, returned by
    // ParseWrappedDek. Nothing here is secret (metadata, the salt, and the
    // ciphertext/tag), so no wiping is needed.
    //
    // The pointer fields do not own memory: they point into the caller's
    // `wrapped` buffer and are valid only as long as it is.
    struct ParsedWrappedDek {
        uint8_t provider_type;
        uint32_t key_id;
        const uint8_t *header; // kHeaderLen bytes, as received - the AAD's first part
        const uint8_t *salt; // kSaltLen bytes
        const uint8_t *nonce; // kNonceLen bytes
        const uint8_t *ciphertext; // kCiphertextLen bytes
        const uint8_t *tag; // kTagLen bytes
        const uint8_t *fingerprint; // kFingerprintLen bytes
    };

    // Writes a kTotalLen-byte WrappedDekV1 payload into out. Array-parameter
    // sizes document the expected byte counts; they are not enforced.
    void SerializeWrappedDek(
        uint8_t provider_type,
        uint32_t key_id,
        const uint8_t salt[kSaltLen],
        const uint8_t nonce[kNonceLen],
        const uint8_t ciphertext[kCiphertextLen],
        const uint8_t tag[kTagLen],
        const uint8_t fingerprint[kFingerprintLen],
        uint8_t out[kTotalLen]);

    // Writes just the kHeaderLen-byte header (Version through Salt) into
    // out - exactly the first kHeaderLen bytes SerializeWrappedDek writes,
    // since that function writes its header through this one. Wrap needs the
    // header before the payload exists, to build the AAD it encrypts under.
    void SerializeWrappedDekHeader(
        uint8_t provider_type,
        uint32_t key_id,
        const uint8_t salt[kSaltLen],
        uint8_t out[kHeaderLen]);

    // The payload's authenticated bytes: header || fingerprint
    // (kAuthenticatedLen bytes; see the layout comment above). Used as the
    // AES-GCM AAD and passed to DeriveWrappingKey for HKDF's info. Wrap
    // passes the header it is about to serialize; unwrap passes
    // ParsedWrappedDek::header, the received bytes. None of it is secret.
    std::vector<uint8_t> BuildWrappedDekAuthenticated(
        const uint8_t header[kHeaderLen],
        const uint8_t fingerprint[kFingerprintLen]);

    // Validates and parses a wrapped payload. Throws HkdfGuardError with
    // HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED if the version is not recognized,
    // and with HKDFGUARD_ERR_PAYLOAD_MALFORMED if wrapped_len != kTotalLen,
    // the reserved bytes are not zero, the provider type is not
    // recognized, or KeyId is not kCurrentKeyId (see that constant). The
    // fingerprint is *not* checked here - that needs the KEK opened, which
    // is hkdfguard.cpp's job.
    ParsedWrappedDek ParseWrappedDek(const uint8_t *wrapped, int32_t wrapped_len);
} // namespace hkdfguard
