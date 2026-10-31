#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// The version 2 key derivation (docs/adr/0001-post-quantum-payload-version-2.md,
// section 2): NIST SP 800-108 in counter mode, with HMAC-SHA-256 keyed by
// the KEK as the PRF. The provider computes it (kek_v2.h): the TPM's HMAC
// over a block built here, or the Software KSP's own SP 800-108 KDF, which
// builds the same block from the label and context. This file only builds
// the inputs:
//
//   block(i)    = [i]_32 || Label || 0x00 || Context || [256]_32
//   K_wrap      = HMAC-SHA-256(KEK, block(1))
//   Context     = u16_le(len(service)) || service || header
//   fingerprint = the same, with the fingerprint label and an empty Context
//
// One block is the whole 256-bit output, so only counter 1 is ever used.
//
// Integers in the block are big-endian, as SP 800-108 specifies; the service
// length is little-endian, framing the variable-length name. Labels,
// framing and order are byte for byte the Linux library's
// (hkdfguard-native-linux, src/crypto.rs), so its known-answer values pin
// this one too; "-v1" in the labels names that construction, not the
// Windows payload version. Nothing here is secret.
namespace hkdfguard {
    constexpr char kWrapLabel[] = "hkdfguard-wrap-v1";
    constexpr char kFingerprintLabel[] = "hkdfguard-kek-fingerprint-v1";
    constexpr uint32_t kKdfOutputBits = 256; // [L]_32: every output is 32 bytes

    // One SP 800-108 counter-mode block for `label` and `context`.
    std::vector<uint8_t> Sp800108Block(uint32_t counter, const char *label, const uint8_t *context, size_t context_len);

    // The fingerprint's block: the fingerprint label, an empty Context.
    std::vector<uint8_t> FingerprintBlock(uint32_t counter);

    // A payload's wrapping-key context: u16_le(len(service)) || service ||
    // header. `service` is the normalized service name (at most 128 bytes);
    // `header` the payload's header bytes. Throws
    // HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR) for an empty name.
    std::vector<uint8_t> WrapContext(const std::string &service, const uint8_t *header, size_t header_len);

    // A payload's wrapping-key block: the wrap label and WrapContext.
    std::vector<uint8_t> WrapBlock(uint32_t counter, const std::string &service, const uint8_t *header, size_t header_len);
} // namespace hkdfguard
