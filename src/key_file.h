#pragma once

#include <cstdint>
#include <string>

namespace hkdfguard {
    // Reads exactly kTotalLen (164) bytes of the wrapped-key file at `path`
    // (null-terminated UTF-8) into `out`, after refusing any path that is a
    // link or passes through one, uses an 8.3 short name, or is not on a
    // local drive, and refusing any file whose size isn't exactly a wrapped
    // payload - then validates those bytes as hkdfguard_unwrap_dek would
    // before touching a KEK. Nothing is decrypted and no KEK is opened. See
    // hkdfguard_open_file in hkdfguard.h for the full contract and codes.
    // Throws HkdfGuardError on every failure; the caller zeroes `out`.
    void ReadWrappedKeyFile(const char *path, uint8_t *out);

    // `path` (null-terminated UTF-8) converted to UTF-16, exactly as
    // ReadWrappedKeyFile converts it. Throws HkdfGuardError
    // (HKDFGUARD_ERR_INVALID_ARG) if it is empty, too long or not valid
    // UTF-8. Used to name the file in the plaintext-key audit event.
    std::wstring KeyFilePathToWide(const char *path);
} // namespace hkdfguard
