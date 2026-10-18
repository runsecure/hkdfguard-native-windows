#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace hkdfguard {
    // Reads exactly kTotalLen (132) bytes of the wrapped-key file at `path`
    // (null-terminated UTF-8) into `out`, after refusing any path that is a
    // link or passes through one, uses an 8.3 short name, or is not on a
    // local drive, any file that it or a folder above it lets an untrusted
    // account write or replace, and any file whose size isn't exactly a
    // wrapped payload - then validates those bytes as hkdfguard_unwrap_dek
    // would before touching a KEK. Nothing is decrypted and no KEK is
    // opened. See hkdfguard_open_file in hkdfguard.h for the full contract
    // and codes. Throws HkdfGuardError on every failure; the caller zeroes
    // `out`.
    void ReadWrappedKeyFile(const char *path, uint8_t *out);

    // The owner and DACL test ReadWrappedKeyFile applies to the key file
    // (`is_folder` false) or to each folder above it (true), on a given
    // security descriptor instead of a live object - so tests can try
    // owners and ACEs that would need privileges to set on a real file.
    // Throws HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED) on refusal.
    void CheckKeyFileSecurity(PSECURITY_DESCRIPTOR sd, bool is_folder);

    // Whether `len` bytes would be refused as HKDFGUARD_ERR_FILE_PLAINTEXT_KEY
    // by content: 32 raw bytes, or a DEK as hex or base64 with surrounding
    // whitespace. Exposed for tests.
    bool LooksLikePlaintextKeyForTest(const uint8_t *bytes, size_t len);

    // `path` (null-terminated UTF-8) converted to UTF-16, exactly as
    // ReadWrappedKeyFile converts it. Throws HkdfGuardError
    // (HKDFGUARD_ERR_INVALID_ARGUMENT) if it is empty, too long or not valid
    // UTF-8. Used to name the file in the plaintext-key audit event.
    std::wstring KeyFilePathToWide(const char *path);
} // namespace hkdfguard
