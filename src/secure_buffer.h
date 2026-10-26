#pragma once

#include <windows.h> // SecureZeroMemory
#include <cstddef> // size_t
#include <cstdint> // uint8_t

namespace hkdfguard {
    // A fixed-size, in-place N-byte buffer for key material or plaintext,
    // zeroed when it goes out of scope on every exit path, exceptions
    // included.
    template<size_t N>
    class SecureBuffer {
    public:
        SecureBuffer() = default;

        // Not copyable: a copy would be a second stash of the secret that
        // nothing tracks or wipes. Pass by reference.
        SecureBuffer(const SecureBuffer &) = delete;

        SecureBuffer &operator=(const SecureBuffer &) = delete;

        // SecureZeroMemory rather than memset: the optimizer may remove a
        // memset of memory that is never read again as a dead store, but
        // never removes SecureZeroMemory.
        ~SecureBuffer() {
            SecureZeroMemory(data_, N);
        }

        // Raw pointers, as CNG takes buffers (PUCHAR + length).
        uint8_t *data() { return data_; }
        const uint8_t *data() const { return data_; }

        constexpr size_t size() const { return N; }

    private:
        uint8_t data_[N] = {}; // zero from construction
    };

    // Wipes sensitive bytes in a buffer not held as a SecureBuffer - e.g. a
    // caller-supplied output buffer from the public C ABI.
    inline void SecureZero(void *p, size_t len) {
        // Some error paths (e.g. hkdfguard.cpp's `fail` lambda) pass null or
        // zero length, which SecureZeroMemory does not promise to handle.
        if (p != nullptr && len != 0) {
            SecureZeroMemory(p, len);
        }
    }

    // SecureBuffer's guarantee for memory this project doesn't hold as a
    // SecureBuffer - a run-time-sized heap buffer, say: zeroes `len` bytes at
    // `p` when the guard goes out of scope, on every exit path, an exception
    // included. The memory must outlive the guard, so declare the guard after
    // whatever owns it. Not copyable, for the same reason SecureBuffer isn't.
    class ScopedSecureZero {
    public:
        ScopedSecureZero(void *p, size_t len) noexcept : p_(p), len_(len) {}
        ScopedSecureZero(const ScopedSecureZero &) = delete;
        ScopedSecureZero &operator=(const ScopedSecureZero &) = delete;
        ~ScopedSecureZero() { SecureZero(p_, len_); }

    private:
        void *p_;
        size_t len_;
    };
} // namespace hkdfguard
