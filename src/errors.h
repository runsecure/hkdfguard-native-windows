#pragma once

#include "../include/hkdfguard.h" // HKDFGUARD_ERR_* status codes
#include <stdexcept>

namespace hkdfguard {
    // The internal error type: an HKDFGUARD_ERR_* status code plus a
    // diagnostic message.
    //
    // Internal helpers (kek_store.cpp, ecdh_hkdf.cpp, aes_gcm.cpp,
    // wire_format.cpp, ...) throw this as soon as something fails; stack
    // unwinding lets the RAII types in secure_buffer.h and handle_traits.h
    // zero secrets and close handles on every error path. The exported
    // functions in hkdfguard.cpp catch it and return its code, so no C++
    // exception ever crosses the C ABI.
    class HkdfGuardError : public std::runtime_error {
    public:
        // `what` is for diagnostics only; callers of the ABI see just `code`.
        explicit HkdfGuardError(int code, const char *what = "hkdfguard error")
            : std::runtime_error(what), code_(code) {
        }

        // The HKDFGUARD_ERR_* status code to return across the ABI.
        int code() const { return code_; }

    private:
        int code_;
    };
} // namespace hkdfguard
