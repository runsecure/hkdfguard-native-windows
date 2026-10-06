#pragma once

// Pulls in the HKDFGUARD_ERR_* status code macros (HkdfGuardError below
// stores one of these as its `code_`).
#include "../include/hkdfguard.h"
// <stdexcept> declares std::runtime_error, the standard-library exception
// type HkdfGuardError below inherits from.
#include <stdexcept>

namespace hkdfguard {
    // `class HkdfGuardError : public std::runtime_error` means HkdfGuardError
    // *is a* std::runtime_error (public inheritance), plus one extra piece of
    // data (`code_`). Because of that "is a" relationship, an HkdfGuardError can
    // be caught anywhere by a handler written as `catch (const std::exception&)`
    // (as tests/test_roundtrip.cpp's CleanupKek does) or as `catch (const
    // std::runtime_error&)`, not just by its own exact type - this is ordinary
    // object-oriented polymorphism applied to exceptions.
    //
    // The strategy this whole codebase uses: internal helper functions (in
    // kek_store.cpp, ecdh_hkdf.cpp, aes_gcm.cpp, wire_format.cpp) `throw` this
    // type the moment something goes wrong, instead of returning an error code
    // that every caller up the chain would otherwise have to check and
    // propagate by hand. Throwing unwinds the C++ call stack automatically,
    // running every live object's destructor along the way - which is exactly
    // what makes the RAII types in secure_buffer.h and handle_traits.h reliably
    // zero secrets and close handles even on an error path, with no extra code
    // required at each call site. The *only* place this exception is ever
    // caught is the `try`/`catch` in the two exported functions in
    // hkdfguard.cpp, which is also the only place these C++ exceptions get
    // turned back into the plain integer return codes the public C ABI uses -
    // by design, no C++ exception ever crosses that boundary.
    class HkdfGuardError : public std::runtime_error {
    public:
        // `explicit` (see handle_traits.h for the same keyword on
        // ScopedHandle's constructor) stops the compiler from implicitly
        // converting a bare `int` into an HkdfGuardError in places that don't
        // obviously call for one. `code` defaults to nothing (it's required),
        // but `what` has a default value, so `HkdfGuardError(HKDFGUARD_ERR_CRYPTO)`
        // alone is a valid call.
        //
        // The constructor's initializer list, `: std::runtime_error(what),
        // code_(code)`, runs *before* the (empty) function body `{}` and is how
        // C++ constructs base classes and member variables - here it forwards
        // `what` up to std::runtime_error's own constructor (which stores it
        // for later retrieval via `.what()`, used by the test's `catch` block)
        // and initializes our own `code_` member directly.
        explicit HkdfGuardError(int code, const char *what = "hkdfguard error")
            : std::runtime_error(what), code_(code) {
        }

        // Read-only accessor for the stored status code. `const` here means
        // this method promises not to modify the HkdfGuardError it's called on,
        // so it can be called even on a `const HkdfGuardError&` (as
        // hkdfguard.cpp's `catch (const HkdfGuardError& e)` handlers do).
        int code() const { return code_; }

    private:
        int code_;
    };
} // namespace hkdfguard
