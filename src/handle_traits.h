#pragma once

// bcrypt.h / ncrypt.h declare the Windows CNG (Cryptography API: Next
// Generation) types and functions this file wraps: the BCRYPT_* handle
// types and BCryptCloseAlgorithmProvider/BCryptDestroyKey/etc., and the
// NCRYPT_* handle types and NCryptFreeObject.
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <utility>

namespace hkdfguard {
    // ScopedHandle is the second RAII wrapper in this project (see
    // secure_buffer.h's SecureBuffer for the first) - same idea, different
    // resource: instead of guaranteeing a buffer gets zeroed, it guarantees a
    // Windows handle gets closed. It's a *class template* taking two type
    // parameters:
    //   Handle - the Windows handle type being wrapped, e.g. NCRYPT_KEY_HANDLE.
    //            All of these Windows handle types are really just typedefs for
    //            an opaque numeric/pointer value (ULONG_PTR or void*), which is
    //            why `Handle handle_ = 0;` below (treating "0" as "no handle")
    //            is meaningful for all of them.
    //   Closer - a small "functor" type (a class whose only job is providing an
    //            operator(), so instances of it can be *called* like a
    //            function - see the Closer structs below) that knows which
    //            specific Windows "close/destroy/free" function applies to this
    //            particular Handle type. Passing behavior in as a *type*
    //            (rather than e.g. a function pointer stored at runtime) lets
    //            the compiler inline the call to Closer{}(handle_) with zero
    //            runtime overhead - there's no actual decision being made at
    //            runtime about which close function to call, it's baked in by
    //            which ScopedHandle<...> specialization you're using.
    template<typename Handle, typename Closer>
    class ScopedHandle {
    public:
        // Default-constructed: owns nothing (handle_ == 0 means "empty").
        ScopedHandle() : handle_(0) {
        }

        // `explicit` prevents the compiler from using this constructor for
        // *implicit* conversions (e.g. silently turning a raw Handle into a
        // ScopedHandle when passing an argument) - callers must write
        // `ScopedHandle(h)` on purpose, which avoids accidentally creating a
        // second "owner" of a handle that's already owned elsewhere.
        explicit ScopedHandle(Handle h) : handle_(h) {
        }

        // Just like SecureBuffer, copying is deleted: two ScopedHandles for the
        // same underlying Windows handle would both try to close it when they
        // went out of scope, which is a double-free / double-close bug.
        ScopedHandle(const ScopedHandle &) = delete;

        ScopedHandle &operator=(const ScopedHandle &) = delete;

        // But *moving* is allowed and implemented by hand here (the `&&`
        // parameter type marks these as "move" overloads, as opposed to the
        // deleted `const&` "copy" overloads above). A move transfers ownership
        // from `other` to `this` and leaves `other` empty (handle_ = 0), so
        // only one ScopedHandle ever "owns" a given Windows handle at a time,
        // even though the handle itself got copied between two C++ objects.
        // This is what lets functions return a ScopedHandle by value (as
        // ImportBCryptEccPublicKey does in ecdh_hkdf.cpp) - the compiler moves
        // the temporary into the caller's variable instead of copying it, and
        // `noexcept` promises the move itself can never throw, which the
        // standard library relies on for some of its own guarantees.
        ScopedHandle(ScopedHandle &&other) noexcept : handle_(other.handle_) {
            other.handle_ = 0;
        }

        ScopedHandle &operator=(ScopedHandle &&other) noexcept {
            // Self-move-assignment guard: `a = std::move(a);` should not close
            // and then read the handle it just closed.
            if (this != &other) {
                reset();
                handle_ = other.handle_;
                other.handle_ = 0;
            }
            return *this;
        }

        // The destructor - this is the actual RAII payoff. Whatever handle
        // `this` currently owns (if any) gets closed automatically the instant
        // the ScopedHandle goes out of scope, on every exit path.
        ~ScopedHandle() { reset(); }

        // Closes the currently-owned handle (if any) and starts owning `h`
        // instead (default h = 0, i.e. "own nothing"). `Closer{}` constructs a
        // temporary instance of the (stateless) Closer functor type and `(...)`
        // immediately calls its operator() on it - equivalent to just calling
        // the right Bcrypt/NCrypt "close" function directly, but written
        // generically so this one `reset()` implementation works for every
        // Handle/Closer combination below.
        void reset(Handle h = 0) {
            if (handle_ != 0) {
                Closer{}(handle_);
            }
            handle_ = h;
        }

        // Many Windows APIs want an "out parameter": a `Handle*` they can write
        // their newly-created handle into (e.g. `NCryptOpenKey(..., key.put(),
        // ...)`). put() first closes anything currently owned (so calling put()
        // twice on the same ScopedHandle can't leak the first handle), then
        // hands back the address of our internal slot for the API to fill in.
        Handle *put() {
            reset();
            return &handle_;
        }

        // Releases ownership without closing the handle - for the rare case
        // where an API call (e.g. NCryptDeleteKey) itself invalidates the
        // handle, so it must not also be passed to Closer.
        Handle release() {
            Handle h = handle_;
            handle_ = 0;
            return h;
        }

        // Read-only access to the raw handle, for passing into Windows API
        // calls that just *use* the handle without taking ownership of it.
        // `const` here means get() can be called on a `const ScopedHandle&`.
        Handle get() const { return handle_; }

        // Lets a ScopedHandle be used in a boolean context, e.g. `if (key) {...}`,
        // to mean "do we currently own a real handle?" `explicit` stops it from
        // being used where a bool isn't clearly intended (e.g. it can't be
        // accidentally added to an int), which is generally good practice for
        // this kind of "is this thing valid" conversion operator.
        explicit operator bool() const { return handle_ != 0; }

    private:
        Handle handle_;
    };

    // One tiny functor struct per Windows handle type, each just forwarding to
    // the one correct "close this" API for that type. `operator()` is the
    // special member name that makes an object "callable" like a function, so
    // `Closer{}(h)` below reads as "call this closer on handle h."
    struct NCryptProvCloser {
        void operator()(NCRYPT_PROV_HANDLE h) const { NCryptFreeObject(h); }
    };

    struct NCryptKeyCloser {
        void operator()(NCRYPT_KEY_HANDLE h) const { NCryptFreeObject(h); }
    };

    struct NCryptSecretCloser {
        void operator()(NCRYPT_SECRET_HANDLE h) const { NCryptFreeObject(h); }
    };

    struct BCryptAlgCloser {
        void operator()(BCRYPT_ALG_HANDLE h) const { BCryptCloseAlgorithmProvider(h, 0); }
    };

    struct BCryptKeyCloser {
        void operator()(BCRYPT_KEY_HANDLE h) const { BCryptDestroyKey(h); }
    };

    struct BCryptSecretCloser {
        void operator()(BCRYPT_SECRET_HANDLE h) const { BCryptDestroySecret(h); }
    };

    struct BCryptHashCloser {
        void operator()(BCRYPT_HASH_HANDLE h) const { BCryptDestroyHash(h); }
    };

    // `using X = Y;` is a *type alias*: it doesn't create a new type, just a
    // shorter name for an existing one - `ScopedNCryptKey` everywhere below
    // means exactly `ScopedHandle<NCRYPT_KEY_HANDLE, NCryptKeyCloser>`. This is
    // what lets the rest of the codebase write `ScopedNCryptKey key;` instead
    // of repeating the full template instantiation at every use.
    using ScopedNCryptProv = ScopedHandle<NCRYPT_PROV_HANDLE, NCryptProvCloser>;
    using ScopedNCryptKey = ScopedHandle<NCRYPT_KEY_HANDLE, NCryptKeyCloser>;
    using ScopedNCryptSecret = ScopedHandle<NCRYPT_SECRET_HANDLE, NCryptSecretCloser>;
    using ScopedBCryptAlg = ScopedHandle<BCRYPT_ALG_HANDLE, BCryptAlgCloser>;
    using ScopedBCryptKey = ScopedHandle<BCRYPT_KEY_HANDLE, BCryptKeyCloser>;
    using ScopedBCryptSecret = ScopedHandle<BCRYPT_SECRET_HANDLE, BCryptSecretCloser>;
    using ScopedBCryptHash = ScopedHandle<BCRYPT_HASH_HANDLE, BCryptHashCloser>;
} // namespace hkdfguard
