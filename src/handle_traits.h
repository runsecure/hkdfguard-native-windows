#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <utility>

namespace hkdfguard {
    // Owns a CNG handle and closes it when it goes out of scope, on every
    // exit path. `Handle` is a BCRYPT_*/NCRYPT_* handle type (0 = no
    // handle); `Closer` is a stateless functor calling that type's close
    // function (see the Closer structs below).
    template<typename Handle, typename Closer>
    class ScopedHandle {
    public:
        ScopedHandle() : handle_(0) {
        }

        explicit ScopedHandle(Handle h) : handle_(h) {
        }

        // Not copyable (two owners would double-close); movable, the source
        // left empty, so exactly one ScopedHandle owns a handle.
        ScopedHandle(const ScopedHandle &) = delete;

        ScopedHandle &operator=(const ScopedHandle &) = delete;

        ScopedHandle(ScopedHandle &&other) noexcept : handle_(other.handle_) {
            other.handle_ = 0;
        }

        ScopedHandle &operator=(ScopedHandle &&other) noexcept {
            // Self-move must not close the handle it then keeps.
            if (this != &other) {
                reset();
                handle_ = other.handle_;
                other.handle_ = 0;
            }
            return *this;
        }

        ~ScopedHandle() { reset(); }

        // Closes the owned handle (if any) and takes ownership of `h`.
        void reset(Handle h = 0) {
            if (handle_ != 0) {
                Closer{}(handle_);
            }
            handle_ = h;
        }

        // For APIs that return a handle through a `Handle*` out-parameter
        // (e.g. `NCryptOpenKey(..., key.put(), ...)`). Closes any owned
        // handle first, so reuse cannot leak it.
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

        // The raw handle, for calls that use it without taking ownership.
        Handle get() const { return handle_; }

        // True if a handle is owned.
        explicit operator bool() const { return handle_ != 0; }

    private:
        Handle handle_;
    };

    // One closer per handle type, forwarding to that type's close API.
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

    using ScopedNCryptProv = ScopedHandle<NCRYPT_PROV_HANDLE, NCryptProvCloser>;
    using ScopedNCryptKey = ScopedHandle<NCRYPT_KEY_HANDLE, NCryptKeyCloser>;
    using ScopedNCryptSecret = ScopedHandle<NCRYPT_SECRET_HANDLE, NCryptSecretCloser>;
    using ScopedBCryptAlg = ScopedHandle<BCRYPT_ALG_HANDLE, BCryptAlgCloser>;
    using ScopedBCryptKey = ScopedHandle<BCRYPT_KEY_HANDLE, BCryptKeyCloser>;
    using ScopedBCryptSecret = ScopedHandle<BCRYPT_SECRET_HANDLE, BCryptSecretCloser>;
    using ScopedBCryptHash = ScopedHandle<BCRYPT_HASH_HANDLE, BCryptHashCloser>;
} // namespace hkdfguard
