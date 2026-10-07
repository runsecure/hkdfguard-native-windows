// #pragma once is a simpler, non-standard-but-universally-supported
// alternative to the #ifndef/#define/#endif include guard seen in
// hkdfguard.h. It tells the compiler "only ever include this exact file
// once per translation unit." Internal headers in this project use #pragma
// once; the public hkdfguard.h uses the portable guard style since it may
// be consumed by stricter/non-MSVC toolchains on the calling side.
#pragma once

// windows.h declares SecureZeroMemory, used below.
#include <windows.h>
#include <cstddef> // size_t
#include <cstdint> // uint8_t

// Everything in this project lives inside `namespace hkdfguard` so its
// internal helper names (SecureBuffer, SecureZero, ...) can't collide with
// same-named things elsewhere in a program that links against this DLL.
namespace hkdfguard {
    // `template <size_t N>` makes SecureBuffer a *class template*: not a single
    // type, but a recipe the compiler uses to stamp out a distinct type for
    // each N you use it with (SecureBuffer<32> and SecureBuffer<12> are two
    // unrelated types, each with its own N-byte array baked in at compile time,
    // just like plain C arrays `uint8_t buf[32];` and `uint8_t buf[12];`).
    //
    // This class exists to implement the pattern called *RAII* (Resource
    // Acquisition Is Initialization), which is the single most important C++
    // idiom used throughout this project: tie a resource's cleanup to an
    // object's lifetime, so the *compiler* guarantees the cleanup runs when
    // that object's scope ends - on a normal return, an early return, a
    // `break`/`continue`, or even when an exception unwinds the stack - without
    // the programmer having to remember to call a "free" function on every one
    // of those exit paths by hand (the classic C bug pattern: `goto cleanup;`
    // forgotten on one obscure branch, or an early `return` that skips the
    // free()).
    //
    // Here the "resource" being managed isn't memory allocation (the array is
    // just an ordinary member, not heap-allocated) but *secrecy*: the guarantee
    // that whatever key material or plaintext was written into this buffer gets
    // overwritten with zeros the moment the buffer goes out of scope, however
    // that happens.
    template<size_t N>
    class SecureBuffer {
    public:
        // `= default` asks the compiler to generate the ordinary do-nothing
        // default constructor itself, rather than us writing an empty `{}`
        // body - it documents "yes, we deliberately want the default behavior"
        // rather than looking like an oversight.
        SecureBuffer() = default;

        // `= delete` does the opposite: it explicitly removes a function the
        // compiler would otherwise have generated for us. Deleting the copy
        // constructor and copy-assignment operator makes it a compile error to
        // write `SecureBuffer<32> b2 = b1;` or `b2 = b1;` anywhere in the
        // codebase. This is deliberate: every copy of a SecureBuffer would be a
        // second, independent stash of the same secret bytes that this class
        // has no way to know about or zero later - so the type simply forbids
        // copying outright, and the compiler enforces it for us at every call
        // site, project-wide, forever. (Passing one by reference, as this
        // codebase does everywhere, is still fine and doesn't copy anything.)
        SecureBuffer(const SecureBuffer &) = delete;

        SecureBuffer &operator=(const SecureBuffer &) = delete;

        // The destructor: C++ guarantees this runs automatically, exactly once,
        // at the end of the object's scope - this is the "RAII" part in action.
        // SecureZeroMemory (a Windows API, not the standard library's memset) is
        // used instead of a plain loop or memset specifically because the
        // Windows documentation guarantees the compiler's optimizer will never
        // remove this call as a "dead store" - a real risk with memset, since an
        // optimizer can prove "this memory is about to go out of scope and
        // nothing reads it again" and legally delete the zeroing writes
        // entirely, silently leaving the secret in memory.
        ~SecureBuffer() {
            SecureZeroMemory(data_, N);
        }

        // Two overloads of data(): the non-const one is selected when called
        // through a non-const SecureBuffer& (lets the caller write into the
        // buffer), the const one when called through a const SecureBuffer& or
        // SecureBuffer (only lets the caller read). Returning a raw pointer
        // here is intentional and matches how every Windows crypto API in this
        // project expects to receive buffers (as `uint8_t*`/`PUCHAR` + a
        // length), so no bridging/copying is needed at each call site.
        uint8_t *data() { return data_; }
        const uint8_t *data() const { return data_; }

        // `constexpr` means the compiler can (and, since N is a compile-time
        // template parameter, always will) evaluate this function at compile
        // time rather than generating a runtime call - `size()` is really just
        // another name for the constant N.
        constexpr size_t size() const { return N; }

    private:
        // The `= {}` value-initializes the array to all zeros at construction
        // time too, so a SecureBuffer never contains uninitialized stack
        // garbage before its first real write.
        uint8_t data_[N] = {};
    };

    // A free (non-member) helper for the cases where the sensitive bytes live
    // in a buffer this project doesn't own as a SecureBuffer - e.g. a
    // caller-supplied output buffer passed in through the public C ABI, which
    // arrives here as a plain pointer + length, not as one of our own objects.
    // `inline` is required because this function's *definition* (not just its
    // declaration) lives in a header that multiple .cpp files include; without
    // `inline`, each of those .cpp files would compile its own copy of the
    // function and the linker would then reject the program for having the
    // same symbol defined more than once.
    inline void SecureZero(void *p, size_t len) {
        // Defensive check: some callers (see hkdfguard.cpp's `fail` lambda) may
        // legitimately call this with a null pointer or zero length on certain
        // error paths, and SecureZeroMemory itself does not promise to handle
        // that gracefully, so we guard it here.
        if (p != nullptr && len != 0) {
            SecureZeroMemory(p, len);
        }
    }
} // namespace hkdfguard
