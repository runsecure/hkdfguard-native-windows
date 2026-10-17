#include "hash_to_curve.h"
#include "errors.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstring>

// Point decompression - finding Y from X - is the one piece of P-256
// arithmetic CNG doesn't expose, so it is done here with a minimal
// arithmetic modulo p. The design goal is being obviously correct rather
// than fast: field elements are four 64-bit limbs, and multiplication is
// double-and-add over modular addition, so nothing beyond add/subtract with
// carry is ever needed. One point costs about a millisecond - small beside
// the TPM agreement it feeds. Every point produced is also checked by the
// caller through BCryptImportKeyPair (ecdh_hkdf.cpp), so an arithmetic
// mistake here could only ever fail closed, and tests/test_roundtrip.cpp
// pins the output against vectors from the Linux implementation's own
// p256 crate.

namespace hkdfguard {
    namespace {
        constexpr char kDomain[] = "HkdfGuard-P256-payload-ECDH-point-v1:";
        constexpr int kMaxAttempts = 255; // counters 0..254, as on Linux (0..u8::MAX)

        // A field element mod p: little-endian 64-bit limbs, v[0] least significant.
        struct Fe {
            uint64_t v[4];
        };

        // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
        constexpr Fe kP = {{0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull}};
        // b, the curve's constant term (a = -3)
        constexpr Fe kB = {{0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, 0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull}};

        bool Equal(const Fe &a, const Fe &b) {
            return a.v[0] == b.v[0] && a.v[1] == b.v[1] && a.v[2] == b.v[2] && a.v[3] == b.v[3];
        }

        bool GreaterOrEqual(const Fe &a, const Fe &b) {
            for (int i = 3; i >= 0; --i) {
                if (a.v[i] != b.v[i]) {
                    return a.v[i] > b.v[i];
                }
            }
            return true;
        }

        // r = a + b over 256 bits; returns the carry out.
        uint64_t AddRaw(Fe &r, const Fe &a, const Fe &b) {
            uint64_t carry = 0;
            for (int i = 0; i < 4; ++i) {
                uint64_t s = a.v[i] + carry;
                uint64_t c1 = s < carry ? 1 : 0;
                uint64_t t = s + b.v[i];
                uint64_t c2 = t < s ? 1 : 0;
                r.v[i] = t;
                carry = c1 | c2;
            }
            return carry;
        }

        // r = a - b over 256 bits; returns the borrow out.
        uint64_t SubRaw(Fe &r, const Fe &a, const Fe &b) {
            uint64_t borrow = 0;
            for (int i = 0; i < 4; ++i) {
                uint64_t d = a.v[i] - b.v[i];
                uint64_t b1 = a.v[i] < b.v[i] ? 1 : 0;
                uint64_t e = d - borrow;
                uint64_t b2 = d < borrow ? 1 : 0;
                r.v[i] = e;
                borrow = b1 | b2;
            }
            return borrow;
        }

        // (a + b) mod p, for a, b < p. The sum is below 2p < 2^257, so one
        // subtraction of p suffices; when the 256-bit add carried out, the
        // wrap-around of that subtraction restores the true value.
        Fe AddMod(const Fe &a, const Fe &b) {
            Fe r;
            uint64_t carry = AddRaw(r, a, b);
            if (carry != 0 || GreaterOrEqual(r, kP)) {
                SubRaw(r, r, kP);
            }
            return r;
        }

        // (a - b) mod p, for a, b < p.
        Fe SubMod(const Fe &a, const Fe &b) {
            Fe r;
            if (SubRaw(r, a, b) != 0) {
                AddRaw(r, r, kP);
            }
            return r;
        }

        bool Bit(const Fe &a, int i) {
            return ((a.v[i / 64] >> (i % 64)) & 1) != 0;
        }

        // (a * b) mod p by double-and-add over b's bits, most significant first.
        Fe MulMod(const Fe &a, const Fe &b) {
            Fe r = {{0, 0, 0, 0}};
            for (int i = 255; i >= 0; --i) {
                r = AddMod(r, r);
                if (Bit(b, i)) {
                    r = AddMod(r, a);
                }
            }
            return r;
        }

        // base^e mod p by square-and-multiply.
        Fe PowMod(const Fe &base, const Fe &e) {
            Fe r = {{1, 0, 0, 0}};
            for (int i = 255; i >= 0; --i) {
                r = MulMod(r, r);
                if (Bit(e, i)) {
                    r = MulMod(r, base);
                }
            }
            return r;
        }

        Fe FromBigEndian(const uint8_t in[32]) {
            Fe r;
            for (int limb = 0; limb < 4; ++limb) {
                uint64_t w = 0;
                for (int k = 0; k < 8; ++k) {
                    w = (w << 8) | in[(3 - limb) * 8 + k];
                }
                r.v[limb] = w;
            }
            return r;
        }

        void ToBigEndian(const Fe &a, uint8_t out[32]) {
            for (int limb = 0; limb < 4; ++limb) {
                for (int k = 0; k < 8; ++k) {
                    out[(3 - limb) * 8 + k] = static_cast<uint8_t>(a.v[limb] >> (56 - 8 * k));
                }
            }
        }

        // (p + 1) / 4: since p = 3 (mod 4), y = rhs^((p+1)/4) is a square root
        // of rhs whenever one exists. Computed from kP, not written out, so
        // there is one fewer constant to get wrong.
        Fe SqrtExponent() {
            Fe one = {{1, 0, 0, 0}}, e;
            AddRaw(e, kP, one); // p + 1 < 2^256: no carry
            for (int i = 0; i < 4; ++i) { // shift right by 2
                e.v[i] = (e.v[i] >> 2) | (i < 3 ? e.v[i + 1] << 62 : 0);
            }
            return e;
        }
    } // namespace

    void PayloadEcdhPoint(const uint8_t salt[kSaltLen], uint8_t point_out[kPublicPointLen]) {
        constexpr size_t domain_len = sizeof(kDomain) - 1; // exclude NUL
        uint8_t input[domain_len + kSaltLen + 1];
        memcpy(input, kDomain, domain_len);
        memcpy(input + domain_len, salt, kSaltLen);

        const Fe exponent = SqrtExponent();
        for (int counter = 0; counter < kMaxAttempts; ++counter) {
            input[domain_len + kSaltLen] = static_cast<uint8_t>(counter);
            uint8_t x_bytes[32];
            NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, input, sizeof(input), x_bytes, 32);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "SHA-256 for hash-to-curve failed");
            }

            Fe x = FromBigEndian(x_bytes);
            if (GreaterOrEqual(x, kP)) {
                continue; // not a field element (as the p256 crate's SEC1 decoder rejects it)
            }
            // rhs = x^3 - 3x + b
            Fe x3 = MulMod(MulMod(x, x), x);
            Fe three_x = AddMod(AddMod(x, x), x);
            Fe rhs = AddMod(SubMod(x3, three_x), kB);

            Fe y = PowMod(rhs, exponent);
            if (!Equal(MulMod(y, y), rhs)) {
                continue; // rhs is not a square: no point has this X
            }
            if ((y.v[0] & 1) != 0) {
                SubRaw(y, kP, y); // the even root: p - y (y is odd, so nonzero)
            }
            ToBigEndian(x, point_out);
            ToBigEndian(y, point_out + 32);
            return;
        }
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "no P-256 point found for this payload salt");
    }
} // namespace hkdfguard
