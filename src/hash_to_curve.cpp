#include "hash_to_curve.h"
#include "errors.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <vector>

// RFC 9380 hash-to-curve (P256_XMD:SHA-256_SSWU_RO_). CNG has no
// hash-to-curve, and no field arithmetic either, so this is done here with a
// minimal arithmetic modulo p. It aims to be obviously correct rather than
// fast: field elements are four 64-bit limbs, and multiplication is
// double-and-add over modular addition, so nothing beyond add/subtract with
// carry is needed. Each step follows the RFC's text, not its optimized
// straight-line versions. One point costs about 8 ms (x64 Release) - mostly
// its six modular exponentiations, and about the cost of the TPM agreement
// it feeds. Every point produced is also checked by the
// caller through BCryptImportKeyPair (ecdh_hkdf.cpp), so an arithmetic
// mistake here fails closed, and tests/test_roundtrip.cpp pins the output
// against the RFC's own test vectors (Appendix J.1.1).

namespace hkdfguard {
    namespace {
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

        void ToBigEndian(const Fe &a, uint8_t out[32]) {
            for (int limb = 0; limb < 4; ++limb) {
                for (int k = 0; k < 8; ++k) {
                    out[(3 - limb) * 8 + k] = static_cast<uint8_t>(a.v[limb] >> (56 - 8 * k));
                }
            }
        }

        constexpr Fe kZero = {{0, 0, 0, 0}};
        constexpr Fe kOne = {{1, 0, 0, 0}};

        Fe Small(uint64_t v) {
            return {{v, 0, 0, 0}};
        }

        Fe Neg(const Fe &a) {
            return SubMod(kZero, a);
        }

        // a^-1 mod p as a^(p-2) (Fermat). This is RFC 9380's inv0: 0 maps to 0.
        Fe Inv(const Fe &a) {
            Fe e;
            SubRaw(e, kP, Small(2));
            return PowMod(a, e);
        }

        // The curve's right-hand side, x^3 + a*x + b, with a = -3.
        Fe CurveRhs(const Fe &x) {
            const Fe a = Neg(Small(3));
            return AddMod(AddMod(MulMod(MulMod(x, x), x), MulMod(a, x)), kB);
        }

        // Sets `root` to a square root of `a` and returns true if `a` is a
        // square mod p (0 included); returns false otherwise. Since
        // p = 3 (mod 4), a^((p+1)/4) is a root whenever one exists. The
        // exponent is computed from kP, not written out, so there is one
        // fewer constant to get wrong.
        bool Sqrt(const Fe &a, Fe &root) {
            Fe e;
            AddRaw(e, kP, kOne); // p + 1 < 2^256: no carry
            for (int i = 0; i < 4; ++i) { // shift right by 2
                e.v[i] = (e.v[i] >> 2) | (i < 3 ? e.v[i + 1] << 62 : 0);
            }
            root = PowMod(a, e);
            return Equal(MulMod(root, root), a);
        }

        // A big-endian integer of any length, reduced mod p by Horner's rule,
        // one byte at a time (r = 256*r + byte), so every intermediate value
        // stays below p.
        Fe ReduceBigEndian(const uint8_t *in, size_t len) {
            Fe r = kZero;
            for (size_t i = 0; i < len; ++i) {
                for (int k = 0; k < 8; ++k) {
                    r = AddMod(r, r);
                }
                r = AddMod(r, Small(in[i]));
            }
            return r;
        }

        void Sha256(std::vector<uint8_t> &in, uint8_t out[32]) {
            NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, in.data(),
                                         static_cast<ULONG>(in.size()), out, 32);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "SHA-256 for hash-to-curve failed");
            }
        }

        // hash_to_field's output: count = 2 elements of L = 48 bytes each
        // (L = ceil((ceil(log2(p)) + k) / 8) for security level k = 128).
        constexpr size_t kFieldBytes = 48;
        constexpr size_t kUniformBytes = 2 * kFieldBytes;

        // RFC 9380 section 5.3.1, expand_message_xmd with SHA-256
        // (b_in_bytes = 32, s_in_bytes = 64), for len_in_bytes = 96, so
        // ell = 3:
        //
        //   DST_prime = DST || I2OSP(len(DST), 1)
        //   b_0 = H(Z_pad(64) || msg || I2OSP(96, 2) || I2OSP(0, 1) || DST_prime)
        //   b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        //   b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        //   uniform_bytes = b_1 || b_2 || b_3
        void ExpandMessageXmd(const uint8_t *msg, size_t msg_len, const char *dst, size_t dst_len,
                              uint8_t out[kUniformBytes]) {
            if (dst_len > 255) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "hash-to-curve DST longer than 255 bytes");
            }
            std::vector<uint8_t> dst_prime(dst, dst + dst_len);
            dst_prime.push_back(static_cast<uint8_t>(dst_len));

            std::vector<uint8_t> input(64, 0); // Z_pad
            input.insert(input.end(), msg, msg + msg_len);
            input.push_back(0);
            input.push_back(static_cast<uint8_t>(kUniformBytes)); // I2OSP(96, 2)
            input.push_back(0);                                   // I2OSP(0, 1)
            input.insert(input.end(), dst_prime.begin(), dst_prime.end());
            uint8_t b0[32];
            Sha256(input, b0);

            uint8_t b_prev[32] = {};
            for (uint8_t i = 1; i <= kUniformBytes / 32; ++i) {
                input.clear();
                for (int k = 0; k < 32; ++k) {
                    input.push_back(i == 1 ? b0[k] : static_cast<uint8_t>(b0[k] ^ b_prev[k]));
                }
                input.push_back(i);
                input.insert(input.end(), dst_prime.begin(), dst_prime.end());
                Sha256(input, b_prev);
                memcpy(out + (i - 1) * 32, b_prev, 32);
            }
        }

        // RFC 9380 section 6.6.2, the simplified SWU map, with A = -3,
        // B = b and Z = -10 (section 8.2):
        //
        //   tv1 = inv0(Z^2 * u^4 + Z * u^2)
        //   x1  = (-B / A) * (1 + tv1);  if tv1 == 0, x1 = B / (Z * A)
        //   gx1 = x1^3 + A * x1 + B
        //   x2  = Z * u^2 * x1
        //   (x, y) = (x1, sqrt(gx1)) if gx1 is square, else (x2, sqrt(gx2))
        //   if sgn0(u) != sgn0(y), y = -y
        //
        // sgn0 on this prime field is the low bit.
        void MapToCurveSswu(const Fe &u, Fe &x, Fe &y) {
            const Fe a = Neg(Small(3)), z = Neg(Small(10));
            static const Fe minus_b_over_a = MulMod(Neg(kB), Inv(Neg(Small(3)))); // computed once
            const Fe z_u2 = MulMod(z, MulMod(u, u));
            const Fe tv1 = Inv(AddMod(MulMod(z_u2, z_u2), z_u2));
            Fe x1;
            if (Equal(tv1, kZero)) {
                x1 = MulMod(kB, Inv(MulMod(z, a)));
            } else {
                x1 = MulMod(minus_b_over_a, AddMod(kOne, tv1));
            }
            if (Sqrt(CurveRhs(x1), y)) {
                x = x1;
            } else {
                x = MulMod(z_u2, x1);
                if (!Sqrt(CurveRhs(x), y)) {
                    // The map guarantees one of gx1, gx2 is a square.
                    throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "simplified SWU found no square");
                }
            }
            if ((u.v[0] & 1) != (y.v[0] & 1)) {
                y = Neg(y);
            }
        }

        // (x0, y0) + (x1, y1) in affine coordinates. Neither input is the
        // point at infinity (the SWU map never outputs it); a sum that is
        // the point at infinity is refused. P-256 has no point with y = 0
        // (its order is odd), so doubling never divides by zero.
        void AddPoints(const Fe &x0, const Fe &y0, const Fe &x1, const Fe &y1, Fe &x, Fe &y) {
            Fe lambda;
            if (!Equal(x0, x1)) {
                lambda = MulMod(SubMod(y1, y0), Inv(SubMod(x1, x0)));
            } else if (Equal(y0, y1)) {
                // Doubling: (3 * x0^2 + a) / (2 * y0), a = -3.
                const Fe x0_sq = MulMod(x0, x0);
                lambda = MulMod(SubMod(AddMod(AddMod(x0_sq, x0_sq), x0_sq), Small(3)), Inv(AddMod(y0, y0)));
            } else {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "hash-to-curve sum is the point at infinity");
            }
            x = SubMod(SubMod(MulMod(lambda, lambda), x0), x1);
            y = SubMod(MulMod(lambda, SubMod(x0, x)), y0);
        }
    } // namespace

    void HashToCurveP256(const uint8_t *msg, size_t msg_len, const char *dst, size_t dst_len,
                         uint8_t point_out[kPublicPointLen]) {
        // hash_to_field: u_i = OS2IP(uniform_bytes[48*i .. 48*i + 47]) mod p.
        uint8_t uniform[kUniformBytes];
        ExpandMessageXmd(msg, msg_len, dst, dst_len, uniform);
        const Fe u0 = ReduceBigEndian(uniform, kFieldBytes);
        const Fe u1 = ReduceBigEndian(uniform + kFieldBytes, kFieldBytes);

        Fe q0x, q0y, q1x, q1y, x, y;
        MapToCurveSswu(u0, q0x, q0y);
        MapToCurveSswu(u1, q1x, q1y);
        AddPoints(q0x, q0y, q1x, q1y, x, y); // clear_cofactor: h_eff = 1
        ToBigEndian(x, point_out);
        ToBigEndian(y, point_out + 32);
    }

    void PayloadEcdhPoint(const uint8_t salt[kSaltLen], uint8_t point_out[kPublicPointLen]) {
        HashToCurveP256(salt, kSaltLen, kPayloadEcdhPointDst, sizeof(kPayloadEcdhPointDst) - 1, point_out);
    }
} // namespace hkdfguard

