"""Independent reference for the golden payload's derivation (Python standard library only).

Recomputes, without any of src/, the values tests/test_roundtrip.cpp freezes
for the golden payload (section 29):

  H(salt)      - RFC 9380 hash-to-curve, suite P256_XMD:SHA-256_SSWU_RO_,
                 checked first against every vector in RFC 9380 Appendix J.1.1
  Z            - x(d * H(salt)), big-endian
  wrapping key - HKDF-SHA512(salt, Z, "hkdfguard-wrap-v1:" || u16le(len(service))
                 || service || header || SHA-256(KEK X || Y)), first 32 bytes

Run: python -I tests/reference/golden_reference.py
"""

import hashlib
import hmac
import sys

# P-256 (SEC 2 / FIPS 186-4)
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Z_SSWU = P - 10

PAYLOAD_DST = b"HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_"


def expand_message_xmd(msg, dst, length):  # RFC 9380 section 5.3.1, SHA-256
    ell = -(-length // 32)
    assert ell <= 255 and len(dst) <= 255
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha256(bytes(64) + msg + length.to_bytes(2, "big") + b"\x00" + dst_prime).digest()
    b = [hashlib.sha256(b0 + b"\x01" + dst_prime).digest()]
    for i in range(2, ell + 1):
        b.append(hashlib.sha256(bytes(x ^ y for x, y in zip(b0, b[-1])) + bytes([i]) + dst_prime).digest())
    return b"".join(b)[:length]


def hash_to_field(msg, dst):  # count = 2, L = 48
    u = expand_message_xmd(msg, dst, 96)
    return [int.from_bytes(u[0:48], "big") % P, int.from_bytes(u[48:96], "big") % P]


def is_square(x):
    return pow(x, (P - 1) // 2, P) in (0, 1)


def sqrt(x):  # P = 3 mod 4
    y = pow(x, (P + 1) // 4, P)
    assert y * y % P == x
    return y


def map_to_curve_sswu(u):  # RFC 9380 section 6.6.2
    tv1 = pow((Z_SSWU * Z_SSWU * pow(u, 4, P) + Z_SSWU * u * u) % P, P - 2, P)
    x1 = (-B * pow(A, P - 2, P) * (1 + tv1)) % P
    if tv1 == 0:
        x1 = B * pow(Z_SSWU * A, P - 2, P) % P
    gx1 = (x1**3 + A * x1 + B) % P
    x2 = Z_SSWU * u * u * x1 % P
    gx2 = (x2**3 + A * x2 + B) % P
    x, y = (x1, sqrt(gx1)) if is_square(gx1) else (x2, sqrt(gx2))
    if u % 2 != y % 2:
        y = P - y
    return (x, y)


def add(p1, p2):  # affine; None is the point at infinity
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, point):
    r = None
    for bit in bin(k)[2:]:
        r = add(r, r)
        if bit == "1":
            r = add(r, point)
    return r


def hash_to_curve(msg, dst):
    u0, u1 = hash_to_field(msg, dst)
    return add(map_to_curve_sswu(u0), map_to_curve_sswu(u1))  # h_eff = 1


def on_curve(pt):
    x, y = pt
    return (y * y - (x**3 + A * x + B)) % P == 0


def hkdf_sha512(salt, ikm, info, length):  # RFC 5869
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
        i += 1
    return okm[:length]


# RFC 9380 Appendix J.1.1, P256_XMD:SHA-256_SSWU_RO_
RFC_DST = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
RFC_VECTORS = [
    (b"",
     "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
     "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"),
    (b"abc",
     "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
     "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"),
    (b"abcdef0123456789",
     "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
     "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"),
    (b"q128_" + b"q" * 128,
     "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
     "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e"),
    (b"a512_" + b"a" * 512,
     "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
     "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc"),
]

# The golden payload's inputs (tests/test_roundtrip.cpp, kGolden*).
GOLDEN_KEK_X = "a55c04e4b2113126f3ea5244034decd0c0c9f55cd25d2e0396a365a7e265082f"
GOLDEN_KEK_Y = "4ab897ae67c14350a0213b0a67d416472aa053a16992018ac4d874dc8529569d"
GOLDEN_KEK_D = "9639379738995d1017b34a6398b444cf9cd0c82acb0dc0cd5d40c91b513f4e90"
GOLDEN_SALT = bytes([0x42]) * 32
GOLDEN_SERVICE = b"hkdfguardwin.test.golden"
PROVIDER_TYPE_SOFTWARE = 2


def main():
    for msg, x, y in RFC_VECTORS:
        assert hash_to_curve(msg, RFC_DST) == (int(x, 16), int(y, 16)), f"RFC 9380 vector {msg[:8]!r} failed"
    print(f"RFC 9380 J.1.1: all {len(RFC_VECTORS)} vectors match")

    kek = (int(GOLDEN_KEK_X, 16), int(GOLDEN_KEK_Y, 16))
    d = int(GOLDEN_KEK_D, 16)
    assert mul(d, (GX, GY)) == kek, "golden KEK: d*G is not the public key"

    h = hash_to_curve(GOLDEN_SALT, PAYLOAD_DST)
    assert on_curve(h)
    z = mul(d, h)[0].to_bytes(32, "big")

    kek_raw = bytes.fromhex(GOLDEN_KEK_X + GOLDEN_KEK_Y)
    header = bytes([0x01, PROVIDER_TYPE_SOFTWARE, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]) + GOLDEN_SALT
    authenticated = header + hashlib.sha256(kek_raw).digest()
    info = (b"hkdfguard-wrap-v1:" + len(GOLDEN_SERVICE).to_bytes(2, "little") + GOLDEN_SERVICE
            + authenticated)
    wrapping_key = hkdf_sha512(GOLDEN_SALT, z, info, 32)

    print(f"H(golden salt).x = {h[0]:064x}")
    print(f"H(golden salt).y = {h[1]:064x}")
    print(f"Z                = {z.hex()}")
    print(f"wrapping key     = {wrapping_key.hex()}")
    print(f"AAD              = {authenticated.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
