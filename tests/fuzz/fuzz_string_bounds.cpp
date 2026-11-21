// libFuzzer target for every C string the ABI takes - the service (through
// each of the six functions that take one), a key file path, a principal -
// with no terminator at all, at the longest length its rule allows, one byte
// over, and with a NUL earlier than the bytes that follow it. Each string
// ends against an inaccessible page (fuzz_abi.h's Guarded), so a read one
// byte past the bounded scan, or past a terminator, is an access violation
// in any build, sanitizer or not. Built only with
// -DHKDFGUARD_BUILD_FUZZERS=ON.
//
// Input: version byte, argument byte, shape byte and its fields:
//   0: unterminated  - fill byte: limit + 1 bytes of it, then the guard page
//   1: longest       - fill byte: limit bytes, then the NUL
//   2: one over      - fill byte: limit + 1 bytes, then the NUL
//   3: early NUL     - head (genuine, or bytes), NUL, then a tail of bytes
//
// Properties, beyond "no crash":
//   - An unterminated or over-long string gets its documented refusal.
//   - The longest valid service name is not refused for its length.
//   - Bytes after the first NUL change neither the status nor the output.
//   - The genuine string still works.
//
// Seeds: tests/fuzz/Make-AbiSeeds.ps1.
#include "fuzz_abi.h"

using namespace fuzz;

namespace {

constexpr size_t kMaxService = 128;
constexpr size_t kMaxPath = size_t{32767} * 3; // key_file.cpp's kMaxPathBytes
constexpr size_t kMaxPrincipal = 255;

enum class Arg { CreateKek, Exists, Fingerprint, Wrap, Unwrap, Generate, Path, Principal, Count };

bool IsService(Arg arg) { return arg <= Arg::Generate; }

size_t Limit(Arg arg) { return IsService(arg) ? kMaxService : (arg == Arg::Path ? kMaxPath : kMaxPrincipal); }

int RefusalFor(Arg arg) { return IsService(arg) ? HKDFGUARD_ERR_INVALID_SERVICE_NAME : HKDFGUARD_ERR_INVALID_ARGUMENT; }

// The string as the library should see it, when it is one: up to the first
// NUL.
std::string AsC(const std::vector<uint8_t>& bytes) {
    return {bytes.begin(), std::ranges::find(bytes, uint8_t{0})};
}

struct Outcome {
    int rc = 0;
    std::vector<uint8_t> output; // what the call returned, where that is deterministic
    bool operator==(const Outcome&) const = default;
};

// Calls the function `arg` names with `text` as its string and otherwise
// well-formed arguments.
Outcome CallWith(Arg arg, const char* text, int version) {
    const World& w = TheWorld();
    Outcome o;
    switch (arg) {
        case Arg::CreateKek: o.rc = hkdfguard_create_kek(text); break;
        case Arg::Exists: {
            int exists = -7;
            o.rc = hkdfguard_kek_exists(text, &exists);
            o.output.push_back(static_cast<uint8_t>(exists));
            break;
        }
        case Arg::Fingerprint: {
            o.output.assign(HKDFGUARD_KEK_FINGERPRINT_LEN, kFill);
            int len = HKDFGUARD_KEK_FINGERPRINT_LEN;
            o.rc = hkdfguard_kek_fingerprint(text, o.output.data(), &len);
            break;
        }
        case Arg::Wrap: {
            // The payload is random per call: only the status is compared.
            uint8_t out[HKDFGUARD_WRAPPED_MAX_LEN];
            int len = sizeof(out);
            o.rc = hkdfguard_wrap_dek(text, w.dek, HKDFGUARD_DEK_LEN, out, &len);
            break;
        }
        case Arg::Unwrap: {
            o.output.assign(HKDFGUARD_DEK_LEN, kFill);
            int len = HKDFGUARD_DEK_LEN;
            o.rc = hkdfguard_unwrap_dek(text, w.genuine[version].data(), HKDFGUARD_WRAPPED_MAX_LEN, o.output.data(), &len);
            break;
        }
        case Arg::Generate: {
            uint8_t out[HKDFGUARD_WRAPPED_MAX_LEN];
            int len = sizeof(out);
            o.rc = hkdfguard_generate_and_wrap_dek(text, out, &len);
            break;
        }
        case Arg::Path: {
            o.output.assign(HKDFGUARD_WRAPPED_MAX_LEN, kFill);
            int len = HKDFGUARD_WRAPPED_MAX_LEN;
            o.rc = hkdfguard_open_file(text, o.output.data(), &len);
            break;
        }
        case Arg::Principal: {
            int trusted = -7;
            o.rc = hkdfguard_key_file_principal_trusted(text, &trusted);
            o.output.push_back(static_cast<uint8_t>(trusted));
            break;
        }
        case Arg::Count: break;
    }
    FUZZ_CHECK(o.rc != HKDFGUARD_ERR_INTERNAL_ERROR && o.rc <= 0, "string_bounds: argument %d returned %d", static_cast<int>(arg),
               o.rc);
    return o;
}

// hkdfguard_create_kek makes a key for any valid name. The harness lets it
// see only names that are invalid, or the service that already has its KEK;
// any other valid name goes to hkdfguard_kek_exists, which reads the same
// string the same way.
Arg Tame(Arg arg, const std::string& as_c) {
    if (arg == Arg::CreateKek && ServiceNameIsValid(as_c) && Lower(as_c) != TheWorld().service) return Arg::Exists;
    return arg;
}

std::vector<uint8_t> Genuine(Arg arg) {
    const World& w = TheWorld();
    const std::string text = IsService(arg) ? w.service : (arg == Arg::Path ? GenuineKeyFile() : std::string("S-1-5-32-544"));
    return {text.begin(), text.end()};
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Setup("strings");
    In in{data, size};
    const int version = PickVersion(in);
    const Arg arg = static_cast<Arg>(in.u8() % static_cast<int>(Arg::Count));
    const size_t limit = Limit(arg);
    const World& w = TheWorld();

    switch (in.u8() % 4) {
        case 0: { // no terminator: exactly the bytes a bounded scan may read
            uint8_t fill = in.u8();
            if (fill == 0) fill = 'a';
            const Guarded text(std::vector<uint8_t>(limit + 1, fill));
            const Outcome o = CallWith(arg, text.ptr(), version);
            FUZZ_CHECK(o.rc == RefusalFor(arg), "string_bounds: an unterminated string (argument %d) returned %d", static_cast<int>(arg),
                       o.rc);
            break;
        }
        case 1: { // the longest the rule allows, its NUL the last readable byte
            uint8_t fill = in.u8();
            if (fill == 0 || (IsService(arg) && !ServiceNameIsValid(std::string(1, static_cast<char>(fill))))) fill = 'a';
            std::vector<uint8_t> bytes(limit, fill);
            bytes.push_back(0);
            const Guarded text(bytes);
            const Outcome o = CallWith(Tame(arg, AsC(bytes)), text.ptr(), version);
            if (IsService(arg)) {
                FUZZ_CHECK(o.rc != HKDFGUARD_ERR_INVALID_SERVICE_NAME, "string_bounds: the longest valid service name was refused");
            }
            break;
        }
        case 2: { // one byte over, terminated
            uint8_t fill = in.u8();
            if (fill == 0) fill = 'a';
            std::vector<uint8_t> bytes(limit + 1, fill);
            bytes.push_back(0);
            const Guarded text(bytes);
            const Outcome o = CallWith(arg, text.ptr(), version);
            FUZZ_CHECK(o.rc == RefusalFor(arg), "string_bounds: a string one byte too long (argument %d) returned %d",
                       static_cast<int>(arg), o.rc);
            break;
        }
        default: { // a NUL, then more bytes: the string ends at the NUL
            const bool genuine = !in.flag();
            std::vector<uint8_t> head = Genuine(arg);
            if (!genuine) {
                const std::vector<uint8_t> raw = in.blob();
                head.assign(raw.begin(), std::ranges::find(raw, uint8_t{0}));
            }
            const std::vector<uint8_t> tail = in.blob();
            const Arg tamed = Tame(arg, AsC(head));

            std::vector<uint8_t> alone = head;
            alone.push_back(0);
            std::vector<uint8_t> followed = alone;
            followed.insert(followed.end(), tail.begin(), tail.end());

            const Guarded alone_text(alone);
            const Guarded followed_text(followed);
            const Outcome plain = CallWith(tamed, alone_text.ptr(), version);
            const Outcome with_tail = CallWith(tamed, followed_text.ptr(), version);
            FUZZ_CHECK(plain == with_tail, "string_bounds: bytes after the NUL changed the answer (argument %d): %d, then %d",
                       static_cast<int>(arg), plain.rc, with_tail.rc);

            if (genuine) {
                switch (arg) {
                    case Arg::Exists:
                        FUZZ_CHECK(plain.rc != HKDFGUARD_OK || plain.output[0] == (w.have_kek[version] ? 1 : 0),
                                   "string_bounds: kek_exists answered %u for the genuine service", plain.output[0]);
                        break;
                    case Arg::Fingerprint:
                    case Arg::Wrap:
                    case Arg::Generate:
                    case Arg::Unwrap:
                        FUZZ_CHECK((plain.rc == HKDFGUARD_OK) == w.have_kek[version],
                                   "string_bounds: the genuine service returned %d (argument %d)", plain.rc, static_cast<int>(arg));
                        if (arg == Arg::Unwrap && plain.rc == HKDFGUARD_OK) {
                            FUZZ_CHECK(std::memcmp(plain.output.data(), w.dek, HKDFGUARD_DEK_LEN) == 0,
                                       "string_bounds: unwrap under the genuine service gave another DEK");
                        }
                        break;
                    case Arg::Path:
                        FUZZ_CHECK(plain.rc == HKDFGUARD_OK && plain.output == w.genuine[2],
                                   "string_bounds: the genuine key file returned %d", plain.rc);
                        break;
                    case Arg::Principal:
                        FUZZ_CHECK(plain.rc == HKDFGUARD_OK && plain.output[0] == 1,
                                   "string_bounds: Administrators returned %d, trusted %u", plain.rc, plain.output[0]);
                        break;
                    case Arg::CreateKek:
                    case Arg::Count:
                        break;
                }
            }
            break;
        }
    }
    return 0;
}
