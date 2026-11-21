// libFuzzer target for hkdfguard_unwrap_dek: arbitrary bytes, and bit-flipped,
// truncated and extended copies of a genuine payload; every shape of service
// string (the genuine one, another case, one with no KEK, arbitrary bytes,
// NULL) and of output buffer (any capacity, negative included; NULL `out`;
// NULL `out_len`). Every buffer is an allocation of exactly its length, so a
// read or write one byte outside it is an AddressSanitizer finding. Built
// only with -DHKDFGUARD_BUILD_FUZZERS=ON. See fuzz_abi.h.
//
// Input: version byte, Service, payload (ReadPayload), Call.
//
// Properties, beyond "no crash":
//   - Only the genuine payload ever unwraps, only under its own service
//     (in either case), and only to its DEK.
//   - Every failure zeroes the caller's declared buffer.
//   - The argument checks answer in the documented order: out_len, the
//     capacity's sign, the service name, the size (BUFFER_TOO_SMALL reports
//     32, and only below it), `out`.
//   - A payload that isn't 132 bytes of a known version and shape gets its
//     documented refusal, before any key is touched.
//   - Never INTERNAL_ERROR.
//
// Seeds: tests/fuzz/Make-AbiSeeds.ps1.
#include "fuzz_abi.h"

using namespace fuzz;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Setup("unwrap");
    In in{data, size};
    const int version = PickVersion(in);
    const Service service = Service::Read(in);
    const std::vector<uint8_t> payload = ReadPayload(in, version);
    const Call call = Call::Read(in);
    const World& w = TheWorld();

    const Ret ret = Unwrap(service, payload, call);
    CheckContract("unwrap_dek", ret, call, true);

    const bool genuine = w.have_kek[version] && payload == w.genuine[version];
    if (const auto verdict = ArgumentVerdict(service, call, HKDFGUARD_DEK_LEN, false)) {
        FUZZ_CHECK(ret.rc == *verdict, "unwrap_dek: the argument checks should return %d, got %d", *verdict, ret.rc);
        if (ret.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
            FUZZ_CHECK(ret.out_len == HKDFGUARD_DEK_LEN, "unwrap_dek: BUFFER_TOO_SMALL reported %d, not 32", ret.out_len.value_or(-1));
        } else if (ret.out_len.has_value()) {
            FUZZ_CHECK(*ret.out_len == call.cap, "unwrap_dek: a refused call changed *out_len from %d to %d", call.cap, *ret.out_len);
        }
        return 0;
    }

    // The arguments are in order: the answer is about the payload.
    FUZZ_CHECK(ret.rc != HKDFGUARD_ERR_INVALID_ARGUMENT && ret.rc != HKDFGUARD_ERR_INVALID_SERVICE_NAME &&
                   ret.rc != HKDFGUARD_ERR_BUFFER_TOO_SMALL,
               "unwrap_dek: well-formed arguments were refused with %d", ret.rc);
    if (payload.size() != HKDFGUARD_WRAPPED_MAX_LEN) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap_dek: a %zu-byte payload returned %d", payload.size(), ret.rc);
    } else if (payload[0] != 1 && payload[0] != 2) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED, "unwrap_dek: payload version %u returned %d", payload[0], ret.rc);
    } else if (!PayloadParses(payload)) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap_dek: a misshapen payload returned %d", ret.rc);
    } else if (payload[0] != version) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED, "unwrap_dek: a version %u payload under version %d returned %d",
                   payload[0], version, ret.rc);
    }

    if (ret.rc == HKDFGUARD_OK) {
        FUZZ_CHECK(genuine && service.is_fuzz(), "unwrap_dek: OK for %s",
                   genuine ? "the genuine payload under another service" : "a payload that isn't the genuine one");
        FUZZ_CHECK(ret.out_len == HKDFGUARD_DEK_LEN, "unwrap_dek: OK with *out_len %d", ret.out_len.value_or(-1));
        FUZZ_CHECK(std::memcmp(ret.buf.data(), w.dek, HKDFGUARD_DEK_LEN) == 0, "unwrap_dek: OK, but not the DEK that was wrapped");
        // Bytes past the DEK are the caller's, untouched.
        FUZZ_CHECK(std::all_of(ret.buf.begin() + HKDFGUARD_DEK_LEN, ret.buf.end(), [](uint8_t b) { return b == kFill; }),
                   "unwrap_dek: OK wrote past the 32 bytes of the DEK");
    } else if (genuine && service.is_fuzz()) {
        Fail("unwrap_dek: the genuine payload under its own service returned %d", ret.rc);
    }
    return 0;
}
