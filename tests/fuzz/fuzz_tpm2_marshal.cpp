// libFuzzer target for src/tpm2_marshal.cpp's response parsers, built only
// with -DHKDFGUARD_BUILD_FUZZERS=ON (tests/CMakeLists.txt), with
// AddressSanitizer. The first input byte picks which command's response the
// rest is parsed as, so one corpus covers every parser; ParsePublicArea also
// sees the raw input. A parser may only return or throw HkdfGuardError -
// anything else, or any memory error, is a finding.
//
// Run, for example, with a corpus folder: fuzz_tpm2_marshal.exe -max_total_time=600 corpus
#include "tpm2_marshal.h"
#include "errors.h"

#include <cstddef>
#include <cstdint>

using namespace hkdfguard::tpm2;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    const uint8_t selector = data[0];
    const uint8_t *body = data + 1;
    const size_t body_size = size - 1;

    try {
        ParsePublicArea(Bytes(body, body + body_size));
    } catch (const hkdfguard::HkdfGuardError &) {
    }

    try {
        bool more = false;
        switch (selector % 9) {
            case 0: { Response r = ParseResponse(body, body_size, 0, 0); if (r.response_code == 0) ParseReadPublic(r); break; }
            case 1: { Response r = ParseResponse(body, body_size, 0, 0); if (r.response_code == 0) ParseCapabilityHandles(r, more); break; }
            case 2: { Response r = ParseResponse(body, body_size, 0, 0); if (r.response_code == 0) ParseCapabilityProperties(r, more); break; }
            case 3: { Response r = ParseResponse(body, body_size, 1, 0); if (r.response_code == 0) ParseStartAuthSession(r); break; }
            case 4: { Response r = ParseResponse(body, body_size, 0, 1); if (r.response_code == 0) ParseCreate(r); break; }
            case 5: { Response r = ParseResponse(body, body_size, 1, 1); if (r.response_code == 0) ParseLoad(r); break; }
            case 6: { Response r = ParseResponse(body, body_size, 1, 0); if (r.response_code == 0) ParseLoad(r); break; }
            case 7: { Response r = ParseResponse(body, body_size, 0, 1); if (r.response_code == 0) ParseHmac(r); break; }
            default: ParseResponse(body, body_size, 0, 0); break; // FlushContext and the header alone
        }
    } catch (const hkdfguard::HkdfGuardError &) {
    }
    return 0;
}
