// libFuzzer target for src/tpm_key_file.cpp's ParseTpmKeyFile: the parser
// of the version 2 TPM KEK's key file, whose bytes come from disk. Built
// only with -DHKDFGUARD_BUILD_FUZZERS=ON (tests/CMakeLists.txt), with
// AddressSanitizer.
//
// Properties:
//   - Any input is either accepted or refused with HKDFGUARD_ERR_KEK_INVALID;
//     no other exception, no memory error.
//   - An accepted file re-serializes to exactly the input (the format has
//     one encoding), and its public area is exactly the KEK template's.
//
// Seeds: tests/fuzz/corpus/fuzz_tpm_key_file.
#include "fuzz_common.h"
#include "errors.h"
#include "tpm_key_file.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace hkdfguard;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TpmKeyFile file;
    try {
        file = ParseTpmKeyFile(data, size);
    } catch (const HkdfGuardError &e) {
        FUZZ_REQUIRE(e.code() == HKDFGUARD_ERR_KEK_INVALID, "a refused key file is KEK_INVALID");
        return 0;
    } catch (...) {
        FUZZ_REQUIRE(false, "ParseTpmKeyFile throws only HkdfGuardError");
    }

    Bytes again;
    try {
        again = SerializeTpmKeyFile(file);
    } catch (...) {
        FUZZ_REQUIRE(false, "an accepted key file can be serialized");
    }
    FUZZ_REQUIRE(again.size() == size && std::memcmp(again.data(), data, size) == 0,
                 "an accepted key file re-serializes to exactly its bytes");

    try {
        FUZZ_REQUIRE(file.public_blob.size() >= 2, "the public blob carries its size");
        CheckTpmKekPublicArea(tpm2::ParsePublicArea(Bytes(file.public_blob.begin() + 2, file.public_blob.end())));
    } catch (...) {
        FUZZ_REQUIRE(false, "an accepted key file's public area is the KEK template's");
    }
    return 0;
}
