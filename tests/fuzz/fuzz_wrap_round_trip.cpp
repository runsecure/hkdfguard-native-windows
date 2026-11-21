// libFuzzer target for the rest of the C ABI: hkdfguard_wrap_dek (any DEK
// length, NULL included), hkdfguard_generate_and_wrap_dek,
// hkdfguard_kek_exists, hkdfguard_kek_fingerprint, hkdfguard_security_model
// and hkdfguard_key_file_principal_trusted - under every shape of service
// string and output buffer. Every buffer is an allocation of exactly its
// length. Built only with -DHKDFGUARD_BUILD_FUZZERS=ON. See fuzz_abi.h.
//
// Input: version byte, Service, operation byte and its fields, Call.
//
// Properties, beyond "no crash":
//   - Whatever wrap produces is 132 bytes that parse, carry the KEK's
//     fingerprint, and unwrap to the same DEK under either spelling of the
//     service; two wraps of one DEK never give the same payload.
//   - Any failed wrap leaves the caller's buffer untouched; BUFFER_TOO_SMALL
//     asks for 132.
//   - A DEK that isn't 32 bytes, or is NULL, is INVALID_ARGUMENT - and a
//     DEK pointer with a wrong length is never read (it points at no bytes).
//   - kek_exists answers 1 for exactly the created KEK; the fingerprint is
//     the one payloads carry.
//   - The security model is the pinned one; SYSTEM, Administrators and this
//     account are trusted key file principals, Everyone is not; a failure
//     leaves the outputs unchanged.
//   - Never INTERNAL_ERROR.
//
// Seeds: tests/fuzz/Make-AbiSeeds.ps1.
#include "fuzz_abi.h"

using namespace fuzz;

namespace {

// Wraps `dek` for `service` into a generous buffer; the payload, or empty.
std::vector<uint8_t> WrapOk(const std::string& service, const uint8_t* dek) {
    std::vector<uint8_t> out(HKDFGUARD_WRAPPED_MAX_LEN);
    int len = HKDFGUARD_WRAPPED_MAX_LEN;
    if (hkdfguard_wrap_dek(service.c_str(), dek, HKDFGUARD_DEK_LEN, out.data(), &len) != HKDFGUARD_OK) return {};
    return out;
}

// What a payload this harness got back from a successful wrap must be.
void CheckWrapped(const char* what, const Ret& ret, int version, const uint8_t* dek) {
    const World& w = TheWorld();
    FUZZ_CHECK(ret.out_len == HKDFGUARD_WRAPPED_MAX_LEN, "%s: OK with *out_len %d", what, ret.out_len.value_or(-1));
    const std::vector<uint8_t> payload(ret.buf.begin(), ret.buf.begin() + HKDFGUARD_WRAPPED_MAX_LEN);
    FUZZ_CHECK(PayloadParses(payload) && payload[0] == version, "%s: produced a payload that doesn't parse as version %d", what,
               version);
    FUZZ_CHECK(std::equal(payload.begin() + hkdfguard::kFingerprintOffset, payload.end(),
                          w.genuine[version].begin() + hkdfguard::kFingerprintOffset),
               "%s: the payload doesn't carry the KEK's fingerprint", what);
    FUZZ_CHECK(std::all_of(ret.buf.begin() + HKDFGUARD_WRAPPED_MAX_LEN, ret.buf.end(), [](uint8_t b) { return b == kFill; }),
               "%s: OK wrote past the 132 bytes of the payload", what);
    for (const std::string& spelling : {w.service, w.service_upper}) {
        uint8_t back[HKDFGUARD_DEK_LEN] = {};
        int len = HKDFGUARD_DEK_LEN;
        const int rc = hkdfguard_unwrap_dek(spelling.c_str(), payload.data(), HKDFGUARD_WRAPPED_MAX_LEN, back, &len);
        FUZZ_CHECK(rc == HKDFGUARD_OK && len == HKDFGUARD_DEK_LEN, "%s: its payload doesn't unwrap under %s (rc %d)", what,
                   spelling.c_str(), rc);
        if (dek != nullptr) {
            FUZZ_CHECK(std::memcmp(back, dek, HKDFGUARD_DEK_LEN) == 0, "%s: its payload unwraps to a different DEK", what);
        }
    }
}

// Wrap and generate share everything after the DEK: the argument order, the
// buffer rules and what a success is.
void CheckWrapOutcome(const char* what, const Ret& ret, const Service& service, const Call& call, int version, const uint8_t* dek) {
    const World& w = TheWorld();
    CheckContract(what, ret, call, false);
    if (ret.rc != HKDFGUARD_OK) {
        FUZZ_CHECK(ret.untouched(), "%s: a failure (rc %d) wrote to the caller's buffer", what, ret.rc);
    }
    if (const auto verdict = ArgumentVerdict(service, call, HKDFGUARD_WRAPPED_MAX_LEN, true)) {
        FUZZ_CHECK(ret.rc == *verdict, "%s: the argument checks should return %d, got %d", what, *verdict, ret.rc);
        if (ret.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
            FUZZ_CHECK(ret.out_len == HKDFGUARD_WRAPPED_MAX_LEN, "%s: BUFFER_TOO_SMALL reported %d, not 132", what,
                       ret.out_len.value_or(-1));
        }
        return;
    }
    if (service.is_fuzz() && w.have_kek[version]) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_OK, "%s: returned %d for the service with a KEK", what, ret.rc);
        CheckWrapped(what, ret, version, dek);
    } else {
        FUZZ_CHECK(ret.rc != HKDFGUARD_OK, "%s: OK for a service with no KEK", what);
        FUZZ_CHECK(ret.rc != HKDFGUARD_ERR_INVALID_ARGUMENT && ret.rc != HKDFGUARD_ERR_INVALID_SERVICE_NAME &&
                       ret.rc != HKDFGUARD_ERR_BUFFER_TOO_SMALL,
                   "%s: well-formed arguments were refused with %d", what, ret.rc);
    }
}

void Wrap(In& in, const Service& service, int version) {
    const std::vector<uint8_t> dek = in.blob();
    const bool dek_null = in.flag();
    const Call call = Call::Read(in);
    const ServiceArg svc(service);
    // Exactly the DEK's bytes - and when the length is wrong, the library
    // must refuse without reading a single one of them.
    const Exact dek_buf(dek);
    const bool right_len = dek.size() == HKDFGUARD_DEK_LEN;
    const Exact nothing(0, 0);
    const uint8_t* dek_ptr = dek_null ? nullptr : (right_len ? dek_buf.data() : nothing.data());

    const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) {
        return hkdfguard_wrap_dek(svc.ptr, dek_ptr, static_cast<int>(dek.size()), out, out_len);
    });
    if (dek_null || !right_len) {
        CheckContract("wrap_dek", ret, call, false);
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "wrap_dek: a %s DEK of length %zu returned %d", dek_null ? "NULL" : "",
                   dek.size(), ret.rc);
        FUZZ_CHECK(ret.untouched(), "wrap_dek: a refused DEK wrote to the caller's buffer");
        return;
    }
    CheckWrapOutcome("wrap_dek", ret, service, call, version, dek.data());

    // Fresh salt and nonce every time: the same DEK never wraps to the same
    // payload twice.
    if (ret.rc == HKDFGUARD_OK) {
        const std::vector<uint8_t> again = WrapOk(TheWorld().service, dek.data());
        FUZZ_CHECK(!again.empty() && !std::equal(again.begin(), again.end(), ret.buf.begin()),
                   "wrap_dek: two wraps of one DEK gave the same payload");
    }
}

void Generate(In& in, const Service& service, int version) {
    const Call call = Call::Read(in);
    const ServiceArg svc(service);
    const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) { return hkdfguard_generate_and_wrap_dek(svc.ptr, out, out_len); });
    CheckWrapOutcome("generate_and_wrap_dek", ret, service, call, version, nullptr);
    if (ret.rc == HKDFGUARD_OK) {
        Ret second = WithBuffer(Call{HKDFGUARD_WRAPPED_MAX_LEN, false, false}, [&](uint8_t* out, int* out_len) {
            return hkdfguard_generate_and_wrap_dek(svc.ptr, out, out_len);
        });
        FUZZ_CHECK(second.rc == HKDFGUARD_OK && second.buf != std::vector<uint8_t>(ret.buf.begin(), ret.buf.begin() + HKDFGUARD_WRAPPED_MAX_LEN),
                   "generate_and_wrap_dek: two calls gave the same payload");
    }
}

void Exists(In& in, const Service& service, int version) {
    const bool out_null = in.flag();
    const ServiceArg svc(service);
    int exists = -7;
    const int rc = hkdfguard_kek_exists(svc.ptr, out_null ? nullptr : &exists);
    FUZZ_CHECK(rc != HKDFGUARD_ERR_INTERNAL_ERROR && rc <= 0, "kek_exists: returned %d", rc);
    if (out_null) {
        FUZZ_CHECK(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "kek_exists: a NULL out_exists returned %d", rc);
    } else if (!service.valid()) {
        FUZZ_CHECK(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "kek_exists: an invalid service name returned %d", rc);
    } else if (rc == HKDFGUARD_OK) {
        const bool expected = service.is_fuzz() && TheWorld().have_kek[version];
        FUZZ_CHECK(exists == (expected ? 1 : 0), "kek_exists: answered %d, expected %d", exists, expected ? 1 : 0);
    } else {
        FUZZ_CHECK(!(service.is_fuzz() && TheWorld().have_kek[version]), "kek_exists: returned %d for the created KEK", rc);
    }
    if (rc != HKDFGUARD_OK) {
        FUZZ_CHECK(exists == -7, "kek_exists: a failure (rc %d) wrote *out_exists", rc);
    }
}

void Fingerprint(In& in, const Service& service, int version) {
    const Call call = Call::Read(in);
    const ServiceArg svc(service);
    const World& w = TheWorld();
    const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) { return hkdfguard_kek_fingerprint(svc.ptr, out, out_len); });
    CheckContract("kek_fingerprint", ret, call, false);
    if (ret.rc != HKDFGUARD_OK) {
        FUZZ_CHECK(ret.untouched(), "kek_fingerprint: a failure (rc %d) wrote to the caller's buffer", ret.rc);
    }
    if (const auto verdict = ArgumentVerdict(service, call, HKDFGUARD_KEK_FINGERPRINT_LEN, true)) {
        FUZZ_CHECK(ret.rc == *verdict, "kek_fingerprint: the argument checks should return %d, got %d", *verdict, ret.rc);
        if (ret.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
            FUZZ_CHECK(ret.out_len == HKDFGUARD_KEK_FINGERPRINT_LEN, "kek_fingerprint: BUFFER_TOO_SMALL reported %d, not 32",
                       ret.out_len.value_or(-1));
        }
        return;
    }
    if (service.is_fuzz() && w.have_kek[version]) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_OK && ret.out_len == HKDFGUARD_KEK_FINGERPRINT_LEN, "kek_fingerprint: returned %d, length %d",
                   ret.rc, ret.out_len.value_or(-1));
        FUZZ_CHECK(std::equal(ret.buf.begin(), ret.buf.begin() + HKDFGUARD_KEK_FINGERPRINT_LEN,
                              w.genuine[version].begin() + hkdfguard::kFingerprintOffset),
                   "kek_fingerprint: not the fingerprint the KEK's payloads carry");
    } else {
        FUZZ_CHECK(ret.rc != HKDFGUARD_OK, "kek_fingerprint: OK for a service with no KEK");
    }
}

void SecurityModel(In& in) {
    const bool model_null = in.flag();
    const bool may_write_null = in.flag();
    int model = -7;
    int may_write = -7;
    const int rc = hkdfguard_security_model(model_null ? nullptr : &model, may_write_null ? nullptr : &may_write);
    if (model_null || may_write_null) {
        FUZZ_CHECK(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "security_model: a NULL output returned %d", rc);
        FUZZ_CHECK(model == -7 && may_write == -7, "security_model: a refused call wrote an output");
    } else {
        FUZZ_CHECK(rc == HKDFGUARD_OK && model == HKDFGUARD_SECURITY_MODEL_DEVELOPER && may_write == 1,
                   "security_model: returned %d, model %d, may_write %d under the developer model", rc, model, may_write);
    }
}

void Principal(In& in) {
    const std::vector<uint8_t> raw = in.blob();
    const bool out_null = in.flag();
    const std::string text(raw.begin(), std::ranges::find(raw, uint8_t{0}));
    const Exact sid = CString(text);
    int trusted = -7;
    const int rc = hkdfguard_key_file_principal_trusted(reinterpret_cast<const char*>(sid.data()), out_null ? nullptr : &trusted);
    FUZZ_CHECK(rc == HKDFGUARD_OK || rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "key_file_principal_trusted: \"%s\" returned %d",
               text.c_str(), rc);
    if (rc != HKDFGUARD_OK) {
        FUZZ_CHECK(trusted == -7, "key_file_principal_trusted: a failure wrote *out_trusted");
        FUZZ_CHECK(out_null || (text != "S-1-5-18" && text != "S-1-5-32-544" && text != "S-1-1-0"),
                   "key_file_principal_trusted: refused the SID \"%s\"", text.c_str());
        return;
    }
    FUZZ_CHECK(!out_null && (trusted == 0 || trusted == 1), "key_file_principal_trusted: OK with *out_trusted %d", trusted);
    FUZZ_CHECK(text.size() < 256, "key_file_principal_trusted: accepted a %zu-byte string", text.size());
    const std::string me = Narrow(TheWorld().me);
    if (text == "S-1-5-18" || text == "S-1-5-32-544" || text == me) {
        FUZZ_CHECK(trusted == 1, "key_file_principal_trusted: %s is not trusted under the developer model", text.c_str());
    }
    if (text == "S-1-1-0" || text == "S-1-5-11" || text == "S-1-5-32-545") {
        FUZZ_CHECK(trusted == 0, "key_file_principal_trusted: the over-broad %s is trusted", text.c_str());
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Setup("wrap");
    In in{data, size};
    const int version = PickVersion(in);
    const Service service = Service::Read(in);
    switch (in.u8() % 6) {
        case 0: Wrap(in, service, version); break;
        case 1: Generate(in, service, version); break;
        case 2: Exists(in, service, version); break;
        case 3: Fingerprint(in, service, version); break;
        case 4: SecurityModel(in); break;
        default: Principal(in); break;
    }
    return 0;
}
