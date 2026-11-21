// libFuzzer target for the C ABI under concurrency: up to four threads at
// once, each a sequence of create_kek, kek_exists, kek_fingerprint, wrap,
// unwrap (genuine and corrupted payloads, short buffers), generate,
// open_file and key_file_principal_trusted. Every thread owns its buffers,
// each an allocation of exactly its length. Built only with
// -DHKDFGUARD_BUILD_FUZZERS=ON. See fuzz_abi.h.
//
// Input: version byte, thread count, then per thread an operation count and
// its operations.
//
// Properties, beyond "no crash":
//   - Every thread gets the answer the call gets alone: its own DEK back and
//     never another thread's, a fingerprint that doesn't change, no KEK
//     appearing for a service without one, the key file's own bytes.
//   - Under AddressSanitizer, a use after free or a stale pointer in the
//     state the calls share is a finding.
//
// Seeds: tests/fuzz/Make-AbiSeeds.ps1.
#include "fuzz_abi.h"

#include <atomic>
#include <thread>

using namespace fuzz;

namespace {

struct Op {
    uint8_t kind = 0;
    uint8_t byte = 0;
    bool flag = false;
    int16_t cap = 0;
    uint16_t offset = 0;
};

constexpr uint8_t kOpKinds = 10;

Op ReadOp(In& in) {
    Op op;
    op.kind = in.u8() % kOpKinds;
    switch (op.kind) {
        case 1: op.flag = in.flag(); break;                      // exists: the other service?
        case 3: op.byte = in.u8(); op.flag = in.flag(); break;   // wrap and unwrap: DEK byte, upper-case service?
        case 5: op.cap = in.i16(); break;                        // unwrap the genuine payload into `cap` bytes
        case 6: op.offset = in.u16(); op.byte = in.u8(); break;  // unwrap a patched payload
        case 7: op.cap = in.i16(); break;                        // open the genuine key file into `cap` bytes
        default: break;
    }
    return op;
}

Service Named(Service::Kind kind) {
    Service s;
    s.kind = kind;
    return s;
}

// What a buffer-taking call must answer for the genuine input, by capacity.
void CheckByCapacity(const char* what, const Ret& ret, int cap, int needed, bool works, const uint8_t* expected) {
    if (cap < 0) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "%s: capacity %d returned %d", what, cap, ret.rc);
    } else if (cap < needed) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL && ret.out_len == needed, "%s: capacity %d returned %d, *out_len %d", what,
                   cap, ret.rc, ret.out_len.value_or(-1));
    } else if (works) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_OK && ret.out_len == needed, "%s: returned %d, *out_len %d", what, ret.rc,
                   ret.out_len.value_or(-1));
        FUZZ_CHECK(std::memcmp(ret.buf.data(), expected, static_cast<size_t>(needed)) == 0, "%s: OK, but with another call's bytes",
                   what);
    } else {
        FUZZ_CHECK(ret.rc != HKDFGUARD_OK, "%s: OK with no KEK", what);
    }
}

void Run(const Op& op, int version) {
    const World& w = TheWorld();
    const bool kek = w.have_kek[version];
    switch (op.kind) {
        case 0: {
            const int rc = hkdfguard_create_kek(w.service.c_str());
            FUZZ_CHECK((rc == HKDFGUARD_OK) == kek, "threads: create_kek returned %d", rc);
            break;
        }
        case 1: {
            int exists = -7;
            const int rc = hkdfguard_kek_exists(op.flag ? w.other.c_str() : w.service.c_str(), &exists);
            if (rc == HKDFGUARD_OK) {
                FUZZ_CHECK(exists == ((!op.flag && kek) ? 1 : 0), "threads: kek_exists answered %d for %s", exists,
                           op.flag ? "a service with no KEK" : "the service");
            } else {
                FUZZ_CHECK(op.flag || !kek, "threads: kek_exists returned %d for the created KEK", rc);
            }
            break;
        }
        case 2: {
            const Call call{HKDFGUARD_KEK_FINGERPRINT_LEN, false, false};
            const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) {
                return hkdfguard_kek_fingerprint(w.service.c_str(), out, out_len);
            });
            CheckContract("threads: kek_fingerprint", ret, call, false);
            CheckByCapacity("threads: kek_fingerprint", ret, call.cap, HKDFGUARD_KEK_FINGERPRINT_LEN, kek,
                            w.genuine[version].data() + hkdfguard::kFingerprintOffset);
            break;
        }
        case 3: {
            // A DEK only this operation knows: what comes back must be it.
            const Exact dek(HKDFGUARD_DEK_LEN, op.byte);
            const Call call{HKDFGUARD_WRAPPED_MAX_LEN, false, false};
            const Ret wrapped = WithBuffer(call, [&](uint8_t* out, int* out_len) {
                return hkdfguard_wrap_dek(w.service.c_str(), dek.data(), HKDFGUARD_DEK_LEN, out, out_len);
            });
            CheckContract("threads: wrap_dek", wrapped, call, false);
            FUZZ_CHECK((wrapped.rc == HKDFGUARD_OK) == kek, "threads: wrap_dek returned %d", wrapped.rc);
            if (wrapped.rc != HKDFGUARD_OK) break;
            const Call out{HKDFGUARD_DEK_LEN, false, false};
            const Ret back = Unwrap(Named(op.flag ? Service::Kind::Upper : Service::Kind::Fuzz), wrapped.buf, out);
            CheckContract("threads: unwrap_dek", back, out, true);
            CheckByCapacity("threads: unwrap of this thread's payload", back, out.cap, HKDFGUARD_DEK_LEN, true, dek.data());
            break;
        }
        case 4: {
            const Call call{HKDFGUARD_WRAPPED_MAX_LEN, false, false};
            const Ret wrapped = WithBuffer(call, [&](uint8_t* out, int* out_len) {
                return hkdfguard_generate_and_wrap_dek(w.service.c_str(), out, out_len);
            });
            CheckContract("threads: generate_and_wrap_dek", wrapped, call, false);
            FUZZ_CHECK((wrapped.rc == HKDFGUARD_OK) == kek, "threads: generate_and_wrap_dek returned %d", wrapped.rc);
            if (wrapped.rc != HKDFGUARD_OK) break;
            const Call out{HKDFGUARD_DEK_LEN, false, false};
            const Ret back = Unwrap(Named(Service::Kind::Fuzz), wrapped.buf, out);
            FUZZ_CHECK(back.rc == HKDFGUARD_OK, "threads: a generated payload doesn't unwrap (rc %d)", back.rc);
            break;
        }
        case 5: {
            const Call call{op.cap, false, false};
            const Ret ret = Unwrap(Named(Service::Kind::Fuzz), w.genuine[version], call);
            CheckContract("threads: unwrap_dek", ret, call, true);
            CheckByCapacity("threads: unwrap of the genuine payload", ret, call.cap, HKDFGUARD_DEK_LEN, kek, w.dek);
            break;
        }
        case 6: {
            std::vector<uint8_t> patched = w.genuine[version];
            patched[op.offset % patched.size()] ^= op.byte;
            const Call call{HKDFGUARD_DEK_LEN, false, false};
            const Ret ret = Unwrap(Named(Service::Kind::Fuzz), patched, call);
            CheckContract("threads: unwrap_dek", ret, call, true);
            if (op.byte == 0) {
                CheckByCapacity("threads: unwrap of the genuine payload", ret, call.cap, HKDFGUARD_DEK_LEN, kek, w.dek);
            } else {
                FUZZ_CHECK(ret.rc != HKDFGUARD_OK, "threads: a corrupted payload unwrapped");
            }
            break;
        }
        case 7: {
            const Call call{op.cap, false, false};
            const Exact path = CString(GenuineKeyFile());
            const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) {
                return hkdfguard_open_file(reinterpret_cast<const char*>(path.data()), out, out_len);
            });
            CheckContract("threads: open_file", ret, call, true);
            CheckByCapacity("threads: open_file", ret, call.cap, HKDFGUARD_WRAPPED_MAX_LEN, true, w.genuine[2].data());
            break;
        }
        case 8: {
            const Exact dek(HKDFGUARD_DEK_LEN, 0x5A);
            const Call call{HKDFGUARD_WRAPPED_MAX_LEN, false, false};
            const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) {
                return hkdfguard_wrap_dek(w.other.c_str(), dek.data(), HKDFGUARD_DEK_LEN, out, out_len);
            });
            CheckContract("threads: wrap_dek", ret, call, false);
            FUZZ_CHECK(ret.rc != HKDFGUARD_OK && ret.untouched(), "threads: wrap for a service with no KEK returned %d", ret.rc);
            break;
        }
        default: {
            int trusted = -7;
            const int rc = hkdfguard_key_file_principal_trusted("S-1-5-32-544", &trusted);
            FUZZ_CHECK(rc == HKDFGUARD_OK && trusted == 1, "threads: Administrators returned %d, trusted %d", rc, trusted);
            break;
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Setup("threads");
    GenuineKeyFile(); // written before any thread needs it
    In in{data, size};
    const int version = PickVersion(in);

    const size_t thread_count = 1 + in.u8() % 4;
    std::vector<std::vector<Op>> plans(thread_count);
    for (auto& plan : plans) {
        const size_t ops = in.u8() % 17;
        for (size_t i = 0; i < ops; ++i) plan.push_back(ReadOp(in));
    }

    std::atomic<size_t> ready{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (const auto& plan : plans) {
        threads.emplace_back([&plan, &ready, &go, version] {
            ++ready;
            while (!go.load()) std::this_thread::yield();
            for (const Op& op : plan) Run(op, version);
        });
    }
    while (ready.load() < thread_count) std::this_thread::yield();
    go = true;
    for (auto& t : threads) t.join();
    return 0;
}
