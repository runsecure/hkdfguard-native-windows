// libFuzzer target for hkdfguard_open_file: arbitrary file contents (alone,
// or after a genuine payload) under every kind of file ACL, and arbitrary
// path strings - under every shape of output buffer, each an allocation of
// exactly its declared capacity. Built only with
// -DHKDFGUARD_BUILD_FUZZERS=ON. See fuzz_abi.h.
//
// Input: version byte, then
//   0: contents - bytes, ACL choice, "after a genuine payload" flag, Call
//   1: path     - bytes (the first NUL ends them), Call
//
// Properties, beyond "no crash":
//   - What is a key file is decided the same way by hkdfguard_open_file, by
//     the plaintext-key detector and by an independent restatement of the
//     payload's shape: exactly 132 bytes that parse are returned unchanged;
//     anything else gets its documented refusal.
//   - A file that another account may write is refused as untrusted,
//     whatever it holds, and before its contents matter.
//   - Every failure zeroes the caller's declared buffer; a refused file's
//     length never comes back through BUFFER_TOO_SMALL, which reports 132
//     and only below it.
//   - No arbitrary path opens as a key file; an empty or non-UTF-8 path is
//     INVALID_ARGUMENT.
//   - Never INTERNAL_ERROR.
//
// Seeds: tests/fuzz/Make-AbiSeeds.ps1.
#include "fuzz_abi.h"
#include "key_file.h" // LooksLikePlaintextKeyForTest

using namespace fuzz;

namespace {

struct FileAcl {
    const wchar_t* others; // ACEs added to SYSTEM, Administrators and this account
    bool trusted;
};

// Index 7 leaves the file with what it inherits from the harness's folder.
const FileAcl kAcls[] = {
    {L"", true},                    // this account, SYSTEM and Administrators only
    {L"(A;;0x1200a9;;;BU)", true},  // Users may read
    {L"(A;;FA;;;BU)", false},       // Users have full control
    {L"(A;;0x2;;;WD)", false},      // Everyone may write data
    {L"(A;;WD;;;AU)", false},       // Authenticated Users may rewrite the ACL
    {L"(A;;WO;;;AU)", false},       // Authenticated Users may take ownership
    {L"(A;;0x1200a9;;;WD)", true},  // Everyone may read
    {nullptr, true},                // inherited
};

// The checks hkdfguard_open_file makes before it opens anything, in order.
std::optional<int> ArgumentVerdictForPath(bool path_ok, const Call& call) {
    if (call.out_len_null || call.cap < 0 || !path_ok) return HKDFGUARD_ERR_INVALID_ARGUMENT;
    if (call.cap < HKDFGUARD_WRAPPED_MAX_LEN) return HKDFGUARD_ERR_BUFFER_TOO_SMALL;
    if (call.out_null) return HKDFGUARD_ERR_INVALID_ARGUMENT;
    return std::nullopt;
}

// Checks shared by both input kinds; true when the arguments decided the
// answer.
bool CheckArguments(const Ret& ret, bool path_ok, const Call& call) {
    CheckContract("open_file", ret, call, true);
    if (ret.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
        FUZZ_CHECK(call.cap < HKDFGUARD_WRAPPED_MAX_LEN && ret.out_len == HKDFGUARD_WRAPPED_MAX_LEN,
                   "open_file: BUFFER_TOO_SMALL for capacity %d reported %d", call.cap, ret.out_len.value_or(-1));
    }
    const auto verdict = ArgumentVerdictForPath(path_ok, call);
    if (!verdict.has_value()) return false;
    FUZZ_CHECK(ret.rc == *verdict, "open_file: the argument checks should return %d, got %d", *verdict, ret.rc);
    return true;
}

void Contents(In& in, int version) {
    const World& w = TheWorld();
    std::vector<uint8_t> content = in.blob();
    const size_t acl_index = in.u8() % (sizeof(kAcls) / sizeof(kAcls[0]));
    const FileAcl& acl = kAcls[acl_index];
    if (in.flag()) content.insert(content.begin(), w.genuine[version].begin(), w.genuine[version].end());
    const Call call = Call::Read(in);

    const std::wstring path = w.dir + L"\\key.bin";
    DeleteFileW(path.c_str()); // so the file starts from the folder's ACL every time
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written = 0;
    const bool wrote = file != INVALID_HANDLE_VALUE &&
                       (content.empty() || (WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) &&
                                            written == content.size()));
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    FUZZ_CHECK(wrote, "harness: could not write %ls (error %lu)", path.c_str(), GetLastError());
    if (acl.others != nullptr) {
        FUZZ_CHECK(SetDacl(path, L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + w.me + L")" + acl.others),
                   "harness: could not set the ACL of %ls", path.c_str());
    }

    const Exact c_path = CString(Narrow(path));
    const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) {
        return hkdfguard_open_file(reinterpret_cast<const char*>(c_path.data()), out, out_len);
    });
    DeleteFileW(path.c_str());
    if (CheckArguments(ret, true, call)) return;

    if (!acl.trusted) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_FILE_UNTRUSTED, "open_file: a file others may change (ACL %zu) returned %d", acl_index,
                   ret.rc);
        return;
    }
    const bool plaintext = hkdfguard::LooksLikePlaintextKeyForTest(content.data(), content.size());
    int expected = HKDFGUARD_OK;
    if (content.size() < HKDFGUARD_WRAPPED_MAX_LEN) {
        expected = plaintext ? HKDFGUARD_ERR_FILE_PLAINTEXT_KEY : HKDFGUARD_ERR_FILE_TOO_SHORT;
    } else if (content.size() > HKDFGUARD_WRAPPED_MAX_LEN) {
        expected = HKDFGUARD_ERR_FILE_TOO_LONG;
    } else if (!PayloadParses(content)) {
        expected = HKDFGUARD_ERR_FILE_MALFORMED;
    }
    FUZZ_CHECK(ret.rc == expected, "open_file: a %zu-byte file should return %d, got %d", content.size(), expected, ret.rc);
    // The detector itself: a key's size is always a key, and nothing the
    // size of a payload or more is.
    FUZZ_CHECK(content.size() != HKDFGUARD_DEK_LEN || plaintext, "the plaintext-key detector passed a 32-byte file");
    FUZZ_CHECK(content.size() < HKDFGUARD_WRAPPED_MAX_LEN || !plaintext, "the plaintext-key detector flagged a %zu-byte file",
               content.size());
    if (ret.rc == HKDFGUARD_OK) {
        FUZZ_CHECK(ret.out_len == HKDFGUARD_WRAPPED_MAX_LEN, "open_file: OK with *out_len %d", ret.out_len.value_or(-1));
        FUZZ_CHECK(std::equal(content.begin(), content.end(), ret.buf.begin()), "open_file: OK, but not the file's bytes");
        FUZZ_CHECK(std::all_of(ret.buf.begin() + HKDFGUARD_WRAPPED_MAX_LEN, ret.buf.end(), [](uint8_t b) { return b == kFill; }),
                   "open_file: OK wrote past the 132 bytes of the payload");
    }
}

void Path(In& in) {
    const std::vector<uint8_t> raw = in.blob();
    const Call call = Call::Read(in);
    const std::string text(raw.begin(), std::ranges::find(raw, uint8_t{0}));
    const Exact c_path = CString(text);
    const bool path_ok = !text.empty() &&
                         MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0) > 0;

    const Ret ret = WithBuffer(call, [&](uint8_t* out, int* out_len) {
        return hkdfguard_open_file(reinterpret_cast<const char*>(c_path.data()), out, out_len);
    });
    if (CheckArguments(ret, path_ok, call)) return;
    // Nothing the fuzzer can name is a key file: the harness's own is gone
    // by now, and anything else on the machine would have to be 132 bytes
    // that parse, in a folder chain only trusted accounts can change.
    FUZZ_CHECK(ret.rc != HKDFGUARD_OK, "open_file: an arbitrary path opened as a key file");
    FUZZ_CHECK(ret.rc != HKDFGUARD_ERR_INVALID_ARGUMENT && ret.rc != HKDFGUARD_ERR_BUFFER_TOO_SMALL,
               "open_file: well-formed arguments were refused with %d", ret.rc);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Setup("openfile");
    In in{data, size};
    const int version = PickVersion(in);
    if ((in.u8() & 1) == 0) {
        Contents(in, version);
    } else {
        Path(in);
    }
    return 0;
}
