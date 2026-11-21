// The fuzz harnesses' stand-in for src/event_log.cpp: every audit event is
// dropped. The ABI targets make millions of failing calls, each of which the
// library would otherwise write to the Application event log. The arguments
// are still read, so a bad pointer passed to the logger is still a finding
// under AddressSanitizer.
#include "event_log.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace hkdfguard {
    namespace {
        std::atomic<uint64_t> g_sink{0};

        void Touch(const void *bytes, size_t len) noexcept {
            uint64_t sum = 0;
            const auto *p = static_cast<const uint8_t *>(bytes);
            for (size_t i = 0; i < len; ++i) {
                sum += p[i];
            }
            g_sink += sum;
        }
    } // namespace

    void LogKekCreated(const std::wstring &service, uint8_t providerType, int32_t tpmFallbackCode) noexcept {
        Touch(service.data(), service.size() * sizeof(wchar_t));
        g_sink += static_cast<uint64_t>(providerType) + static_cast<uint64_t>(tpmFallbackCode);
    }

    void LogVersion2Unavailable(const std::wstring &service, const std::string &reason) noexcept {
        Touch(service.data(), service.size() * sizeof(wchar_t));
        Touch(reason.data(), reason.size());
    }

    void LogDekOperation(AuditOp op, const std::string &service, uint8_t providerType, uint8_t payloadVersion,
                         const uint8_t *kekFingerprint, const uint8_t *payload, size_t payloadLen) noexcept {
        Touch(service.data(), service.size());
        Touch(kekFingerprint, 32);
        Touch(payload, payloadLen);
        g_sink += static_cast<uint64_t>(op) + providerType + payloadVersion;
    }

    void LogOperationFailure(AuditOp op, const std::string &service, int32_t code) noexcept {
        Touch(service.data(), service.size());
        g_sink += static_cast<uint64_t>(op) + static_cast<uint64_t>(code);
    }

    void LogPlaintextKeyFile(const std::wstring &path) noexcept {
        Touch(path.data(), path.size() * sizeof(wchar_t));
    }

    void LogSetupCallsExceeded(unsigned long calls, unsigned long floor_ms) noexcept {
        g_sink += calls + floor_ms;
    }

    void LogDeveloperModeKeyFile() noexcept {
        ++g_sink;
    }
} // namespace hkdfguard
