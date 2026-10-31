#include "sp800_108.h"
#include "errors.h"

#include <cstring> // strlen

namespace hkdfguard {
    namespace {
        void AppendU32BigEndian(std::vector<uint8_t> &out, uint32_t v) {
            out.push_back(static_cast<uint8_t>(v >> 24));
            out.push_back(static_cast<uint8_t>(v >> 16));
            out.push_back(static_cast<uint8_t>(v >> 8));
            out.push_back(static_cast<uint8_t>(v));
        }
    } // namespace

    std::vector<uint8_t> Sp800108Block(uint32_t counter, const char *label, const uint8_t *context, size_t context_len) {
        const size_t label_len = std::strlen(label);
        std::vector<uint8_t> block;
        block.reserve(4 + label_len + 1 + context_len + 4);
        AppendU32BigEndian(block, counter);            // [i]_32
        block.insert(block.end(), label, label + label_len);
        block.push_back(0x00);                         // separates Label from Context
        if (context_len != 0) {
            block.insert(block.end(), context, context + context_len);
        }
        AppendU32BigEndian(block, kKdfOutputBits);     // [L]_32
        return block;
    }

    std::vector<uint8_t> FingerprintBlock(uint32_t counter) {
        return Sp800108Block(counter, kFingerprintLabel, nullptr, 0);
    }

    std::vector<uint8_t> WrapContext(const std::string &service, const uint8_t *header, size_t header_len) {
        if (service.empty() || service.size() > 0xFFFF) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "service name can't be framed in the KDF context");
        }
        std::vector<uint8_t> context;
        context.reserve(2 + service.size() + header_len);
        // u16_le(len(service)): unambiguous framing for the variable-length
        // name, so no two (service, header) pairs give the same block.
        context.push_back(static_cast<uint8_t>(service.size() & 0xFF));
        context.push_back(static_cast<uint8_t>((service.size() >> 8) & 0xFF));
        context.insert(context.end(), service.begin(), service.end());
        context.insert(context.end(), header, header + header_len);
        return context;
    }

    std::vector<uint8_t> WrapBlock(uint32_t counter, const std::string &service, const uint8_t *header, size_t header_len) {
        const std::vector<uint8_t> context = WrapContext(service, header, header_len);
        return Sp800108Block(counter, kWrapLabel, context.data(), context.size());
    }
} // namespace hkdfguard
