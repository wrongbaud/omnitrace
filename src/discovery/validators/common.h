// common.h — small helpers shared by the validators. Everything here works on
// Span accessors only; no raw pointer arithmetic over evidence bytes.
#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "omnitrace/discovery/Signature.h"

namespace omnitrace::discovery::validators {

inline Finding make_finding(const Signature& sig, std::uint64_t start, Confidence c) {
    Finding f;
    f.offset = start;
    f.format = sig.format;
    f.category = sig.category;
    f.signature = sig.name;
    f.confidence = c;
    f.endian = sig.endian.value_or(Endian::Little);
    return f;
}

inline void diag(Finding& f, Severity s, std::string code, std::string message) {
    f.diagnostics.push_back(Diagnostic{s, std::move(code), std::move(message)});
}

inline std::string hex(std::uint64_t v) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    if (v == 0) out = "0";
    while (v != 0) {
        out.insert(out.begin(), digits[v & 0xF]);
        v >>= 4;
    }
    return "0x" + out;
}

inline std::string hex_fixed(std::uint64_t v, unsigned width) {
    static const char* digits = "0123456789abcdef";
    std::string out(width, '0');
    for (unsigned i = 0; i < width; ++i) {
        out[width - 1 - i] = digits[v & 0xF];
        v >>= 4;
    }
    return "0x" + out;
}

inline std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

inline std::string hex_bytes(std::span<const std::uint8_t> b) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (const std::uint8_t x : b) {
        out.push_back(digits[x >> 4]);
        out.push_back(digits[x & 0xF]);
    }
    return out;
}

// 16 raw bytes -> 8-4-4-4-12 in storage order (ext4 s_uuid, UBI etc.).
inline std::string uuid_raw(std::span<const std::uint8_t> b) {
    if (b.size() != 16) return {};
    const std::string h = hex_bytes(b);
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) +
           "-" + h.substr(20, 12);
}

// 16 bytes in GPT/EFI mixed-endian layout -> canonical text.
inline std::string guid_mixed(std::span<const std::uint8_t> b) {
    if (b.size() != 16) return {};
    std::array<std::uint8_t, 16> c{};
    c[0] = b[3];
    c[1] = b[2];
    c[2] = b[1];
    c[3] = b[0];
    c[4] = b[5];
    c[5] = b[4];
    c[6] = b[7];
    c[7] = b[6];
    for (std::size_t i = 8; i < 16; ++i) c[i] = b[i];
    return uuid_raw(std::span<const std::uint8_t>(c.data(), c.size()));
}

// Optional integer from Signature::extra (TOML keys the schema does not name).
inline std::optional<std::uint64_t> extra_u64(const Signature& sig, const std::string& key) {
    const auto it = sig.extra.find(key);
    if (it == sig.extra.end()) return std::nullopt;
    std::uint64_t v = 0;
    for (const char ch : it->second) {
        if (ch < '0' || ch > '9') return std::nullopt;
        const std::uint64_t d = static_cast<std::uint64_t>(ch - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

// Bytes available from `start` to the end of the Span (0 if start is past it).
inline std::uint64_t remaining(const Span& span, std::uint64_t start) {
    return start > span.size() ? 0 : span.size() - start;
}

// Clamp a claimed structure size to the Span; reports whether clamping happened.
inline std::uint64_t clamp_size(const Span& span, std::uint64_t start, std::uint64_t claimed,
                                bool& truncated) {
    const std::uint64_t avail = remaining(span, start);
    truncated = claimed > avail;
    return truncated ? avail : claimed;
}

// Make a string safe for the "a:b:c;d:e:f" attr lists: drop control bytes and
// the two separators.
inline std::string list_safe(std::string_view s) {
    std::string out;
    for (const char ch : s) {
        const auto u = static_cast<unsigned char>(ch);
        if (u < 0x20 || u == 0x7F || ch == ':' || ch == ';')
            out.push_back('_');
        else
            out.push_back(ch);
    }
    return out;
}

inline bool all_bytes(std::span<const std::uint8_t> b, std::uint8_t v) {
    for (const std::uint8_t x : b)
        if (x != v) return false;
    return true;
}

inline bool is_pow2(std::uint64_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

}  // namespace omnitrace::discovery::validators
