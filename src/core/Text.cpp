// Text.cpp — string hygiene for anything that leaves the process.
//
// UTF-8 validation is table driven: kLead[b] gives, for every lead byte, the
// total sequence length and the allowed range of the second byte (Unicode
// Standard, Table 3-7 "Well-Formed UTF-8 Byte Sequences"). That one table
// rejects overlong forms (C0, C1, E0 80..9F, F0 80..8F), UTF-16 surrogates
// (ED A0..BF) and code points above U+10FFFF (F4 90.., F5..FF). Remaining
// continuation bytes must be 80..BF. Anything else is escaped one byte at a
// time as "\xNN" so the output is always valid UTF-8, never aborts a JSON or
// YAML emitter, and still shows the examiner the exact bytes on disk.
#include "omnitrace/core/Text.h"

#include <cstddef>
#include <string_view>

#include "HostNames.h"

namespace omnitrace {

namespace {

struct LeadInfo {
    std::uint8_t len;  // total bytes in the sequence; 0 = never a lead byte
    std::uint8_t lo;   // allowed range of the second byte (inclusive)
    std::uint8_t hi;
};

constexpr LeadInfo lead_info(unsigned b) {
    if (b < 0x80) return {1, 0, 0};
    if (b < 0xC2) return {0, 0, 0};         // continuation or overlong 2-byte lead
    if (b < 0xE0) return {2, 0x80, 0xBF};   // C2..DF
    if (b == 0xE0) return {3, 0xA0, 0xBF};  // no overlong
    if (b < 0xED) return {3, 0x80, 0xBF};   // E1..EC
    if (b == 0xED) return {3, 0x80, 0x9F};  // no surrogates
    if (b < 0xF0) return {3, 0x80, 0xBF};   // EE..EF
    if (b == 0xF0) return {4, 0x90, 0xBF};  // no overlong
    if (b < 0xF4) return {4, 0x80, 0xBF};   // F1..F3
    if (b == 0xF4) return {4, 0x80, 0x8F};  // <= U+10FFFF
    return {0, 0, 0};                       // F5..FF
}

struct LeadTable {
    LeadInfo rows[256];
    constexpr LeadTable() : rows{} {
        for (unsigned b = 0; b < 256; ++b) rows[b] = lead_info(b);
    }
};

constexpr LeadTable kLead{};

constexpr bool is_continuation(std::uint8_t b) {
    return (b & 0xC0u) == 0x80u;
}

// Length of the well-formed sequence starting at in[i], or 0 when the bytes
// there are not a well-formed sequence (invalid lead, bad second byte, bad
// continuation, or truncated by the end of the input).
std::size_t well_formed_length(const std::uint8_t* in, std::size_t size, std::size_t i) {
    const LeadInfo li = kLead.rows[in[i]];
    if (li.len == 0) return 0;
    if (li.len == 1) return 1;
    if (size - i < li.len) return 0;
    if (in[i + 1] < li.lo || in[i + 1] > li.hi) return 0;
    for (std::size_t k = 2; k < li.len; ++k) {
        if (!is_continuation(in[i + k])) return 0;
    }
    return li.len;
}

constexpr bool is_allowed_control(std::uint8_t b) {
    return b == '\t' || b == '\n' || b == '\r';
}

void append_escape(std::string& out, std::uint8_t b) {
    static constexpr char kHex[] = "0123456789abcdef";
    out += "\\x";
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0Fu]);
}

std::string sanitize_bytes(const std::uint8_t* in, std::size_t size) {
    std::string out;
    out.reserve(size);
    std::size_t i = 0;
    while (i < size) {
        const std::uint8_t b = in[i];
        if (b < 0x80) {
            if (b < 0x20 && !is_allowed_control(b)) {
                append_escape(out, b);
            } else {
                out.push_back(static_cast<char>(b));
            }
            ++i;
            continue;
        }
        const std::size_t n = well_formed_length(in, size, i);
        if (n == 0) {
            append_escape(out, b);
            ++i;
            continue;
        }
        out.append(reinterpret_cast<const char*>(in + i), n);
        i += n;
    }
    return out;
}

bool clean_bytes(const std::uint8_t* in, std::size_t size) {
    std::size_t i = 0;
    while (i < size) {
        const std::uint8_t b = in[i];
        if (b < 0x80) {
            if (b < 0x20 && !is_allowed_control(b)) return false;
            ++i;
            continue;
        }
        const std::size_t n = well_formed_length(in, size, i);
        if (n == 0) return false;
        i += n;
    }
    return true;
}

void append_code_point(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else {
        out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
}

// Cut a valid UTF-8 string to at most max_len bytes without splitting a
// multi-byte sequence.
void trim_utf8(std::string& s, std::size_t max_len) {
    if (s.size() <= max_len) return;
    std::size_t cut = max_len;
    while (cut > 0 && is_continuation(static_cast<std::uint8_t>(s[cut]))) --cut;
    s.resize(cut);
}

constexpr bool is_reserved_filename_char(std::uint8_t c) {
    return c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' ||
           c == '>' || c == '|' || c < 0x20 || c == 0x7F;
}

}  // namespace

namespace detail {

// Windows treats these as devices in any directory, with or without an
// extension ("CON.txt" is still the console) and ignoring trailing spaces.
bool is_windows_reserved_name(std::string_view name) {
    std::string_view stem = name.substr(0, name.find('.'));
    while (!stem.empty() && stem.back() == ' ') stem.remove_suffix(1);
    if (stem.size() < 3 || stem.size() > 4) return false;
    char u[4] = {0, 0, 0, 0};
    for (std::size_t i = 0; i < stem.size(); ++i) {
        const char c = stem[i];
        u[i] = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
    }
    const std::string_view up(u, stem.size());
    if (up.size() == 3) return up == "CON" || up == "PRN" || up == "AUX" || up == "NUL";
    const bool digit = up[3] >= '1' && up[3] <= '9';
    return digit && (up.substr(0, 3) == "COM" || up.substr(0, 3) == "LPT");
}

}  // namespace detail

std::string sanitize_utf8(std::string_view in) {
    return sanitize_bytes(reinterpret_cast<const std::uint8_t*>(in.data()), in.size());
}

std::string sanitize_utf8(std::span<const std::uint8_t> in) {
    return sanitize_bytes(in.data(), in.size());
}

bool is_clean_utf8(std::string_view in) {
    return clean_bytes(reinterpret_cast<const std::uint8_t*>(in.data()), in.size());
}

std::string utf16le_to_utf8(std::span<const std::uint8_t> in) {
    std::string out;
    out.reserve(in.size());
    std::size_t i = 0;
    while (i + 1 < in.size()) {
        const std::uint32_t cu =
            static_cast<std::uint32_t>(in[i]) | (static_cast<std::uint32_t>(in[i + 1]) << 8);
        if (cu == 0) return sanitize_utf8(out);  // fixed-width fields are NUL padded
        if (cu >= 0xD800 && cu <= 0xDBFF && i + 3 < in.size()) {
            const std::uint32_t lo = static_cast<std::uint32_t>(in[i + 2]) |
                                     (static_cast<std::uint32_t>(in[i + 3]) << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                append_code_point(out, 0x10000u + ((cu - 0xD800u) << 10) + (lo - 0xDC00u));
                i += 4;
                continue;
            }
        }
        if (cu >= 0xD800 && cu <= 0xDFFF) {
            // Lone surrogate: not encodable, so show the raw bytes.
            append_escape(out, in[i]);
            append_escape(out, in[i + 1]);
        } else {
            append_code_point(out, cu);
        }
        i += 2;
    }
    // An odd trailing byte is not a code unit; keep it visible.
    if (i < in.size()) append_escape(out, in[i]);
    return sanitize_utf8(out);
}

std::string safe_filename_component(std::string_view in, std::size_t max_len) {
    std::string s = sanitize_utf8(in);
    for (char& ch : s) {
        if (is_reserved_filename_char(static_cast<std::uint8_t>(ch))) ch = '_';
    }
    // Collapse runs of '_' so "a///b" becomes "a_b", not "a___b".
    std::string collapsed;
    collapsed.reserve(s.size());
    for (const char ch : s) {
        if (ch == '_' && !collapsed.empty() && collapsed.back() == '_') continue;
        collapsed.push_back(ch);
    }
    s.swap(collapsed);
    // Leading dots would hide the entry or walk up ("..", ".hidden").
    std::size_t lead = 0;
    while (lead < s.size() && s[lead] == '.') ++lead;
    s.erase(0, lead);
    trim_utf8(s, max_len);
    // Trailing dots and spaces are stripped by Win32 and make "a." collide with "a".
    while (!s.empty() && (s.back() == '.' || s.back() == ' ')) s.pop_back();
    if (detail::is_windows_reserved_name(s)) {
        if (max_len > 0 && s.size() >= max_len) trim_utf8(s, max_len - 1);
        s.push_back('_');
    }
    if (s.empty()) return "unnamed";
    return s;
}

}  // namespace omnitrace
