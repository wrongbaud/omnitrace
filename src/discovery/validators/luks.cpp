// luks.cpp — LUKS1 / LUKS2 encrypted-volume header validator.
//
// LUKS1 (592-byte header, big-endian integers; cryptsetup LUKS1 on-disk spec):
//    0 magic "LUKS\xba\xbe"   6 version u16 (1)   8 cipher-name[32]
//   40 cipher-mode[32]        72 hash-spec[32]   104 payload-offset u32 (sectors)
//  108 key-bytes u32         112 mk-digest[20]   132 mk-digest-salt[32]
//  164 mk-digest-iter u32    168 uuid[40]        208 key-slots 8 x 48:
//      active u32 (0x00AC71F3 enabled / 0x0000DEAD disabled), iterations u32,
//      salt[32], key-material-offset u32 (sectors), stripes u32
// LUKS2 (4096-byte binary header + JSON area, both repeated as a secondary
// header at hdr_size; cryptsetup LUKS2 on-disk format):
//    0 magic ("LUKS\xba\xbe" primary, "SKUL\xba\xbe" secondary)  6 version u16 (2)
//    8 hdr_size u64  16 seqid u64  24 label[48]  72 csum_alg[32]  104 salt[64]
//  168 uuid[40]  208 subsystem[48]  256 hdr_offset u64  264 pad[184]  448 csum[64]
// The JSON area (hdr_size - 4096 bytes) holds the cipher and payload layout.
// Nothing here can decrypt anything: the finding tells the examiner that a
// region is encrypted and how, so it lands in the coverage table.
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kSlotEnabled = 0x00AC71F3u, kSlotDisabled = 0x0000DEADu;
constexpr std::uint64_t kLuks2BinaryHeader = 4096;
constexpr std::uint64_t kDefaultMaxJson = 4u << 20;

// NUL-padded ASCII field; nullopt when it holds bytes a LUKS token never has.
std::optional<std::string> token(const Span& span, std::uint64_t off, std::size_t width,
                                 bool allow_empty) {
    const auto s = span.cstring(off, width);
    if (!s) return std::nullopt;
    if (s->empty()) return allow_empty ? std::optional<std::string>("") : std::nullopt;
    for (const char c : *s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ':' || c == '.' ||
                        c == '+' || c == ' ';
        if (!ok) return std::nullopt;
    }
    return s;
}

bool uuid_text_ok(const std::string& s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

// Value of the first "key":"value" pair at or after `from` in `json`.
std::optional<std::string> json_string(const std::string& json, const std::string& key,
                                       std::size_t from = 0) {
    const std::string pat = "\"" + key + "\"";
    std::size_t p = json.find(pat, from);
    if (p == std::string::npos) return std::nullopt;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return std::nullopt;
    p = json.find('"', p);
    if (p == std::string::npos) return std::nullopt;
    const std::size_t e = json.find('"', p + 1);
    if (e == std::string::npos) return std::nullopt;
    return list_safe(json.substr(p + 1, e - p - 1));
}

std::optional<Finding> luks1(const Span& span, std::uint64_t start, Finding f) {
    const auto cipher = token(span, start + 8, 32, false);
    const auto mode = token(span, start + 40, 32, false);
    const auto hash = token(span, start + 72, 32, false);
    const auto payload_offset = span.at<std::uint32_t>(start + 104, Endian::Big);
    const auto key_bytes = span.at<std::uint32_t>(start + 108, Endian::Big);
    const auto iterations = span.at<std::uint32_t>(start + 164, Endian::Big);
    const auto uuid = span.cstring(start + 168, 40);
    if (!cipher || !mode || !hash || !uuid) {
        diag(f, Severity::Warning, "luks-bad-header",
             "cipher, mode, hash or uuid field is not a printable token");
        return f;
    }
    if (!payload_offset || !key_bytes || !iterations) {
        diag(f, Severity::Warning, "luks-truncated-header",
             "fewer than 592 bytes available for the LUKS1 header");
        return f;
    }
    if (*payload_offset == 0 || *key_bytes == 0 || *key_bytes > 4096) {
        diag(f, Severity::Warning, "luks-bad-header",
             "payload offset " + dec(*payload_offset) + " or key size " + dec(*key_bytes) +
                 " out of range");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["version"] = "1";
    f.attrs["cipher"] = *cipher;
    f.attrs["mode"] = *mode;
    f.attrs["hash"] = *hash;
    f.attrs["key_bits"] = dec(static_cast<std::uint64_t>(*key_bytes) * 8);
    f.attrs["payload_offset"] = dec(static_cast<std::uint64_t>(*payload_offset) * 512);
    f.attrs["payload_offset_sectors"] = dec(*payload_offset);
    f.attrs["mk_digest_iterations"] = dec(*iterations);
    f.attrs["uuid"] = list_safe(*uuid);
    if (!uuid_text_ok(*uuid))
        diag(f, Severity::Info, "luks-bad-uuid", "uuid field is not in 8-4-4-4-12 form");

    // Key slots: every slot enabled or disabled, key material before the payload.
    std::uint64_t enabled = 0;
    bool slots_ok = true;
    for (std::uint64_t s = 0; s < 8; ++s) {
        const std::uint64_t so = start + 208 + s * 48;
        const auto active = span.at<std::uint32_t>(so, Endian::Big);
        const auto km = span.at<std::uint32_t>(so + 40, Endian::Big);
        const auto stripes = span.at<std::uint32_t>(so + 44, Endian::Big);
        if (!active || !km || !stripes) {
            slots_ok = false;
            break;
        }
        if (*active == kSlotEnabled) {
            ++enabled;
            if (*km >= *payload_offset || *stripes == 0) slots_ok = false;
        } else if (*active != kSlotDisabled) {
            slots_ok = false;
        }
    }
    f.attrs["key_slots_enabled"] = dec(enabled);
    bool truncated = false;
    f.size = clamp_size(span, start, static_cast<std::uint64_t>(*payload_offset) * 512, truncated);
    if (truncated)
        diag(f, Severity::Warning, "luks-truncated",
             "header area (" + dec(static_cast<std::uint64_t>(*payload_offset) * 512) +
                 " bytes to the payload) extends past the available data");
    if (!slots_ok)
        diag(f, Severity::Warning, "luks-bad-keyslots",
             "a key slot has an unknown state or key material past the payload offset");
    else if (uuid_text_ok(*uuid))
        f.confidence = Confidence::Consistent;
    f.evidence = "LUKS1 " + *cipher + "-" + *mode + " (" + *hash + "), " + dec(enabled) +
                 " key slot(s) enabled, payload at sector " + dec(*payload_offset);
    return f;
}

std::optional<Finding> luks2(const Span& span, std::uint64_t start, const Signature& sig,
                             Finding f) {
    const auto hdr_size = span.at<std::uint64_t>(start + 8, Endian::Big);
    const auto seqid = span.at<std::uint64_t>(start + 16, Endian::Big);
    const auto label = token(span, start + 24, 48, true);
    const auto csum_alg = token(span, start + 72, 32, false);
    const auto uuid = span.cstring(start + 168, 40);
    const auto subsystem = token(span, start + 208, 48, true);
    const auto hdr_offset = span.at<std::uint64_t>(start + 256, Endian::Big);
    if (!hdr_size || !seqid || !hdr_offset || !uuid) {
        diag(f, Severity::Warning, "luks-truncated-header",
             "fewer than 4096 bytes available for the LUKS2 binary header");
        return f;
    }
    if (!csum_alg || !label || !subsystem) {
        diag(f, Severity::Warning, "luks-bad-header", "checksum algorithm or label is not a token");
        return f;
    }
    if (!is_pow2(*hdr_size) || *hdr_size < 16384 || *hdr_size > (4u << 20)) {
        diag(f, Severity::Warning, "luks-bad-hdr-size",
             "hdr_size " + dec(*hdr_size) + " is not a power of two in 16 KiB..4 MiB");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["version"] = "2";
    f.attrs["hdr_size"] = dec(*hdr_size);
    f.attrs["seqid"] = dec(*seqid);
    f.attrs["checksum_alg"] = *csum_alg;
    if (!label->empty()) f.attrs["label"] = *label;
    if (!subsystem->empty()) f.attrs["subsystem"] = *subsystem;
    f.attrs["uuid"] = list_safe(*uuid);
    f.attrs["hdr_offset"] = dec(*hdr_offset);
    const std::uint64_t claimed = *hdr_size * 2;
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated)
        diag(f, Severity::Warning, "luks-truncated",
             "primary and secondary headers (" + dec(claimed) + " bytes) extend past the data");

    // JSON area: cipher and payload offset live in the segments object.
    const std::uint64_t json_cap = extra_u64(sig, "max_json").value_or(kDefaultMaxJson);
    const std::uint64_t json_len = std::min(
        {*hdr_size - kLuks2BinaryHeader, json_cap, remaining(span, start + kLuks2BinaryHeader)});
    const auto json = span.cstring(start + kLuks2BinaryHeader, static_cast<std::size_t>(json_len));
    bool json_ok = false;
    if (json && !json->empty() && (*json)[0] == '{') {
        json_ok = json->find("\"keyslots\"") != std::string::npos &&
                  json->find("\"segments\"") != std::string::npos;
        const std::size_t seg = json->find("\"segments\"");
        if (seg != std::string::npos) {
            if (const auto enc = json_string(*json, "encryption", seg)) {
                f.attrs["cipher_spec"] = *enc;
                const std::size_t dash = enc->find('-');
                f.attrs["cipher"] = dash == std::string::npos ? *enc : enc->substr(0, dash);
                if (dash != std::string::npos) f.attrs["mode"] = enc->substr(dash + 1);
            }
            if (const auto off = json_string(*json, "offset", seg)) {
                bool digits = !off->empty();
                for (const char c : *off) digits = digits && c >= '0' && c <= '9';
                if (digits) f.attrs["payload_offset"] = *off;
            }
        }
        const std::size_t dig = json->find("\"digests\"");
        if (dig != std::string::npos)
            if (const auto h = json_string(*json, "hash", dig)) f.attrs["hash"] = *h;
        const std::size_t ks = json->find("\"keyslots\"");
        if (ks != std::string::npos)
            if (const auto kdf = json_string(*json, "type", json->find("\"kdf\"", ks)))
                f.attrs["kdf"] = *kdf;
    }
    if (!json_ok)
        diag(f, Severity::Warning, "luks-bad-json",
             "JSON area does not start with '{' or lacks keyslots/segments");
    else if (uuid_text_ok(*uuid) && *hdr_offset == 0)
        f.confidence = Confidence::Consistent;
    f.evidence = "LUKS2 " +
                 (f.attrs.count("cipher_spec") ? f.attrs["cipher_spec"]
                                               : std::string("(cipher not found in JSON)")) +
                 ", header " + dec(*hdr_size) + " bytes, checksum " + *csum_alg;
    return f;
}

std::optional<Finding> validate_luks(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Big;
    const auto version = span.at<std::uint16_t>(start + 6, Endian::Big);
    if (!version) {
        diag(f, Severity::Warning, "luks-truncated-header", "version field missing");
        return f;
    }
    if (*version == 1) return luks1(span, start, std::move(f));
    if (*version == 2) return luks2(span, start, sig, std::move(f));
    diag(f, Severity::Warning, "luks-unsupported-version",
         "LUKS version " + dec(*version) + " is neither 1 nor 2");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("luks", validate_luks);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(luks)
