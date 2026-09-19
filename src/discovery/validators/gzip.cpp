// gzip.cpp — gzip member header validator (RFC 1952).
//
// 0 1F 8B, 2 CM (8 = deflate), 3 FLG, 4 MTIME u32 LE, 8 XFL, 9 OS, then
// optional FEXTRA (u16 len + data), FNAME (NUL-terminated), FCOMMENT, FHCRC.
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint8_t kFText = 0x01, kFHcrc = 0x02, kFExtra = 0x04, kFName = 0x08,
                       kFComment = 0x10;

std::string os_name(std::uint8_t v) {
    static const char* names[] = {"fat",     "amiga", "vms",       "unix",        "vm/cms",
                                  "atari",   "hpfs",  "macintosh", "z-system",    "cp/m",
                                  "tops-20", "ntfs",  "qdos",      "acorn-riscos"};
    if (v == 255) return "unknown";
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "invalid(" + dec(v) + ")";
}

std::optional<Finding> validate_gzip(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    const auto flg = span.u8(start + 3);
    const auto mtime = span.at<std::uint32_t>(start + 4, Endian::Little);
    const auto xfl = span.u8(start + 8);
    const auto os = span.u8(start + 9);
    if (!os) {
        diag(f, Severity::Warning, "gzip-truncated-header",
             "fewer than 10 bytes available for the header");
        return f;
    }
    if ((*flg & 0xE0) != 0) return std::nullopt;  // reserved flag bits set: not a gzip header
    if (*xfl != 0 && *xfl != 2 && *xfl != 4) {
        diag(f, Severity::Info, "gzip-unusual-xfl", "XFL " + dec(*xfl) + " is not 0, 2 or 4");
    }
    if (*os > 13 && *os != 255) {
        diag(f, Severity::Warning, "gzip-bad-os",
             "OS byte " + dec(*os) + " is not a defined value");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["mtime"] = dec(*mtime);
    f.attrs["xfl"] = dec(*xfl);
    f.attrs["os"] = os_name(*os);
    f.attrs["flags"] = hex_fixed(*flg, 2);
    if ((*flg & kFText) != 0) f.attrs["text"] = "true";
    std::uint64_t pos = start + 10;
    if ((*flg & kFExtra) != 0) {
        const auto xlen = span.at<std::uint16_t>(pos, Endian::Little);
        if (!xlen) {
            diag(f, Severity::Warning, "gzip-truncated-header", "FEXTRA length missing");
            return f;
        }
        f.attrs["extra_len"] = dec(*xlen);
        pos += 2u + *xlen;
    }
    if ((*flg & kFName) != 0) {
        const std::optional<std::uint64_t> cap = extra_u64(sig, "max_name_len");
        const std::uint64_t limit =
            std::min<std::uint64_t>(cap.value_or(UINT64_MAX), remaining(span, pos));
        if (const auto name = span.cstring(pos, static_cast<std::size_t>(limit))) {
            f.attrs["original_name"] = *name;
            pos += name->size() + 1;
        }
    }
    if ((*flg & kFComment) != 0) f.attrs["has_comment"] = "true";
    if ((*flg & kFHcrc) != 0) f.attrs["has_header_crc"] = "true";
    f.attrs["header_len"] = dec(pos - start);
    f.evidence = "deflate member, os " + os_name(*os) +
                 (f.attrs.count("original_name") ? ", name \"" + f.attrs["original_name"] + "\""
                                                 : std::string{});
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("gzip", validate_gzip);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(gzip)
