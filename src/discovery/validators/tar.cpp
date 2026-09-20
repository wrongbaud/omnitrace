// tar.cpp — tar archive validator: walks the 512-byte member headers to the
// end-of-archive marker, which is the only way to know where a tar ends.
//
// Header (512 bytes): 0 name[100], 100 mode[8], 108 uid[8], 116 gid[8],
// 124 size[12], 136 mtime[12], 148 chksum[8], 156 typeflag, 157 linkname[100],
// 257 magic[6], 263 version[2], 265 uname[32], 297 gname[32], 329 devmajor[8],
// 337 devminor[8], 345 prefix[155] (ustar) or atime/ctime (GNU).
//
// Numeric fields are NUL/space-terminated ASCII octal; GNU writes values that
// do not fit in binary instead, flagged by bit 7 of the first byte. The
// checksum is the sum of the header bytes with the checksum field read as
// spaces, and historic writers disagreed on whether the bytes are signed, so
// both sums are accepted -- that check is what lifts the finding to verified.
//
// The archive ends with two zero blocks, then padding to the writer's blocking
// factor (GNU tar uses 20 blocks, 10 KiB).
// Reference: https://www.gnu.org/software/tar/manual/html_node/Standard.html
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kBlock = 512;
constexpr std::uint64_t kGnuBlocking = 20 * kBlock;
constexpr std::uint64_t kMagicOffset = 257;

// A numeric header field: ASCII octal, or GNU base-256 when bit 7 of the
// first byte is set. nullopt when the field is unreadable.
std::optional<std::uint64_t> num_field(const Span& span, std::uint64_t off, std::size_t n) {
    const auto bytes = span.bytes(off, n);
    if (!bytes) return std::nullopt;
    const std::vector<std::uint8_t>& b = *bytes;
    if ((b[0] & 0x80U) != 0) {  // GNU base-256
        std::uint64_t v = b[0] & 0x7FU;
        for (std::size_t i = 1; i < b.size(); ++i) {
            if (v > (UINT64_MAX >> 8)) return std::nullopt;
            v = (v << 8) | b[i];
        }
        return v;
    }
    std::uint64_t v = 0;
    bool any = false;
    for (const std::uint8_t c : b) {
        if (c == 0 || c == ' ') {
            if (any) break;  // leading padding
            continue;
        }
        if (c < '0' || c > '7') return std::nullopt;
        if (v > (UINT64_MAX - static_cast<std::uint64_t>(c - '0')) / 8) return std::nullopt;
        v = (v * 8) + static_cast<std::uint64_t>(c - '0');
        any = true;
    }
    return any ? std::optional<std::uint64_t>(v) : std::optional<std::uint64_t>(0);
}

// True when the stored checksum matches either the signed or the unsigned sum
// of the header with the checksum field taken as spaces.
bool checksum_ok(const std::vector<std::uint8_t>& h, std::uint64_t stored) {
    std::uint64_t unsigned_sum = 0;
    std::int64_t signed_sum = 0;
    for (std::size_t i = 0; i < h.size(); ++i) {
        const std::uint8_t byte = (i >= 148 && i < 156) ? static_cast<std::uint8_t>(' ') : h[i];
        unsigned_sum += byte;
        signed_sum += static_cast<std::int8_t>(byte);
    }
    return stored == unsigned_sum ||
           (signed_sum >= 0 && stored == static_cast<std::uint64_t>(signed_sum));
}

bool all_zero(const std::vector<std::uint8_t>& b) {
    for (const std::uint8_t v : b) {
        if (v != 0) return false;
    }
    return true;
}

std::optional<Finding> validate_tar(const Span& span, std::uint64_t start, const Signature& sig) {
    // The magic sits 257 bytes into the header, so a hit near the start of a
    // Span has no header behind it.
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);

    const auto ver = span.bytes(start + kMagicOffset, 8);
    if (!ver) return std::nullopt;
    const bool gnu = (*ver)[5] == ' ' && (*ver)[6] == ' ';
    f.attrs["variant"] = gnu ? "gnu" : "ustar";

    const std::uint64_t cap = extra_u64(sig, "max_entries").value_or(200000);
    std::uint64_t pos = start;
    std::uint64_t entries = 0, data_bytes = 0, checked = 0, bad_sums = 0;
    bool end_marker = false;
    bool pax = false;

    for (;;) {
        if (entries > cap) {
            diag(f, Severity::Warning, "tar-limit-entries",
                 "more than " + dec(cap) + " members before the end marker; not walked further");
            break;
        }
        const auto header = span.bytes(pos, static_cast<std::size_t>(kBlock));
        if (!header) {
            diag(f, Severity::Warning, "tar-truncated",
                 "the archive ends inside a header at " + hex(span.absolute(pos)));
            break;
        }
        if (all_zero(*header)) {
            // One zero block ends the archive; a second confirms it.
            end_marker = true;
            pos += kBlock;
            if (const auto second = span.bytes(pos, static_cast<std::size_t>(kBlock))) {
                if (all_zero(*second)) pos += kBlock;
            }
            break;
        }
        const auto stored = num_field(span, pos + 148, 8);
        const auto size = num_field(span, pos + 124, 12);
        if (!stored || !size) {
            diag(f, Severity::Warning, "tar-bad-header",
                 "member " + dec(entries) + " at " + hex(span.absolute(pos)) +
                     " has an unreadable size or checksum");
            break;
        }
        ++checked;
        if (!checksum_ok(*header, *stored)) {
            ++bad_sums;
            diag(f, Severity::Warning, "tar-checksum-mismatch",
                 "member " + dec(entries) + " at " + hex(span.absolute(pos)) +
                     " does not match its header checksum");
            break;
        }
        const auto flag = span.u8(pos + 156);
        if (flag && (*flag == 'x' || *flag == 'g')) pax = true;
        // Only the header itself counts towards the member total; the extended
        // headers GNU and pax use are part of the member that follows.
        if (!flag || (*flag != 'L' && *flag != 'K' && *flag != 'x' && *flag != 'g')) {
            ++entries;
            data_bytes = sat_add(data_bytes, *size);
        }
        const std::uint64_t padded = (*size + kBlock - 1) & ~(kBlock - 1);
        const std::uint64_t next = sat_add(sat_add(pos, kBlock), padded);
        if (next <= pos || next > span.size()) {
            diag(f, Severity::Warning, "tar-truncated",
                 "member " + dec(entries) + " runs past the available data");
            break;
        }
        pos = next;
    }

    if (pax) f.attrs["variant"] = "pax";
    f.attrs["entries"] = dec(entries);
    f.attrs["data_bytes"] = dec(data_bytes);
    if (!end_marker) {
        // Without the end marker the extent is unknown. A stray "ustar" in
        // other data must not claim whatever follows it.
        diag(f, Severity::Info, "tar-no-end-marker",
             "no end-of-archive block was reached, so the archive has no extent and claims no "
             "bytes");
        f.attrs["extent"] = "unknown";
        if (checked != 0 && bad_sums == 0) f.confidence = Confidence::Structural;
        return f;
    }
    f.confidence = checked != 0 ? Confidence::Verified : Confidence::Consistent;

    // tar pads to its blocking factor; claim the padding only when it is zeros.
    // The blocking factor is a multiple of 512, not a power of two (GNU uses
    // 20 blocks = 10240), so this rounds by division rather than by masking.
    std::uint64_t end = pos;
    for (const std::uint64_t unit : {kBlock, kGnuBlocking}) {
        if (unit == 0) continue;
        const std::uint64_t padded = ((end + unit - 1) / unit) * unit;
        if (padded <= end || padded > span.size()) continue;
        if (const auto tail = span.bytes(end, static_cast<std::size_t>(padded - end))) {
            if (all_zero(*tail)) end = padded;
        }
    }
    bool truncated = false;
    f.size = clamp_size(span, start, end - start, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "tar-truncated", "the archive ends past the available data");
    }
    f.evidence = f.attrs["variant"] + " archive, " + dec(entries) + " member(s), " +
                 dec(data_bytes) + " bytes of data, " + dec(checked) + " header checksum(s) ok";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("tar", validate_tar);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(tar)
