// cpio.cpp — cpio archive validator: walks the member headers to find the
// trailer, which is the only way to know where the archive ends.
//
// Three header flavours share the format id. SVR4 "newc" (070701) and its
// CRC variant (070702) use a 110-byte header of 8-digit ASCII hex fields,
// with the name and the data each padded to a 4-byte boundary. POSIX "odc"
// (070707) uses a 76-byte header of 6- and 11-digit ASCII octal fields with
// no padding at all. All three end with an entry named "TRAILER!!!" and are
// written out padded to a 512-byte block.
//
// Walking costs one hop per member (no data is read), so sizing a 100 MB
// initramfs is a few thousand header reads.
// Reference: https://www.kernel.org/doc/html/latest/driver-api/early-userspace/buffer-format.html
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kNewcHeader = 110;
constexpr std::uint64_t kOdcHeader = 76;
constexpr std::uint64_t kBlock = 512;
constexpr const char* kTrailer = "TRAILER!!!";

// A field of `n` ASCII digits in base `base`; nullopt when any digit is bad.
std::optional<std::uint64_t> ascii_field(const Span& span, std::uint64_t off, std::size_t n,
                                         unsigned base) {
    const auto bytes = span.bytes(off, n);
    if (!bytes) return std::nullopt;
    std::uint64_t v = 0;
    for (const std::uint8_t c : *bytes) {
        unsigned d = 0;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            d = 10u + (c - 'A');
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            d = 10u + (c - 'a');
        } else {
            return std::nullopt;
        }
        if (d >= base) return std::nullopt;
        if (v > (UINT64_MAX - d) / base) return std::nullopt;
        v = v * base + d;
    }
    return v;
}

std::uint64_t align4(std::uint64_t v) {
    return v > UINT64_MAX - 3 ? v : (v + 3) & ~std::uint64_t{3};
}

std::optional<Finding> validate_cpio(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);

    const bool odc = sig.name == "cpio-odc";
    const char* variant = odc ? "odc" : (sig.name == "cpio-crc" ? "crc" : "newc");
    f.attrs["variant"] = variant;

    const std::uint64_t cap = extra_u64(sig, "max_entries").value_or(200000);
    std::uint64_t pos = start;
    std::uint64_t entries = 0, data_bytes = 0;
    bool trailer = false;

    for (;;) {
        if (entries > cap) {
            diag(f, Severity::Warning, "cpio-limit-entries",
                 "more than " + dec(cap) + " members before a trailer; not walked further");
            break;
        }
        // Every member repeats the magic; a run that stops matching is the end
        // of this archive, not a member.
        if (!span.matches_at(pos, std::span<const std::uint8_t>(sig.magic.data(),
                                                                sig.magic.size()))) {
            break;
        }
        std::optional<std::uint64_t> namesize, filesize;
        std::uint64_t header = 0;
        if (odc) {
            header = kOdcHeader;
            namesize = ascii_field(span, pos + 59, 6, 8);
            filesize = ascii_field(span, pos + 65, 11, 8);
        } else {
            header = kNewcHeader;
            namesize = ascii_field(span, pos + 94, 8, 16);
            filesize = ascii_field(span, pos + 54, 8, 16);
        }
        if (!namesize || !filesize || *namesize == 0) {
            diag(f, Severity::Warning, "cpio-bad-header",
                 "member " + dec(entries) + " at " + hex(span.absolute(pos)) +
                     " has an unreadable name or file size");
            break;
        }
        // The name sits right after the header; newc pads the pair to 4.
        const std::uint64_t name_at = pos + header;
        const auto name = span.cstring(name_at, static_cast<std::size_t>(
                                                    std::min<std::uint64_t>(*namesize, 4096)));
        if (!name) {
            diag(f, Severity::Warning, "cpio-bad-header",
                 "member " + dec(entries) + " name runs past the available data");
            break;
        }
        if (*name == kTrailer) {
            pos = odc ? name_at + *namesize : align4(name_at + *namesize);
            trailer = true;
            break;
        }
        ++entries;
        data_bytes = sat_add(data_bytes, *filesize);
        const std::uint64_t data_at = odc ? name_at + *namesize : align4(name_at + *namesize);
        const std::uint64_t next = odc ? sat_add(data_at, *filesize)
                                       : align4(sat_add(data_at, *filesize));
        if (next <= pos || next >= span.size()) {
            diag(f, Severity::Warning, "cpio-truncated",
                 "member " + dec(entries) + " runs past the available data");
            break;
        }
        pos = next;
    }

    f.attrs["entries"] = dec(entries);
    f.attrs["data_bytes"] = dec(data_bytes);
    if (!trailer) {
        // Without a trailer the extent is unknown: claiming bytes here would
        // let a stray "070701" in text swallow whatever follows it.
        diag(f, Severity::Info, "cpio-no-trailer",
             "no TRAILER!!! member was reached, so the archive has no extent and claims no bytes");
        f.attrs["extent"] = "unknown";
        return f;
    }
    f.confidence = Confidence::Consistent;

    // cpio pads its output to a 512-byte block. Claim the padding only when it
    // really is padding, so a following structure is never swallowed.
    std::uint64_t end = pos;
    const std::uint64_t padded = (end + kBlock - 1) & ~(kBlock - 1);
    if (padded > end && padded <= span.size()) {
        if (const auto tail = span.bytes(end, static_cast<std::size_t>(padded - end))) {
            if (all_bytes(std::span<const std::uint8_t>(tail->data(), tail->size()), 0)) end = padded;
        }
    }
    bool truncated = false;
    f.size = clamp_size(span, start, end - start, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "cpio-truncated", "the archive ends past the available data");
    }
    f.evidence = std::string(variant) + " archive, " + dec(entries) + " member(s), " +
                 dec(data_bytes) + " bytes of data";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("cpio", validate_cpio);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(cpio)
