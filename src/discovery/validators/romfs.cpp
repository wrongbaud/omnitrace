// romfs.cpp — romfs superblock validator.
//
// Big-endian header: 0 "-rom1fs-", 8 full size u32, 12 checksum u32, 16
// volume name (NUL-terminated, padded to a 16-byte boundary), then the first
// file header. The checksum makes the big-endian u32 sum of the first 512
// bytes (or of the whole image when smaller) zero. Images are padded to
// 1024 bytes. Reference: Linux Documentation/filesystems/romfs.rst, fs/romfs/
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kChecksumWindow = 512;
constexpr std::uint64_t kDefaultMaxName = 256;

std::optional<Finding> validate_romfs(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Big;
    const auto full = span.at<std::uint32_t>(start + 8, Endian::Big);
    const auto stored = span.at<std::uint32_t>(start + 12, Endian::Big);
    if (!full || !stored) {
        diag(f, Severity::Warning, "romfs-truncated-header",
             "fewer than 16 bytes available for the superblock");
        return f;
    }
    const std::uint64_t max_name = extra_u64(sig, "max_name_len").value_or(kDefaultMaxName);
    const auto name = span.cstring(start + 16, static_cast<std::size_t>(max_name));
    bool name_ok = name.has_value();
    if (name)
        for (const char c : *name)
            name_ok = name_ok && static_cast<unsigned char>(c) >= 0x20 &&
                      static_cast<unsigned char>(c) < 0x7F;
    if (!name_ok) {
        diag(f, Severity::Warning, "romfs-bad-name",
             "volume name is not printable ASCII; magic string inside other data");
        return f;
    }
    // Header (16) + name padded to 16 + at least one 16-byte file header.
    const std::uint64_t name_field = ((name->size() + 1) + 15) & ~std::uint64_t{15};
    if (*full < 16 + name_field + 16) {
        diag(f, Severity::Warning, "romfs-bad-size",
             "full size " + dec(*full) + " cannot hold the header and a file entry");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["volume_name"] = *name;
    f.attrs["full_size"] = dec(*full);
    const std::uint64_t claimed = (static_cast<std::uint64_t>(*full) + 1023) & ~std::uint64_t{1023};
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "romfs-truncated",
             "full size " + dec(*full) + " extends past the available data");
        return f;
    }
    f.confidence = Confidence::Consistent;
    // First file header: next-pointer (low 4 bits = type) must stay inside the image.
    const auto next = span.at<std::uint32_t>(start + 16 + name_field, Endian::Big);
    if (next && (*next & ~15u) != 0 && (*next & ~15u) >= *full) {
        diag(f, Severity::Warning, "romfs-bad-first-header",
             "first file header points past the end of the image");
        f.confidence = Confidence::Structural;
    }
    const std::uint64_t window = std::min<std::uint64_t>(kChecksumWindow, *full);
    std::uint32_t sum = 0;
    std::array<std::uint8_t, 4> w{};
    for (std::uint64_t o = 0; o + 4 <= window; o += 4) {
        if (span.read(start + o, std::span<std::uint8_t>(w.data(), 4)) != 4) break;
        sum += load_int<std::uint32_t>(w.data(), Endian::Big);
    }
    if (sum == 0) {
        f.attrs["checksum"] = "ok";
        if (f.confidence == Confidence::Consistent) f.confidence = Confidence::Verified;
    } else {
        f.attrs["checksum"] = "mismatch";
        diag(f, Severity::Warning, "romfs-checksum-mismatch",
             "header checksum over the first " + dec(window) + " bytes is " + hex_fixed(sum, 8) +
                 ", not zero");
    }
    f.evidence =
        "romfs \"" + *name + "\", " + dec(*full) + " bytes, checksum " + f.attrs["checksum"];
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("romfs", validate_romfs);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(romfs)
