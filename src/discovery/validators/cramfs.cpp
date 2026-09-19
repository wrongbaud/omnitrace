// cramfs.cpp — cramfs superblock validator.
//
// 76-byte superblock in the filesystem's byte order:
//    0 magic 0x28cd3d45   4 size u32   8 flags u32   12 future u32
//   16 signature[16] "Compressed ROMFS"
//   32 fsid: crc u32, edition u32, blocks u32, files u32
//   48 name[16]   64 root inode (mode u16, uid u16, size:24 gid:8, namelen:6 offset:26)
// With CRAMFS_FLAG_FSID_VERSION_2 (0x1) the size and fsid fields are valid;
// the crc is crc32 (zlib) of the whole image with the crc field zeroed.
// Reference: Linux include/uapi/linux/cramfs_fs.h, fs/cramfs/inode.c
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kFlagFsidV2 = 0x1, kFlagSortedDirs = 0x2, kFlagHoles = 0x100,
                        kFlagWrongSignature = 0x200, kFlagShiftedRootOffset = 0x400,
                        kFlagExtBlockPointers = 0x800;
constexpr std::uint32_t kKnownFlags = kFlagFsidV2 | kFlagSortedDirs | kFlagHoles |
                                      kFlagWrongSignature | kFlagShiftedRootOffset |
                                      kFlagExtBlockPointers;
constexpr std::array<std::uint8_t, 16> kSignature{'C', 'o', 'm', 'p', 'r', 'e', 's', 's',
                                                  'e', 'd', ' ', 'R', 'O', 'M', 'F', 'S'};

std::optional<Finding> validate_cramfs(const Span& span, std::uint64_t start,
                                       const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const Endian e = sig.endian.value_or(Endian::Little);
    std::array<std::uint8_t, 76> raw{};
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    if (!std::equal(kSignature.begin(), kSignature.end(), raw.begin() + 16))
        return std::nullopt;  // 4-byte magic without its 16-byte signature: noise
    auto u32 = [&](std::size_t o) { return load_int<std::uint32_t>(raw.data() + o, e); };
    const std::uint32_t size = u32(4), flags = u32(8), crc = u32(32), edition = u32(36),
                        blocks = u32(40), files = u32(44);
    Finding f = make_finding(sig, start, Confidence::Structural);
    f.endian = e;
    f.attrs["flags"] = hex_fixed(flags, 8);
    if (const auto name = span.cstring(start + 48, 16)) f.attrs["name"] = list_safe(*name);
    if ((flags & ~kKnownFlags) != 0)
        diag(f, Severity::Info, "cramfs-unknown-flags",
             "flags " + hex_fixed(flags & ~kKnownFlags, 8) + " are not defined by cramfs");
    if ((flags & kFlagFsidV2) == 0) {
        // Version 1 images (pre-2.3.x kernels) leave size/fsid unset.
        diag(f, Severity::Info, "cramfs-v1-no-size",
             "FSID_VERSION_2 flag clear: size and fsid fields are not valid; size unknown");
        f.attrs["version"] = "1";
        f.evidence = "cramfs v1 superblock (no size field)";
        return f;
    }
    f.attrs["version"] = "2";
    f.attrs["edition"] = dec(edition);
    f.attrs["blocks"] = dec(blocks);
    f.attrs["files"] = dec(files);
    f.attrs["crc"] = hex_fixed(crc, 8);
    if (size < 76 || files == 0) {
        diag(f, Severity::Warning, "cramfs-bad-size",
             "size " + dec(size) + " / files " + dec(files) + " out of range");
        return f;
    }
    bool truncated = false;
    f.size = clamp_size(span, start, size, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "cramfs-truncated",
             "size " + dec(size) + " extends past the available data");
        return f;
    }
    f.confidence = Confidence::Consistent;
    // Whole-image CRC with the crc field zeroed: chain the three pieces.
    const auto head = crc32_span(span, start, 32, 0xFFFFFFFFu, 0u);
    if (head) {
        const std::array<std::uint8_t, 4> zero{};
        const std::uint32_t mid =
            crc32_update(*head, std::span<const std::uint8_t>(zero.data(), 4));
        const auto tail = crc32_span(span, start + 36, size - 36, mid, 0xFFFFFFFFu);
        if (tail && *tail == crc) {
            f.attrs["crc_check"] = "ok";
            f.confidence = Confidence::Verified;
        } else {
            f.attrs["crc_check"] = "mismatch";
            diag(f, Severity::Warning, "cramfs-crc-mismatch",
                 "image CRC32 does not match the superblock crc field");
        }
    }
    f.evidence = "cramfs v2 \"" + f.attrs["name"] + "\", " + dec(files) + " files, " + dec(size) +
                 " bytes, crc " +
                 (f.attrs.count("crc_check") ? f.attrs["crc_check"] : std::string("unchecked"));
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("cramfs", validate_cramfs);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(cramfs)
