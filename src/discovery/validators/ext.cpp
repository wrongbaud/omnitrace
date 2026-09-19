// ext.cpp — ext2/ext3/ext4 superblock validator.
//
// The superblock sits 1024 bytes into the filesystem (little-endian):
//   0x00 s_inodes_count    0x04 s_blocks_count_lo   0x14 s_first_data_block
//   0x18 s_log_block_size  0x20 s_blocks_per_group  0x28 s_inodes_per_group
//   0x2C s_mtime  0x30 s_wtime  0x38 s_magic 0xEF53  0x3A s_state  0x4C s_rev_level
//   0x58 s_inode_size  0x5C s_feature_compat  0x60 s_feature_incompat  0x64 s_feature_ro_compat
//   0x68 s_uuid[16]  0x78 s_volume_name[16]  0x88 s_last_mounted[64]
//   0x150 s_blocks_count_hi (INCOMPAT_64BIT)  0x3FC s_checksum (RO_COMPAT_METADATA_CSUM, crc32c)
// Reference: Linux fs/ext4/ext4.h; https://www.kernel.org/doc/html/latest/filesystems/ext4/
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kCompatHasJournal = 0x0004;
constexpr std::uint32_t kIncompat64Bit = 0x0080;
constexpr std::uint32_t kIncompatExt4Mask =
    0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x0400 | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x10000 |
    0x20000;  // extents,64bit,mmp,flex_bg,ea_inode,dirdata,csum_seed,largedir,inline,encrypt,casefold
constexpr std::uint32_t kRoCompatExt4Mask = 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080 | 0x0100 |
                                            0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 |
                                            0x8000;  // huge_file,gdt_csum,dir_nlink,extra_isize,...
constexpr std::uint32_t kRoCompatMetadataCsum = 0x0400;

std::optional<Finding> validate_ext(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const std::uint64_t sb = start + 1024;
    const Endian e = Endian::Little;
    const auto inodes_count = span.at<std::uint32_t>(sb + 0x00, e);
    const auto blocks_lo = span.at<std::uint32_t>(sb + 0x04, e);
    const auto first_data_block = span.at<std::uint32_t>(sb + 0x14, e);
    const auto log_block_size = span.at<std::uint32_t>(sb + 0x18, e);
    const auto blocks_per_group = span.at<std::uint32_t>(sb + 0x20, e);
    const auto inodes_per_group = span.at<std::uint32_t>(sb + 0x28, e);
    const auto mtime = span.at<std::uint32_t>(sb + 0x2C, e);
    const auto wtime = span.at<std::uint32_t>(sb + 0x30, e);
    const auto mnt_count = span.at<std::uint16_t>(sb + 0x34, e);
    const auto state = span.at<std::uint16_t>(sb + 0x3A, e);
    const auto rev_level = span.at<std::uint32_t>(sb + 0x4C, e);
    const auto inode_size = span.at<std::uint16_t>(sb + 0x58, e);
    const auto compat = span.at<std::uint32_t>(sb + 0x5C, e);
    const auto incompat = span.at<std::uint32_t>(sb + 0x60, e);
    const auto ro_compat = span.at<std::uint32_t>(sb + 0x64, e);
    if (!ro_compat) return std::nullopt;  // 2-byte magic and no superblock behind it

    // Hard constraints. A false hit on 0xEF53 is common in a large image, so
    // anything a real superblock could never contain is a rejection.
    if (*log_block_size > 6) return std::nullopt;
    if (*rev_level > 1) return std::nullopt;
    if (*blocks_lo == 0 || *inodes_count == 0 || *blocks_per_group == 0 || *inodes_per_group == 0)
        return std::nullopt;
    const std::uint64_t block_size = 1024ull << *log_block_size;
    if ((block_size == 1024 && *first_data_block != 1) ||
        (block_size != 1024 && *first_data_block != 0))
        return std::nullopt;
    if (*rev_level == 1 && (*inode_size < 128 || !is_pow2(*inode_size) || *inode_size > block_size))
        return std::nullopt;

    std::uint64_t blocks_count = *blocks_lo;
    if (*rev_level == 1 && (*incompat & kIncompat64Bit) != 0) {
        if (const auto hi = span.at<std::uint32_t>(sb + 0x150, e))
            blocks_count |= static_cast<std::uint64_t>(*hi) << 32;
    }

    Finding f = make_finding(sig, start, Confidence::Structural);
    if (*rev_level == 1 &&
        ((*incompat & kIncompatExt4Mask) != 0 || (*ro_compat & kRoCompatExt4Mask) != 0))
        f.format = "ext4";
    else if (*rev_level == 1 && (*compat & kCompatHasJournal) != 0)
        f.format = "ext3";
    else
        f.format = "ext2";

    f.attrs["block_size"] = dec(block_size);
    f.attrs["blocks_count"] = dec(blocks_count);
    f.attrs["inode_count"] = dec(*inodes_count);
    f.attrs["blocks_per_group"] = dec(*blocks_per_group);
    f.attrs["inodes_per_group"] = dec(*inodes_per_group);
    f.attrs["rev_level"] = dec(*rev_level);
    f.attrs["state"] = (*state & 1) ? "clean" : "not-clean";
    if ((*state & 2) != 0) f.attrs["state"] = "errors";
    f.attrs["last_mount_time"] = dec(*mtime);
    f.attrs["last_write_time"] = dec(*wtime);
    f.attrs["mount_count"] = dec(*mnt_count);
    if (*rev_level == 1) {
        f.attrs["inode_size"] = dec(*inode_size);
        f.attrs["feature_compat"] = hex_fixed(*compat, 8);
        f.attrs["feature_incompat"] = hex_fixed(*incompat, 8);
        f.attrs["feature_ro_compat"] = hex_fixed(*ro_compat, 8);
        if (const auto uuid = span.bytes(sb + 0x68, 16)) f.attrs["uuid"] = uuid_raw(*uuid);
        if (const auto name = span.cstring(sb + 0x78, 16)) f.attrs["volume_name"] = *name;
        if (const auto mounted = span.cstring(sb + 0x88, 64)) f.attrs["last_mounted"] = *mounted;
    }

    // Size and cross-field consistency.
    const std::uint64_t claimed =
        blocks_count > UINT64_MAX / block_size ? UINT64_MAX : blocks_count * block_size;
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    bool consistent = !truncated;
    if (truncated)
        diag(f, Severity::Warning, "ext-truncated",
             "blocks_count * block_size = " + dec(claimed) + " exceeds the " +
                 dec(remaining(span, start)) + " bytes available");
    const std::uint64_t data_blocks =
        blocks_count > *first_data_block ? blocks_count - *first_data_block : 0;
    const std::uint64_t groups = (data_blocks + *blocks_per_group - 1) / *blocks_per_group;
    f.attrs["block_groups"] = dec(groups);
    if (groups == 0 || groups > UINT64_MAX / *inodes_per_group ||
        groups * *inodes_per_group != *inodes_count) {
        diag(f, Severity::Warning, "ext-inode-count-mismatch",
             "inodes_count " + dec(*inodes_count) + " != block_groups " + dec(groups) +
                 " * inodes_per_group " + dec(*inodes_per_group));
        consistent = false;
    }
    if (consistent) f.confidence = Confidence::Consistent;

    // metadata_csum: crc32c over the first 1020 bytes of the superblock.
    if (*rev_level == 1 && (*ro_compat & kRoCompatMetadataCsum) != 0) {
        const auto stored = span.at<std::uint32_t>(sb + 0x3FC, e);
        const auto computed = crc32_span<kCrc32cPoly>(span, sb, 0x3FC, 0xFFFFFFFFu, 0u);
        if (stored && computed) {
            if (*stored == *computed) {
                f.attrs["superblock_checksum"] = "ok";
                if (consistent) f.confidence = Confidence::Verified;
            } else {
                f.attrs["superblock_checksum"] = "mismatch";
                diag(f, Severity::Warning, "ext-superblock-csum-mismatch",
                     "superblock crc32c does not match s_checksum");
            }
        }
    }
    f.evidence = f.format + " superblock: " + dec(blocks_count) + " blocks of " + dec(block_size) +
                 ", " + dec(*inodes_count) + " inodes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("ext", validate_ext);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(ext)
