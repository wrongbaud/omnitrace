// squashfs.cpp — SquashFS v4 superblock validator.
//
// Layout (96 bytes, byte order given by the magic):
//   0  magic          4   16 fragments     4   24 flags        2   32 root_inode            8
//   4  inodes         4   20 compression   2   26 no_ids       2   40 bytes_used            8
//   8  mkfs_time      4   22 block_log     2   28 s_major      2   48 id_table_start        8
//  12  block_size     4                        30 s_minor      2   56 xattr_id_table_start  8
//  64 inode_table_start 8   72 directory_table_start 8   80 fragment_table_start 8   88
//  export_table_start 8
// Reference: Linux fs/squashfs/squashfs_fs.h; https://dr-emann.github.io/squashfs/
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kAbsent = 0xFFFFFFFFFFFFFFFFull;

const char* compression_name(std::uint16_t id) {
    switch (id) {
        case 1:
            return "gzip";
        case 2:
            return "lzma";
        case 3:
            return "lzo";
        case 4:
            return "xz";
        case 5:
            return "lz4";
        case 6:
            return "zstd";
        default:
            return "unknown";
    }
}

std::optional<Finding> validate_squashfs(const Span& span, std::uint64_t start,
                                         const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    // Byte order: from the signature when it says so; otherwise pick whichever
    // makes the major version read as 4 (vendor magics do not imply an order).
    Endian e = sig.endian.value_or(Endian::Little);
    if (!sig.endian) {
        const auto le = span.at<std::uint16_t>(start + 28, Endian::Little);
        const auto be = span.at<std::uint16_t>(start + 28, Endian::Big);
        if (le && *le != 4 && be && *be == 4) e = Endian::Big;
    }
    const auto inodes = span.at<std::uint32_t>(start + 4, e);
    const auto mkfs_time = span.at<std::uint32_t>(start + 8, e);
    const auto block_size = span.at<std::uint32_t>(start + 12, e);
    const auto fragments = span.at<std::uint32_t>(start + 16, e);
    const auto compression = span.at<std::uint16_t>(start + 20, e);
    const auto block_log = span.at<std::uint16_t>(start + 22, e);
    const auto flags = span.at<std::uint16_t>(start + 24, e);
    const auto no_ids = span.at<std::uint16_t>(start + 26, e);
    const auto major = span.at<std::uint16_t>(start + 28, e);
    const auto minor = span.at<std::uint16_t>(start + 30, e);
    const auto bytes_used = span.at<std::uint64_t>(start + 40, e);
    const auto id_table = span.at<std::uint64_t>(start + 48, e);
    const auto xattr_table = span.at<std::uint64_t>(start + 56, e);
    const auto inode_table = span.at<std::uint64_t>(start + 64, e);
    const auto dir_table = span.at<std::uint64_t>(start + 72, e);
    const auto frag_table = span.at<std::uint64_t>(start + 80, e);
    const auto export_table = span.at<std::uint64_t>(start + 88, e);

    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = e;
    if (!export_table) {
        diag(f, Severity::Warning, "squashfs-truncated-superblock",
             "fewer than 96 bytes available after the magic; superblock not parsed");
        return f;
    }
    if (*major != 4) {
        if (*major >= 1 && *major <= 3) {
            f.attrs["version"] = dec(*major) + "." + dec(*minor);
            diag(f, Severity::Warning, "squashfs-unsupported-version",
                 "SquashFS " + dec(*major) + "." + dec(*minor) + " superblock; only v4 is parsed");
            return f;
        }
        return std::nullopt;  // random bytes behind a magic-shaped word
    }
    f.attrs["version"] = dec(*major) + "." + dec(*minor);
    f.attrs["compression"] = compression_name(*compression);
    f.attrs["compression_id"] = dec(*compression);
    f.attrs["block_size"] = dec(*block_size);
    f.attrs["inodes"] = dec(*inodes);
    f.attrs["fragments"] = dec(*fragments);
    f.attrs["mkfs_time"] = dec(*mkfs_time);
    f.attrs["flags"] = hex_fixed(*flags, 4);
    f.attrs["id_count"] = dec(*no_ids);
    f.attrs["bytes_used"] = dec(*bytes_used);

    // Hard constraints -> Structural.
    bool ok = true;
    if (*block_size < 4096 || *block_size > (1u << 20) || !is_pow2(*block_size)) {
        diag(f, Severity::Warning, "squashfs-bad-block-size",
             "block_size " + dec(*block_size) + " is not a power of two in [4K, 1M]");
        ok = false;
    } else if (*block_log >= 32 ||
               (1u << *block_log) !=
                   *block_size) {  // shift guard: block_log is attacker-controlled
        diag(f, Severity::Warning, "squashfs-block-log-mismatch",
             "block_log " + dec(*block_log) + " disagrees with block_size " + dec(*block_size));
        ok = false;
    }
    if (*compression < 1 || *compression > 6) {
        diag(f, Severity::Warning, "squashfs-bad-compression",
             "compression id " + dec(*compression) + " is not in 1..6");
        ok = false;
    }
    if (*bytes_used < 96) {
        diag(f, Severity::Warning, "squashfs-bad-bytes-used",
             "bytes_used " + dec(*bytes_used) + " is smaller than the superblock");
        ok = false;
    }
    if (!ok) return f;  // Magic, with the reasons attached
    f.confidence = Confidence::Structural;

    bool truncated = false;
    const std::uint64_t used = clamp_size(span, start, *bytes_used, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "squashfs-truncated",
             "bytes_used " + dec(*bytes_used) + " exceeds the " + dec(remaining(span, start)) +
                 " bytes available");
        f.size = used;
        return f;
    }
    // Size: bytes_used rounded up to 4K (mksquashfs pads the image), clamped.
    const std::uint64_t padded = (*bytes_used + 4095u) & ~static_cast<std::uint64_t>(4095u);
    f.size = padded <= remaining(span, start) ? padded : used;

    // Cross-field consistency: every table the superblock points at must lie
    // inside bytes_used (absent tables are all-ones).
    bool consistent = true;
    auto check_table = [&](const char* name, std::uint64_t off, bool may_be_absent) {
        if (may_be_absent && off == kAbsent) return;
        if (off < 96 || off >= *bytes_used) {
            diag(f, Severity::Warning, "squashfs-table-outside",
                 std::string(name) + " at " + hex(off) + " is outside bytes_used " +
                     dec(*bytes_used));
            consistent = false;
        }
    };
    check_table("inode_table_start", *inode_table, false);
    check_table("directory_table_start", *dir_table, false);
    check_table("id_table_start", *id_table, false);
    check_table("fragment_table_start", *frag_table, *fragments == 0);
    check_table("xattr_id_table_start", *xattr_table, true);
    check_table("export_table_start", *export_table, true);
    if (*inode_table >= *dir_table) {
        diag(f, Severity::Warning, "squashfs-table-order",
             "inode table does not precede directory table");
        consistent = false;
    }
    if (consistent) f.confidence = Confidence::Consistent;
    f.evidence = "v4 superblock, " + std::string(compression_name(*compression)) + ", " +
                 dec(*inodes) + " inodes, " + dec(*bytes_used) + " bytes used";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("squashfs", validate_squashfs);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(squashfs)
