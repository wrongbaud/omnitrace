// squashfs.cpp — SquashFS superblock validator, v1 through v4.
//
// Layout (96 bytes, byte order given by the magic):
//   0  magic          4   16 fragments     4   24 flags        2   32 root_inode            8
//   4  inodes         4   20 compression   2   26 no_ids       2   40 bytes_used            8
//   8  mkfs_time      4   22 block_log     2   28 s_major      2   48 id_table_start        8
//  12  block_size     4                        30 s_minor      2   56 xattr_id_table_start  8
//  64 inode_table_start 8   72 directory_table_start 8   80 fragment_table_start 8   88
//  export_table_start 8
//
// v1-v3 use a different, **packed** superblock whose fields are not aligned:
//   0  magic  4    28 s_major  2    36 flags     1    43 root_inode  8
//   4  inodes 4    30 s_minor  2    37 no_uids   1    51 block_size  4  (v2+)
//   8  bytes_used_2 4 (v1/v2: the only bytes_used)  38 no_guids  1    55 fragments 4 (v2+)
//  12  uid_start_2 4   20 inode_table_start_2 4   39 mkfs_time 4
//  16  guid_start_2 4  24 directory_table_start_2 4
//  63  bytes_used 8    71 uid_start 8    79 guid_start 8    87 inode_table_start 8  (v3)
//  95  directory_table_start 8   103 fragment_table_start 8   111 lookup_table_start 8
// Note 32 block_size_1 (u16) and 34 block_log (u16): v1 has no 32-bit
// block_size, so its block size is the u16 and cannot exceed 32 KiB.
//
// The version is at the same offset in both, which is what makes one validator
// possible: read s_major first, then parse the superblock it names.
//
// Reference: Linux fs/squashfs/squashfs_fs.h; squashfs-tools 3.4
// squashfs_fs.h for the packed layout; https://dr-emann.github.io/squashfs/
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

// v1-v3: the packed superblock. Reached from validate_squashfs once s_major
// says so, with the Finding already made and the byte order already settled.
//
// Sizing is the whole point. Before this, a v3 superblock was identified and
// then dropped for want of an extent, and because `docs/ARCHITECTURE.md` says
// an unsized structure is never handed to a reader, an entire root filesystem
// went unread -- 3,903 files on one corpus router (`docs/PARITY.md`).
std::optional<Finding> validate_legacy(const Span& span, std::uint64_t start, const Signature& sig,
                                       Finding& f, std::uint16_t major, std::uint16_t minor) {
    (void)sig;
    const Endian e = f.endian;
    // v1 stops after root_inode; v2 adds block_size/fragments; v3 adds the
    // 64-bit tables. Ask only for what the version actually has.
    const std::uint64_t need = major >= 3 ? 119u : (major == 2 ? 63u : 51u);
    if (remaining(span, start) < need) {
        diag(f, Severity::Warning, "squashfs-truncated-superblock",
             "fewer than " + dec(need) + " bytes available after the magic; v" + dec(major) +
                 " superblock not parsed");
        return f;
    }

    const auto inodes = span.at<std::uint32_t>(start + 4, e);
    const auto bytes_used_32 = span.at<std::uint32_t>(start + 8, e);
    const auto inode_table_32 = span.at<std::uint32_t>(start + 20, e);
    const auto dir_table_32 = span.at<std::uint32_t>(start + 24, e);
    const auto block_size_1 = span.at<std::uint16_t>(start + 32, e);
    const auto block_log = span.at<std::uint16_t>(start + 34, e);
    const auto mkfs_time = span.at<std::uint32_t>(start + 39, e);
    if (!inodes || !bytes_used_32 || !block_log || !mkfs_time) return f;

    // v2 introduced the 32-bit block_size; v1 has only the 16-bit one, so a v1
    // image cannot describe a block larger than 32 KiB.
    std::uint64_t block_size = *block_size_1;
    if (major >= 2) {
        const auto bs = span.at<std::uint32_t>(start + 51, e);
        if (!bs) return f;
        block_size = *bs;
    }
    const auto fragments =
        major >= 2 ? span.at<std::uint32_t>(start + 55, e) : std::optional<std::uint32_t>(0u);

    // v3 keeps a 64-bit bytes_used and leaves the 32-bit twin at zero on an
    // image larger than 4 GiB; below that both are set. Prefer the wide field
    // and fall back, rather than trusting either alone.
    std::uint64_t bytes_used = *bytes_used_32;
    std::uint64_t inode_table = *inode_table_32;
    std::uint64_t dir_table = *dir_table_32;
    if (major >= 3) {
        const auto wide = span.at<std::uint64_t>(start + 63, e);
        const auto wide_inode = span.at<std::uint64_t>(start + 87, e);
        const auto wide_dir = span.at<std::uint64_t>(start + 95, e);
        if (!wide || !wide_inode || !wide_dir) return f;
        if (*wide >= need) bytes_used = *wide;
        if (*wide_inode >= need) inode_table = *wide_inode;
        if (*wide_dir >= need) dir_table = *wide_dir;
    }

    f.attrs["version"] = dec(major) + "." + dec(minor);
    f.attrs["block_size"] = dec(block_size);
    f.attrs["inodes"] = dec(*inodes);
    f.attrs["fragments"] = dec(fragments.value_or(0));
    f.attrs["mkfs_time"] = dec(*mkfs_time);
    f.attrs["bytes_used"] = dec(bytes_used);

    bool ok = true;
    const std::uint64_t max_block = major == 1 ? (1u << 15) : (1u << 20);
    if (block_size < 4096 || block_size > max_block || !is_pow2(block_size)) {
        diag(f, Severity::Warning, "squashfs-bad-block-size",
             "block_size " + dec(block_size) + " is not a power of two in [4K, " + dec(max_block) +
                 "]");
        ok = false;
    } else if (*block_log >= 32 || (1ull << *block_log) != block_size) {
        diag(f, Severity::Warning, "squashfs-block-log-mismatch",
             "block_log " + dec(*block_log) + " disagrees with block_size " + dec(block_size));
        ok = false;
    }
    if (bytes_used < need) {
        diag(f, Severity::Warning, "squashfs-bad-bytes-used",
             "bytes_used " + dec(bytes_used) + " is smaller than the superblock");
        ok = false;
    }
    if (*inodes == 0) {
        diag(f, Severity::Warning, "squashfs-bad-inode-count", "the superblock claims no inodes");
        ok = false;
    }
    if (!ok) return f;
    f.confidence = Confidence::Structural;

    bool truncated = false;
    const std::uint64_t used = clamp_size(span, start, bytes_used, truncated);
    const std::uint64_t padded = (bytes_used + 4095u) & ~static_cast<std::uint64_t>(4095u);
    f.size = truncated || padded > remaining(span, start) ? used : padded;
    if (truncated)
        diag(f, Severity::Warning, "squashfs-truncated",
             "bytes_used " + dec(bytes_used) + " exceeds the " + dec(remaining(span, start)) +
                 " bytes available");

    bool consistent = !truncated;
    auto check_table = [&](const char* name, std::uint64_t off) {
        if (off < need || off >= bytes_used) {
            diag(f, Severity::Warning, "squashfs-table-outside",
                 std::string(name) + " at " + hex(off) + " is outside bytes_used " +
                     dec(bytes_used));
            consistent = false;
        }
    };
    check_table("inode_table_start", inode_table);
    check_table("directory_table_start", dir_table);
    if (inode_table >= dir_table) {
        diag(f, Severity::Warning, "squashfs-table-order",
             "inode table does not precede directory table");
        consistent = false;
    }
    if (consistent) f.confidence = Confidence::Consistent;
    f.evidence = "v" + dec(major) + "." + dec(minor) + " superblock, " + dec(*inodes) +
                 " inodes, " + dec(bytes_used) + " bytes used";
    return f;
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
        if (*major >= 1 && *major <= 3) return validate_legacy(span, start, sig, f, *major, *minor);
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

    // Size: bytes_used rounded up to 4K (mksquashfs pads the image), clamped.
    bool truncated = false;
    const std::uint64_t used = clamp_size(span, start, *bytes_used, truncated);
    const std::uint64_t padded = (*bytes_used + 4095u) & ~static_cast<std::uint64_t>(4095u);
    f.size = truncated || padded > remaining(span, start) ? used : padded;
    if (truncated)
        diag(f, Severity::Warning, "squashfs-truncated",
             "bytes_used " + dec(*bytes_used) + " exceeds the " + dec(remaining(span, start)) +
                 " bytes available");

    // Cross-field consistency: every table the superblock points at must lie
    // inside bytes_used (absent tables are all-ones). A truncated image stays
    // at Structural (ext does the same): every table sits at the end of a
    // SquashFS, so on a cut image none of them is there to be checked and the
    // pointers were verified against a claimed size, not against data. The
    // checks still run, so the diagnostics and the evidence line describe the
    // superblock either way.
    bool consistent = !truncated;
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
