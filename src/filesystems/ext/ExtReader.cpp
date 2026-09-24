// ExtReader.cpp — native ext2 / ext3 / ext4 reader. See ExtReader.h and
// docs/formats/ext.md.
//
// Format knowledge: Linux fs/ext4/ext4.h, ext4_extents.h, xattr.h, dir.c and
// the kernel's ext4 documentation (Documentation/filesystems/ext4/), read for
// understanding; e2fsprogs (debugfs, dumpe2fs) is the reference tool. All
// on-disk integers are little-endian. Every read goes through Span; every cap
// is a Limits field; every skipped thing is a Diagnostic.
//
// Layout, in one paragraph: the superblock is at byte 1024; the group
// descriptor table follows the superblock's block (or lives in meta block
// groups); each descriptor names the group's block bitmap, inode bitmap and
// inode table. Inode 2 is the root directory. A file's blocks are found by
// an extent tree rooted in the 60-byte i_block area (EXTENTS_FL), by the
// classic 12 direct + 3 indirect pointers (ext2/ext3), or the data is inline
// in the inode (INLINE_DATA_FL). Directories are arrays of variable-length
// entries; an unlinked entry is normally merged into its predecessor's
// rec_len, so its bytes remain in the "slack" and can be read back.
#include "ExtReader.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <vector>

#include "../../discovery/crc32.h"
#include "omnitrace/core/Endian.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_ext() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants
// Format constants from ext4.h / ext4_extents.h / xattr.h. None is a limit.
constexpr std::uint64_t kSuperblockOffset = 1024;
constexpr std::uint64_t kSuperblockSize = 1024;
constexpr std::uint16_t kMagic = 0xEF53;
constexpr std::uint16_t kExtentMagic = 0xF30A;
constexpr std::uint32_t kXattrMagic = 0xEA020000u;
constexpr std::uint32_t kRootIno = 2;
constexpr std::uint32_t kJournalIno = 8;
constexpr std::uint32_t kGoodOldFirstIno = 11;
constexpr std::uint16_t kGoodOldInodeSize = 128;
constexpr std::uint16_t kMinDescSize = 32;
constexpr std::uint16_t kDescSize64 = 64;
constexpr std::size_t kIBlockBytes = 60;
constexpr std::size_t kExtentHeaderSize = 12;
constexpr std::size_t kExtentEntrySize = 12;
constexpr std::size_t kMaxExtentDepth = 5;  // EXT4_MAX_EXTENT_DEPTH: deeper trees are invalid
constexpr std::uint32_t kExtentInitMaxLen = 32768;  // EXT_INIT_MAX_LEN; longer = uninitialized
constexpr std::size_t kDirEntryHeader = 8;
constexpr std::uint32_t kMaxRecLen = 65535;  // EXT4_MAX_REC_LEN

// Feature flags.
constexpr std::uint32_t kCompatHasJournal = 0x0004;
constexpr std::uint32_t kIncompatFiletype = 0x0002;
constexpr std::uint32_t kIncompatRecover = 0x0004;
constexpr std::uint32_t kIncompatMetaBg = 0x0010;
constexpr std::uint32_t kIncompat64Bit = 0x0080;
constexpr std::uint32_t kIncompatCsumSeed = 0x2000;
constexpr std::uint32_t kIncompatLargedir = 0x4000;
constexpr std::uint32_t kIncompatInlineData = 0x8000;
constexpr std::uint32_t kIncompatEncrypt = 0x10000;
constexpr std::uint32_t kIncompatCasefold = 0x20000;
constexpr std::uint32_t kRoCompatSparseSuper = 0x0001;
constexpr std::uint32_t kRoCompatHugeFile = 0x0008;
constexpr std::uint32_t kRoCompatGdtCsum = 0x0010;
constexpr std::uint32_t kRoCompatMetadataCsum = 0x0400;
// Incompat bits this reader knows how to walk past; anything else is
// reported as ext-unsupported-feature at open.
constexpr std::uint32_t kIncompatKnown = 0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0080 | 0x0100 |
                                         0x0200 | 0x0400 | 0x1000 | 0x2000 | 0x4000 | 0x8000 |
                                         0x10000 | 0x20000;
// The same masks the discovery validator uses to pick the format id.
constexpr std::uint32_t kIncompatExt4Mask = 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x0400 | 0x1000 |
                                            0x2000 | 0x4000 | 0x8000 | 0x10000 | 0x20000;
constexpr std::uint32_t kRoCompatExt4Mask = 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080 | 0x0100 |
                                            0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x8000;

// Group descriptor flags.
constexpr std::uint16_t kBgInodeUninit = 0x0001;
constexpr std::uint16_t kBgBlockUninit = 0x0002;

// Inode flags.
constexpr std::uint32_t kFlCompr = 0x00000004;
constexpr std::uint32_t kFlImmutable = 0x00000010;
constexpr std::uint32_t kFlAppend = 0x00000020;
constexpr std::uint32_t kFlEncrypt = 0x00000800;
constexpr std::uint32_t kFlIndex = 0x00001000;
constexpr std::uint32_t kFlHugeFile = 0x00040000;
constexpr std::uint32_t kFlExtents = 0x00080000;
constexpr std::uint32_t kFlVerity = 0x00100000;
constexpr std::uint32_t kFlEaInode = 0x00200000;
constexpr std::uint32_t kFlInlineData = 0x10000000;
constexpr std::uint32_t kFlCasefold = 0x40000000;

// i_mode type bits.
constexpr std::uint16_t kIfmt = 0xF000;
constexpr std::uint16_t kIfsock = 0xC000;
constexpr std::uint16_t kIflnk = 0xA000;
constexpr std::uint16_t kIfreg = 0x8000;
constexpr std::uint16_t kIfblk = 0x6000;
constexpr std::uint16_t kIfdir = 0x4000;
constexpr std::uint16_t kIfchr = 0x2000;
constexpr std::uint16_t kIffifo = 0x1000;

// Directory entry file types.
enum DirFileType : std::uint8_t {
    kFtUnknown = 0,
    kFtRegular = 1,
    kFtDir = 2,
    kFtChrdev = 3,
    kFtBlkdev = 4,
    kFtFifo = 5,
    kFtSock = 6,
    kFtSymlink = 7,
};

// Performance knobs, not input guards: the walk is correct with any value.
constexpr std::size_t kGroupDescCacheEntries = 4096;  // descriptors kept decoded
constexpr std::uint64_t kStreamChunkBlocks = 256;     // blocks per Sink::write of a run

// Diagnostic codes. Tests and downstream agents key on these strings.
constexpr const char* kCodeSuperblockBad = "ext-superblock-bad";
constexpr const char* kCodeTruncatedImage = "ext-truncated-image";
constexpr const char* kCodeUnsupportedFeature = "ext-unsupported-feature";
constexpr const char* kCodeGdtCsumMismatch = "ext-gdt-csum-mismatch";
constexpr const char* kCodeInodeCsumMismatch = "ext-inode-csum-mismatch";
constexpr const char* kCodeMetadataCorrupt = "ext-metadata-corrupt";
constexpr const char* kCodeExtentCorrupt = "ext-extent-corrupt";
constexpr const char* kCodeBlockmapCorrupt = "ext-blockmap-corrupt";
constexpr const char* kCodeInlineDataCorrupt = "ext-inline-data-corrupt";
constexpr const char* kCodeDataTruncated = "ext-data-truncated";
constexpr const char* kCodeDirentCorrupt = "ext-dirent-corrupt";
constexpr const char* kCodeDirLoop = "ext-dir-loop";
constexpr const char* kCodeXattrCorrupt = "ext-xattr-corrupt";
constexpr const char* kCodeDeletedNoBlocks = "ext-deleted-no-blocks";
constexpr const char* kCodeDeletedBlocksReused = "ext-deleted-blocks-reused";
constexpr const char* kCodeLimitNodes = "ext-limit-nodes";
constexpr const char* kCodeLimitFiles = "ext-limit-files";
constexpr const char* kCodeLimitFileBytes = "ext-limit-file-bytes";
constexpr const char* kCodeSinkError = "ext-sink-error";
constexpr const char* kCodeRootInvalid = "ext-root-invalid";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}
std::string hex(std::uint64_t v) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    do {
        s.insert(s.begin(), digits[v & 0xf]);
        v >>= 4;
    } while (v);
    return "0x" + s;
}
std::string hex_fixed(std::uint32_t v, int width) {
    static const char digits[] = "0123456789abcdef";
    std::string s(static_cast<std::size_t>(width), '0');
    for (int i = width - 1; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = digits[v & 0xf];
        v >>= 4;
    }
    return "0x" + s;
}
std::string uuid_text(const std::uint8_t* p) {
    std::string s;
    static const char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) s += '-';
        s += digits[p[i] >> 4];
        s += digits[p[i] & 0xf];
    }
    return s;
}
std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    return a > std::numeric_limits<std::uint64_t>::max() - b
               ? std::numeric_limits<std::uint64_t>::max()
               : a + b;
}
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    if (a == 0 || b == 0) return 0;
    return a > std::numeric_limits<std::uint64_t>::max() / b
               ? std::numeric_limits<std::uint64_t>::max()
               : a * b;
}
std::size_t align4(std::size_t n) {
    return (n + 3) & ~static_cast<std::size_t>(3);
}
template <class T>
T ld(const std::uint8_t* p) {
    return load_int<T>(p, Endian::Little);
}

// Names of the feature bits, for attrs. Unknown bits are rendered as hex.
struct FlagName {
    std::uint32_t bit;
    const char* name;
};
constexpr FlagName kCompatNames[] = {
    {0x0001, "dir_prealloc"}, {0x0002, "imagic_inodes"},  {0x0004, "has_journal"},
    {0x0008, "ext_attr"},     {0x0010, "resize_inode"},   {0x0020, "dir_index"},
    {0x0040, "lazy_bg"},      {0x0100, "exclude_bitmap"}, {0x0200, "sparse_super2"},
    {0x0400, "fast_commit"},  {0x0800, "stable_inodes"},  {0x1000, "orphan_file"},
};
constexpr FlagName kIncompatNames[] = {
    {0x0001, "compression"}, {0x0002, "filetype"},    {0x0004, "recover"},  {0x0008, "journal_dev"},
    {0x0010, "meta_bg"},     {0x0040, "extents"},     {0x0080, "64bit"},    {0x0100, "mmp"},
    {0x0200, "flex_bg"},     {0x0400, "ea_inode"},    {0x1000, "dirdata"},  {0x2000, "csum_seed"},
    {0x4000, "largedir"},    {0x8000, "inline_data"}, {0x10000, "encrypt"}, {0x20000, "casefold"},
};
constexpr FlagName kRoCompatNames[] = {
    {0x0001, "sparse_super"}, {0x0002, "large_file"},      {0x0004, "btree_dir"},
    {0x0008, "huge_file"},    {0x0010, "gdt_csum"},        {0x0020, "dir_nlink"},
    {0x0040, "extra_isize"},  {0x0080, "has_snapshot"},    {0x0100, "quota"},
    {0x0200, "bigalloc"},     {0x0400, "metadata_csum"},   {0x0800, "replica"},
    {0x1000, "read-only"},    {0x2000, "project"},         {0x4000, "shared_blocks"},
    {0x8000, "verity"},       {0x10000, "orphan_present"},
};
template <std::size_t N>
std::string flag_names(std::uint32_t v, const FlagName (&table)[N]) {
    std::string s;
    std::uint32_t seen = 0;
    for (const FlagName& f : table) {
        if (v & f.bit) {
            if (!s.empty()) s += ',';
            s += f.name;
            seen |= f.bit;
        }
    }
    if (v & ~seen) {
        if (!s.empty()) s += ',';
        s += hex(v & ~seen);
    }
    return s;
}

const char* creator_os_name(std::uint32_t v) {
    switch (v) {
        case 0:
            return "linux";
        case 1:
            return "hurd";
        case 2:
            return "masix";
        case 3:
            return "freebsd";
        case 4:
            return "lites";
        default:
            return "unknown";
    }
}

const char* xattr_prefix(std::uint8_t index) {
    switch (index) {
        case 0:
            return "";
        case 1:
            return "user.";
        case 2:
            return "system.posix_acl_access";
        case 3:
            return "system.posix_acl_default";
        case 4:
            return "trusted.";
        case 6:
            return "security.";
        case 7:
            return "system.";
        case 8:
            return "system.richacl";
        case 9:
            return "encryption.";
        case 10:
            return "hurd.";
        default:
            return nullptr;
    }
}

// CRC-16 (ANSI, poly 0x8005 reflected) as the kernel's crc16() used by the
// gdt_csum feature before metadata_csum existed.
std::uint16_t crc16_update(std::uint16_t crc, const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int k = 0; k < 8; ++k)
            crc = static_cast<std::uint16_t>((crc & 1u) ? (crc >> 1) ^ 0xA001u : (crc >> 1));
    }
    return crc;
}

std::uint32_t crc32c_update(std::uint32_t crc, const std::uint8_t* p, std::size_t n) {
    return discovery::crc32_update<discovery::kCrc32cPoly>(crc,
                                                           std::span<const std::uint8_t>(p, n));
}

// rec_len as stored on disk -> bytes (ext4_rec_len_from_disk).
std::uint32_t rec_len_from_disk(std::uint16_t dlen, std::uint64_t block_size) {
    std::uint32_t len = dlen;
    if (block_size < 65536) return len;
    if (len == kMaxRecLen || len == 0) return static_cast<std::uint32_t>(block_size);
    return (len & 65532u) | ((len & 3u) << 16);
}

EntryKind kind_for_mode(std::uint16_t mode) {
    switch (mode & kIfmt) {
        case kIfreg:
            return EntryKind::Regular;
        case kIfdir:
            return EntryKind::Directory;
        case kIflnk:
            return EntryKind::Symlink;
        case kIfchr:
            return EntryKind::CharDevice;
        case kIfblk:
            return EntryKind::BlockDevice;
        case kIffifo:
            return EntryKind::Fifo;
        case kIfsock:
            return EntryKind::Socket;
        default:
            return EntryKind::Unknown;
    }
}

EntryKind kind_for_file_type(std::uint8_t ft) {
    switch (ft) {
        case kFtRegular:
            return EntryKind::Regular;
        case kFtDir:
            return EntryKind::Directory;
        case kFtChrdev:
            return EntryKind::CharDevice;
        case kFtBlkdev:
            return EntryKind::BlockDevice;
        case kFtFifo:
            return EntryKind::Fifo;
        case kFtSock:
            return EntryKind::Socket;
        case kFtSymlink:
            return EntryKind::Symlink;
        default:
            return EntryKind::Unknown;
    }
}

// ------------------------------------------------------------------ structures

struct Superblock {
    std::uint32_t inodes_count = 0, free_inodes = 0, first_data_block = 0, log_block_size = 0;
    std::uint32_t blocks_per_group = 0, inodes_per_group = 0, mtime = 0, wtime = 0;
    std::uint16_t mnt_count = 0, max_mnt_count = 0, state = 0, errors = 0;
    std::uint32_t lastcheck = 0, creator_os = 0, rev_level = 0, first_ino = kGoodOldFirstIno;
    std::uint16_t inode_size = kGoodOldInodeSize;
    std::uint32_t compat = 0, incompat = 0, ro_compat = 0;
    std::array<std::uint8_t, 16> uuid{};
    std::string volume_name, last_mounted;
    std::uint32_t journal_inum = 0;
    std::uint16_t desc_size = kMinDescSize;
    std::uint32_t first_meta_bg = 0, mkfs_time = 0;
    std::uint64_t blocks_count = 0, free_blocks = 0;
    std::uint16_t min_extra_isize = 0;
    std::uint8_t checksum_type = 0;
    std::uint32_t checksum_seed = 0;
    std::uint16_t encoding = 0;
    std::uint32_t checksum = 0;
    // derived
    std::uint64_t block_size = 0;
    std::uint64_t groups = 0;
    std::uint32_t csum_seed = 0;  // crc32c seed for metadata_csum
    bool has_64bit = false, has_filetype = false, has_metadata_csum = false, has_gdt_csum = false;
    bool has_meta_bg = false, has_sparse_super = false, has_huge_file = false;
    bool has_journal = false, has_inline_data = false, has_largedir = false;
    std::string format;  // "ext2" | "ext3" | "ext4"
};

struct GroupDesc {
    std::uint64_t block_bitmap = 0, inode_bitmap = 0, inode_table = 0;
    std::uint16_t flags = 0;
    std::uint32_t itable_unused = 0;
};

// The union of inode fields the walk needs, decoded once.
struct Inode {
    std::uint32_t number = 0;
    std::uint16_t mode = 0;
    std::uint32_t uid = 0, gid = 0;
    std::uint64_t size = 0;
    std::optional<std::int64_t> atime, ctime, mtime, crtime;
    std::optional<std::uint32_t> atime_nsec, ctime_nsec, mtime_nsec;
    std::uint32_t dtime = 0;
    std::uint16_t links = 0;
    std::uint64_t blocks512 = 0;  // i_blocks in 512-byte units
    std::uint32_t flags = 0;
    std::uint32_t generation = 0;
    std::uint64_t file_acl = 0;
    std::uint16_t extra_isize = 0;
    std::array<std::uint8_t, kIBlockBytes> iblock{};
    std::vector<std::uint8_t> raw;  // the whole on-disk inode (for xattrs / inline data)
    bool csum_ok = true;            // false when metadata_csum is on and it mismatched
    bool csum_checked = false;
};

struct DirEntry {
    std::uint32_t inode = 0;
    std::uint8_t file_type = 0;
    std::string name;
};

// A directory-entry remnant found in slack space, or a live one recorded for
// name resolution of freed inodes.
struct HistDirent {
    std::string parent_path;  // "" for the root
    std::string name;
    std::uint32_t inode = 0;
    std::uint8_t file_type = 0;
};

// One contiguous mapping of logical blocks to physical blocks. `physical`
// 0 (or `uninit`) means the run reads as zeros.
struct Run {
    std::uint64_t logical = 0;
    std::uint64_t length = 0;
    std::uint64_t physical = 0;
    bool uninit = false;
};

// A set of inode numbers that grows only with the pages touched, so a
// hostile s_inodes_count cannot make it allocate 512 MiB up front.
class InodeSet {
   public:
    bool test(std::uint32_t ino) const {
        const auto it = pages_.find(ino >> kShift);
        return it != pages_.end() && it->second[ino & kMask];
    }
    void set(std::uint32_t ino) {
        auto& page = pages_[ino >> kShift];
        if (page.empty()) page.assign(1u << kShift, false);
        page[ino & kMask] = true;
    }

   private:
    static constexpr std::uint32_t kShift = 15;
    static constexpr std::uint32_t kMask = (1u << kShift) - 1;
    std::map<std::uint32_t, std::vector<bool>> pages_;
};

}  // namespace

// ------------------------------------------------------------------ Impl

struct ExtReader::Impl {
    Span span;
    Superblock sb;
    bool opened = false;
    std::vector<Diagnostic> open_diags;  // reported at the start of every walk

    // Limits in force for the current walk (rule 4: every guard is a Limits
    // field). Set by walk(); the defaults apply while open() reads tables.
    const Limits* lim = nullptr;
    const Limits& limits() const {
        static const Limits kDefault{};
        return lim ? *lim : kDefault;
    }

    // caches: group descriptors, one bitmap block per kind, the indirect
    // blocks of the file being streamed
    std::map<std::uint32_t, GroupDesc> gd_cache;
    struct BlockBuf {
        std::uint64_t block = std::numeric_limits<std::uint64_t>::max();
        std::vector<std::uint8_t> data;
    };
    BlockBuf block_bitmap_buf, inode_bitmap_buf;
    std::array<BlockBuf, 6> ind_cache;  // single; double 1,2; triple 1,2,3
    std::vector<std::uint8_t> dir_buf, data_buf, zero_buf, inline_buf, xattr_buf;
    std::array<std::vector<std::uint8_t>, kMaxExtentDepth + 1> extent_bufs;

    // per-walk state
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        std::uint64_t nodes = 0;
        bool stop = false;             // a limit tripped: unwind
        InodeSet reachable;            // every inode a live directory entry led to
        InodeSet dirs_seen;            // directories already listed (loop / hard-linked dir guard)
        std::vector<HistDirent> hist;  // slack dirents (history only)
        std::map<std::string, std::uint32_t> live;  // path -> inode (history only)
        std::uint64_t inode_csum_bad = 0;           // counted, reported once
        std::string inode_csum_first;
        std::uint32_t feature_reported = 0;  // per-entry unsupported flags reported once each
    };

    void diag(WalkResult& out, Severity s, const char* code, std::string msg) const {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }

    // -------------------------------------------------------------- superblock / groups
    Status parse_superblock();
    void check_group_descriptors();
    bool group_has_super(std::uint64_t g) const;
    std::optional<std::uint64_t> group_desc_offset(std::uint64_t g) const;
    bool group_desc(std::uint32_t g, GroupDesc& out, std::string* why);
    bool verify_group_desc(std::uint32_t g, const std::uint8_t* d) const;
    std::optional<std::uint64_t> block_offset(std::uint64_t blk) const {
        if (blk >= sb.blocks_count) return std::nullopt;
        const std::uint64_t off = sat_mul(blk, sb.block_size);  // 64-bit pointers can wrap
        if (off > span.size() || sb.block_size > span.size() - off) return std::nullopt;
        return off;
    }
    bool read_block(std::uint64_t blk, std::vector<std::uint8_t>& buf, std::string* why);
    bool read_block_cached(std::uint64_t blk, BlockBuf& buf, std::string* why);
    // Bitmap bit for a block / inode; nullopt when the bitmap is unreadable.
    std::optional<bool> block_allocated(std::uint64_t blk);
    std::optional<bool> inode_allocated(std::uint32_t ino);

    // -------------------------------------------------------------- inodes
    bool read_inode(std::uint32_t ino, Inode& out, std::string* why);
    bool verify_inode_csum(const Inode& in) const;
    bool has_extra(const Inode& in, std::size_t field_end) const {
        return sb.inode_size > kGoodOldInodeSize && in.extra_isize >= 4 &&
               static_cast<std::size_t>(kGoodOldInodeSize) + in.extra_isize >= field_end &&
               field_end <= in.raw.size();
    }
    std::string xattr_summary(const Inode& in, std::vector<std::uint8_t>* system_data,
                              std::string* why);
    bool parse_xattr_entries(const std::uint8_t* base, std::size_t len, std::size_t first_entry,
                             std::size_t value_base, std::string& summary, std::uint64_t& count,
                             std::vector<std::uint8_t>* system_data, std::string* why);

    // -------------------------------------------------------------- block mapping
    // Calls `fn(run)` for every mapped run in logical order until it returns
    // false. `max_blocks` bounds the logical range of interest. Returns false
    // with `code`/`why` when the map itself is corrupt (runs before the
    // corruption were delivered).
    template <class Fn>
    bool map_runs(const Inode& in, std::uint64_t max_blocks, Fn&& fn, const char** code,
                  std::string* why);
    // `want_depth` / `want_first`: what the parent index entry promised for
    // this node (nullopt at the root). The kernel refuses a node that
    // disagrees (__ext4_ext_check), and so does this reader: without it an
    // index block that points at itself is re-entered at every level.
    template <class Fn>
    bool walk_extent_node(const std::uint8_t* node, std::size_t len, std::size_t depth,
                          std::optional<std::uint16_t> want_depth,
                          std::optional<std::uint32_t> want_first, std::uint64_t max_blocks,
                          std::uint64_t& next_logical, Fn& fn, bool& stopped, const char** code,
                          std::string* why);
    template <class Fn>
    bool walk_block_map(const Inode& in, std::uint64_t max_blocks, Fn& fn, const char** code,
                        std::string* why);
    std::uint64_t indirect_ptr(std::uint64_t blk, std::uint64_t idx, std::size_t cache, bool& bad,
                               std::string* why);
    bool inline_data(const Inode& in, std::vector<std::uint8_t>& out, std::string* why);
    bool fast_symlink(const Inode& in) const;

    // -------------------------------------------------------------- data
    bool write_zeros(Walk& w, std::uint64_t n);
    bool stream_data(Walk& w, const std::string& path, const Inode& in, std::uint64_t size,
                     bool unallocated, bool& truncated, std::uint64_t* reused);
    bool read_symlink(const Inode& in, std::string& target, std::string* why);

    // -------------------------------------------------------------- directories
    bool read_directory(Walk& w, const Inode& dir, const std::string& path,
                        std::vector<DirEntry>& entries, bool* limit_hit);
    void parse_dir_block(Walk& w, const std::uint8_t* blk, std::size_t n, bool inline_dir,
                         bool indexed, std::uint64_t block_index, const std::string& path,
                         std::vector<DirEntry>& entries, bool* limit_hit);
    void scan_slack(Walk& w, const std::uint8_t* blk, std::size_t n, std::size_t from,
                    std::size_t to, const std::string& path);

    // -------------------------------------------------------------- walk
    FileMeta make_meta(Walk& w, const std::string& path, const Inode& in);
    void emit_regular(Walk& w, FileMeta meta, const Inode& in, bool unallocated);
    bool emit_other(Walk& w, const FileMeta& meta);
    bool walk_live(Walk& w);
    void walk_history(Walk& w);
    bool count_node(Walk& w, const std::string& path);
};

// ---------------------------------------------------------------- superblock

Status ExtReader::Impl::parse_superblock() {
    if (span.size() < kSuperblockOffset + kSuperblockSize)
        return Status::fail("ext-superblock-bad: fewer than 2048 bytes; no superblock");
    const auto raw = span.bytes(kSuperblockOffset, kSuperblockSize);
    if (!raw) return Status::fail("ext-superblock-bad: superblock unreadable");
    const std::uint8_t* p = raw->data();
    auto u16 = [&](std::size_t off) { return ld<std::uint16_t>(p + off); };
    auto u32 = [&](std::size_t off) { return ld<std::uint32_t>(p + off); };
    auto u8 = [&](std::size_t off) { return p[off]; };

    if (u16(0x38) != kMagic)
        return Status::fail("ext-superblock-bad: s_magic " + hex(u16(0x38)) + " is not 0xef53");
    sb.inodes_count = u32(0x00);
    const std::uint32_t blocks_lo = u32(0x04);
    const std::uint32_t free_blocks_lo = u32(0x0C);
    sb.free_inodes = u32(0x10);
    sb.first_data_block = u32(0x14);
    sb.log_block_size = u32(0x18);
    sb.blocks_per_group = u32(0x20);
    sb.inodes_per_group = u32(0x28);
    sb.mtime = u32(0x2C);
    sb.wtime = u32(0x30);
    sb.mnt_count = u16(0x34);
    sb.max_mnt_count = u16(0x36);
    sb.state = u16(0x3A);
    sb.errors = u16(0x3C);
    sb.lastcheck = u32(0x40);
    sb.creator_os = u32(0x48);
    sb.rev_level = u32(0x4C);
    if (sb.rev_level > 1)
        return Status::fail("ext-superblock-bad: s_rev_level " + dec(sb.rev_level) +
                            " (only 0 and 1 exist)");
    if (sb.log_block_size > 6)
        return Status::fail("ext-superblock-bad: s_log_block_size " + dec(sb.log_block_size) +
                            " (block size would exceed 64 KiB)");
    sb.block_size = 1024ull << sb.log_block_size;
    if (sb.rev_level >= 1) {
        sb.first_ino = u32(0x54);
        sb.inode_size = u16(0x58);
        sb.compat = u32(0x5C);
        sb.incompat = u32(0x60);
        sb.ro_compat = u32(0x64);
        std::memcpy(sb.uuid.data(), p + 0x68, 16);
        sb.volume_name = *span.cstring(kSuperblockOffset + 0x78, 16);
        sb.last_mounted = *span.cstring(kSuperblockOffset + 0x88, 64);
        sb.journal_inum = u32(0xE0);
        sb.desc_size = u16(0xFE);
        sb.first_meta_bg = u32(0x104);
        sb.mkfs_time = u32(0x108);
        sb.min_extra_isize = u16(0x15C);
        sb.checksum_type = u8(0x175);
        sb.checksum_seed = u32(0x270);
        sb.encoding = u16(0x27C);
        sb.checksum = u32(0x3FC);
    }
    sb.has_64bit = (sb.incompat & kIncompat64Bit) != 0;
    sb.has_filetype = (sb.incompat & kIncompatFiletype) != 0;
    sb.has_meta_bg = (sb.incompat & kIncompatMetaBg) != 0;
    sb.has_inline_data = (sb.incompat & kIncompatInlineData) != 0;
    sb.has_largedir = (sb.incompat & kIncompatLargedir) != 0;
    sb.has_metadata_csum = (sb.ro_compat & kRoCompatMetadataCsum) != 0;
    sb.has_gdt_csum = (sb.ro_compat & kRoCompatGdtCsum) != 0 && !sb.has_metadata_csum;
    sb.has_sparse_super = (sb.ro_compat & kRoCompatSparseSuper) != 0;
    sb.has_huge_file = (sb.ro_compat & kRoCompatHugeFile) != 0;
    sb.has_journal = (sb.compat & kCompatHasJournal) != 0;

    sb.blocks_count = blocks_lo;
    sb.free_blocks = free_blocks_lo;
    if (sb.has_64bit) {
        sb.blocks_count |= static_cast<std::uint64_t>(u32(0x150)) << 32;
        sb.free_blocks |= static_cast<std::uint64_t>(u32(0x158)) << 32;
    }
    if (!sb.has_64bit || sb.desc_size < kMinDescSize) sb.desc_size = kMinDescSize;
    if (sb.has_64bit && sb.desc_size < kDescSize64) sb.desc_size = kDescSize64;
    if (sb.rev_level == 0) sb.inode_size = kGoodOldInodeSize;
    if (sb.first_ino < kRootIno + 1) sb.first_ino = kGoodOldFirstIno;

    // Hard constraints: anything a real superblock could never contain.
    if (sb.inode_size < kGoodOldInodeSize || (sb.inode_size & (sb.inode_size - 1)) != 0 ||
        sb.inode_size > sb.block_size)
        return Status::fail("ext-superblock-bad: s_inode_size " + dec(sb.inode_size) +
                            " (must be a power of two in 128.." + dec(sb.block_size) + ")");
    if (sb.blocks_count == 0 || sb.inodes_count == 0 || sb.blocks_per_group == 0 ||
        sb.inodes_per_group == 0)
        return Status::fail("ext-superblock-bad: zero block, inode or per-group count");
    if (sb.blocks_per_group > sb.block_size * 8 || sb.inodes_per_group > sb.block_size * 8)
        return Status::fail("ext-superblock-bad: blocks_per_group " + dec(sb.blocks_per_group) +
                            " / inodes_per_group " + dec(sb.inodes_per_group) +
                            " exceed one bitmap block");
    if ((sb.block_size == 1024 && sb.first_data_block != 1) ||
        (sb.block_size != 1024 && sb.first_data_block != 0))
        return Status::fail("ext-superblock-bad: s_first_data_block " + dec(sb.first_data_block) +
                            " disagrees with a block size of " + dec(sb.block_size));
    if (sb.desc_size > sb.block_size || (sb.desc_size & (sb.desc_size - 1)) != 0)
        return Status::fail("ext-superblock-bad: s_desc_size " + dec(sb.desc_size));
    if (sb.first_data_block >= sb.blocks_count)
        return Status::fail("ext-superblock-bad: s_first_data_block beyond blocks_count");
    if (sb.inodes_per_group * static_cast<std::uint64_t>(sb.inode_size) >
        sb.block_size * static_cast<std::uint64_t>(sb.blocks_per_group))
        return Status::fail("ext-superblock-bad: inode table larger than its block group");

    // The image may be shorter than the filesystem claims (partial dump). Clamp
    // the block count to what is present; every read is range-checked anyway.
    const std::uint64_t claimed = sat_mul(sb.blocks_count, sb.block_size);
    sb.groups = (sb.blocks_count - sb.first_data_block - 1) / sb.blocks_per_group + 1;
    const std::uint64_t inodes_by_groups = sat_mul(sb.groups, sb.inodes_per_group);
    if (claimed > span.size()) {
        // Only the groups whose first block is inside the data can hold a
        // descriptor, a bitmap or an inode table worth scanning; a hostile
        // 64-bit blocks_count must not turn every per-group loop into 2^50
        // iterations.
        const std::uint64_t present_blocks = span.size() / sb.block_size;
        const std::uint64_t present_groups =
            present_blocks > sb.first_data_block
                ? (present_blocks - sb.first_data_block - 1) / sb.blocks_per_group + 1
                : 1;
        const std::uint64_t all_groups = sb.groups;
        sb.groups = std::min(sb.groups, present_groups);
        open_diags.push_back({Severity::Warning, kCodeTruncatedImage,
                              "blocks_count * block_size = " + dec(claimed) + " exceeds the " +
                                  dec(span.size()) + " bytes available; " + dec(sb.groups) +
                                  " of " + dec(all_groups) +
                                  " block groups are inside the data and reads past the end fail"});
    }
    if (inodes_by_groups != sb.inodes_count)
        open_diags.push_back({Severity::Warning, kCodeMetadataCorrupt,
                              "inodes_count " + dec(sb.inodes_count) + " != block_groups " +
                                  dec(sb.groups) + " * inodes_per_group " +
                                  dec(sb.inodes_per_group) + "; walking what the tables hold"});

    // Format id, the same way the validator decides it.
    if (sb.rev_level == 1 &&
        ((sb.incompat & kIncompatExt4Mask) != 0 || (sb.ro_compat & kRoCompatExt4Mask) != 0))
        sb.format = "ext4";
    else if (sb.rev_level == 1 && sb.has_journal)
        sb.format = "ext3";
    else
        sb.format = "ext2";

    // metadata_csum: the seed is s_checksum_seed with csum_seed, else crc32c(~0, uuid).
    if (sb.has_metadata_csum) {
        sb.csum_seed = (sb.incompat & kIncompatCsumSeed) != 0
                           ? sb.checksum_seed
                           : crc32c_update(0xFFFFFFFFu, sb.uuid.data(), 16);
        const std::uint32_t computed = crc32c_update(0xFFFFFFFFu, p, 0x3FC);
        if (computed != sb.checksum)
            open_diags.push_back({Severity::Warning, kCodeSuperblockBad,
                                  "superblock crc32c " + hex(computed) + " != s_checksum " +
                                      hex(sb.checksum) + "; continuing with the fields as read"});
        if (sb.checksum_type != 1)
            open_diags.push_back({Severity::Warning, kCodeUnsupportedFeature,
                                  "s_checksum_type " + dec(sb.checksum_type) +
                                      " is not crc32c; checksums are not verified"});
    }
    if (const std::uint32_t unknown = sb.incompat & ~kIncompatKnown; unknown != 0)
        open_diags.push_back({Severity::Warning, kCodeUnsupportedFeature,
                              "unknown incompat feature bits " + hex(unknown) +
                                  "; the walk continues but may misread structures"});
    if ((sb.incompat & kIncompatRecover) != 0)
        open_diags.push_back({Severity::Info, kCodeUnsupportedFeature,
                              "the journal needs recovery (INCOMPAT_RECOVER); it is not replayed, "
                              "so the listing is the on-disk state before replay"});
    if ((sb.incompat & kIncompatEncrypt) != 0)
        open_diags.push_back({Severity::Info, kCodeUnsupportedFeature,
                              "filesystem has encrypted files; their names and data are listed "
                              "as stored, not decrypted"});
    if ((sb.incompat & kIncompatCasefold) != 0)
        open_diags.push_back({Severity::Info, kCodeUnsupportedFeature,
                              "casefold directories are walked byte-wise; names are not folded"});
    return Status::success();
}

bool ExtReader::Impl::group_has_super(std::uint64_t g) const {
    if (!sb.has_sparse_super) return true;
    if (g <= 1) return true;
    for (const std::uint64_t base : {3ull, 5ull, 7ull}) {
        std::uint64_t v = base;
        while (v < g) v = sat_mul(v, base);
        if (v == g) return true;
    }
    return false;
}

std::optional<std::uint64_t> ExtReader::Impl::group_desc_offset(std::uint64_t g) const {
    if (g >= sb.groups) return std::nullopt;
    const std::uint64_t per_block = sb.block_size / sb.desc_size;
    const std::uint64_t meta_first = sat_mul(sb.first_meta_bg, per_block);
    if (!sb.has_meta_bg || g < meta_first) {
        // The classic table: contiguous from the block after the superblock's.
        const std::uint64_t gdt_block = sb.first_data_block + 1;
        return sat_add(sat_mul(gdt_block, sb.block_size), sat_mul(g, sb.desc_size));
    }
    // meta_bg: descriptors of meta group m sit in the first block of its first
    // group, after that group's superblock backup when it has one.
    const std::uint64_t m = g / per_block;
    const std::uint64_t first_group = m * per_block;
    const std::uint64_t first_block =
        sat_add(sb.first_data_block, sat_mul(first_group, sb.blocks_per_group));
    const std::uint64_t desc_block = first_block + (group_has_super(first_group) ? 1 : 0);
    return sat_add(sat_mul(desc_block, sb.block_size), sat_mul(g % per_block, sb.desc_size));
}

bool ExtReader::Impl::verify_group_desc(std::uint32_t g, const std::uint8_t* d) const {
    const std::uint16_t stored = ld<std::uint16_t>(d + 0x1E);
    std::uint8_t gle[4];
    gle[0] = static_cast<std::uint8_t>(g);
    gle[1] = static_cast<std::uint8_t>(g >> 8);
    gle[2] = static_cast<std::uint8_t>(g >> 16);
    gle[3] = static_cast<std::uint8_t>(g >> 24);
    const std::uint8_t zero2[2] = {0, 0};
    if (sb.has_metadata_csum) {
        std::uint32_t c = crc32c_update(sb.csum_seed, gle, 4);
        c = crc32c_update(c, d, 0x1E);
        c = crc32c_update(c, zero2, 2);
        if (sb.desc_size > 0x20) c = crc32c_update(c, d + 0x20, sb.desc_size - 0x20);
        return static_cast<std::uint16_t>(c & 0xFFFFu) == stored;
    }
    std::uint16_t c = crc16_update(0xFFFFu, sb.uuid.data(), 16);
    c = crc16_update(c, gle, 4);
    c = crc16_update(c, d, 0x1E);
    if (sb.desc_size > 0x20) c = crc16_update(c, d + 0x20, sb.desc_size - 0x20);
    return c == stored;
}

bool ExtReader::Impl::group_desc(std::uint32_t g, GroupDesc& out, std::string* why) {
    if (const auto hit = gd_cache.find(g); hit != gd_cache.end()) {
        out = hit->second;
        return true;
    }
    const auto off = group_desc_offset(g);
    if (!off) {
        if (why) *why = "group " + dec(g) + " is beyond the " + dec(sb.groups) + " block groups";
        return false;
    }
    const auto raw = span.bytes(*off, sb.desc_size);
    if (!raw) {
        if (why) *why = "group descriptor " + dec(g) + " at " + hex(*off) + " is outside the image";
        return false;
    }
    const std::uint8_t* d = raw->data();
    out = GroupDesc{};
    out.block_bitmap = ld<std::uint32_t>(d + 0x00);
    out.inode_bitmap = ld<std::uint32_t>(d + 0x04);
    out.inode_table = ld<std::uint32_t>(d + 0x08);
    out.flags = ld<std::uint16_t>(d + 0x12);
    out.itable_unused = ld<std::uint16_t>(d + 0x1C);
    if (sb.desc_size >= kDescSize64) {
        out.block_bitmap |= static_cast<std::uint64_t>(ld<std::uint32_t>(d + 0x20)) << 32;
        out.inode_bitmap |= static_cast<std::uint64_t>(ld<std::uint32_t>(d + 0x24)) << 32;
        out.inode_table |= static_cast<std::uint64_t>(ld<std::uint32_t>(d + 0x28)) << 32;
        out.itable_unused |= static_cast<std::uint32_t>(ld<std::uint16_t>(d + 0x32)) << 16;
    }
    if (gd_cache.size() >= kGroupDescCacheEntries) gd_cache.clear();
    gd_cache[g] = out;
    return true;
}

// One pass over every group descriptor at open: checksum verification is
// summarised in one diagnostic so a wrong seed does not produce one line per
// group. Descriptors that cannot be read are reported when a walk needs them.
void ExtReader::Impl::check_group_descriptors() {
    if (!sb.has_metadata_csum && !sb.has_gdt_csum) return;
    std::uint64_t bad = 0, checked = 0;
    std::string first;
    for (std::uint64_t g = 0; g < sb.groups; ++g) {
        const auto off = group_desc_offset(g);
        if (!off) break;
        const auto raw = span.bytes(*off, sb.desc_size);
        if (!raw) break;
        ++checked;
        if (!verify_group_desc(static_cast<std::uint32_t>(g), raw->data())) {
            if (bad == 0) first = dec(g);
            ++bad;
        }
    }
    if (bad != 0)
        open_diags.push_back({Severity::Warning, kCodeGdtCsumMismatch,
                              dec(bad) + " of " + dec(checked) + " group descriptors fail their " +
                                  (sb.has_metadata_csum ? "crc32c" : "crc16") +
                                  " checksum (first: group " + first +
                                  "); their bitmaps and inode tables may be stale"});
}

bool ExtReader::Impl::read_block(std::uint64_t blk, std::vector<std::uint8_t>& buf,
                                 std::string* why) {
    const auto off = block_offset(blk);
    if (!off) {
        if (why) *why = "block " + dec(blk) + " lies outside the image";
        return false;
    }
    buf.resize(static_cast<std::size_t>(sb.block_size));
    if (span.read(*off, buf) != sb.block_size) {
        if (why) *why = "block " + dec(blk) + " could not be read";
        return false;
    }
    return true;
}

bool ExtReader::Impl::read_block_cached(std::uint64_t blk, BlockBuf& buf, std::string* why) {
    if (buf.block == blk && !buf.data.empty()) return true;
    buf.block = std::numeric_limits<std::uint64_t>::max();
    if (!read_block(blk, buf.data, why)) return false;
    buf.block = blk;
    return true;
}

std::optional<bool> ExtReader::Impl::block_allocated(std::uint64_t blk) {
    if (blk < sb.first_data_block || blk >= sb.blocks_count) return std::nullopt;
    const std::uint64_t rel = blk - sb.first_data_block;
    const std::uint64_t g = rel / sb.blocks_per_group;
    const std::uint64_t idx = rel % sb.blocks_per_group;
    GroupDesc gd;
    if (g > std::numeric_limits<std::uint32_t>::max() ||
        !group_desc(static_cast<std::uint32_t>(g), gd, nullptr))
        return std::nullopt;
    if (gd.flags & kBgBlockUninit) return false;  // bitmap not written: nothing allocated yet
    if (!read_block_cached(gd.block_bitmap, block_bitmap_buf, nullptr)) return std::nullopt;
    return (block_bitmap_buf.data[static_cast<std::size_t>(idx / 8)] >> (idx % 8)) & 1u;
}

std::optional<bool> ExtReader::Impl::inode_allocated(std::uint32_t ino) {
    if (ino == 0 || ino > sb.inodes_count) return std::nullopt;
    const std::uint32_t g = (ino - 1) / sb.inodes_per_group;
    const std::uint32_t idx = (ino - 1) % sb.inodes_per_group;
    GroupDesc gd;
    if (!group_desc(g, gd, nullptr)) return std::nullopt;
    if (gd.flags & kBgInodeUninit) return false;
    if (!read_block_cached(gd.inode_bitmap, inode_bitmap_buf, nullptr)) return std::nullopt;
    return (inode_bitmap_buf.data[idx / 8] >> (idx % 8)) & 1u;
}

// ---------------------------------------------------------------- inodes

bool ExtReader::Impl::verify_inode_csum(const Inode& in) const {
    const std::uint8_t* p = in.raw.data();
    const std::size_t isz = in.raw.size();
    std::uint8_t le[4];
    auto put = [&](std::uint32_t v) {
        le[0] = static_cast<std::uint8_t>(v);
        le[1] = static_cast<std::uint8_t>(v >> 8);
        le[2] = static_cast<std::uint8_t>(v >> 16);
        le[3] = static_cast<std::uint8_t>(v >> 24);
    };
    put(in.number);
    std::uint32_t c = crc32c_update(sb.csum_seed, le, 4);
    put(in.generation);
    c = crc32c_update(c, le, 4);
    const std::uint8_t zero2[2] = {0, 0};
    c = crc32c_update(c, p, 0x7C);
    c = crc32c_update(c, zero2, 2);
    c = crc32c_update(c, p + 0x7E, kGoodOldInodeSize - 0x7E);
    const bool has_hi = isz > kGoodOldInodeSize && in.extra_isize >= 4;
    if (isz > kGoodOldInodeSize) {
        c = crc32c_update(c, p + kGoodOldInodeSize, 0x82 - kGoodOldInodeSize);
        std::size_t off = 0x82;
        if (has_hi) {
            c = crc32c_update(c, zero2, 2);
            off = 0x84;
        }
        c = crc32c_update(c, p + off, isz - off);
    }
    const std::uint32_t lo = ld<std::uint16_t>(p + 0x7C);
    if (!has_hi) return (c & 0xFFFFu) == lo;
    const std::uint32_t hi = ld<std::uint16_t>(p + 0x82);
    return c == (lo | (hi << 16));
}

bool ExtReader::Impl::read_inode(std::uint32_t ino, Inode& out, std::string* why) {
    out = Inode{};
    out.number = ino;
    if (ino == 0 || ino > sb.inodes_count) {
        if (why) *why = "inode " + dec(ino) + " is outside 1.." + dec(sb.inodes_count);
        return false;
    }
    const std::uint32_t g = (ino - 1) / sb.inodes_per_group;
    const std::uint64_t idx = (ino - 1) % sb.inodes_per_group;
    GroupDesc gd;
    if (!group_desc(g, gd, why)) return false;
    const auto table = block_offset(gd.inode_table);
    if (!table) {
        if (why)
            *why = "inode table of group " + dec(g) + " (block " + dec(gd.inode_table) +
                   ") lies outside the image";
        return false;
    }
    const std::uint64_t off = sat_add(*table, idx * sb.inode_size);
    out.raw.resize(sb.inode_size);
    if (span.read(off, out.raw) != sb.inode_size) {
        if (why) *why = "inode " + dec(ino) + " at " + hex(off) + " lies outside the image";
        return false;
    }
    const std::uint8_t* p = out.raw.data();
    auto u16 = [&](std::size_t o) { return ld<std::uint16_t>(p + o); };
    auto u32 = [&](std::size_t o) { return ld<std::uint32_t>(p + o); };
    out.mode = u16(0x00);
    out.uid = u16(0x02);
    out.gid = u16(0x18);
    const std::uint32_t size_lo = u32(0x04);
    const std::uint32_t atime = u32(0x08), ctime = u32(0x0C), mtime = u32(0x10);
    out.dtime = u32(0x14);
    out.links = u16(0x1A);
    out.blocks512 = u32(0x1C);
    out.flags = u32(0x20);
    std::memcpy(out.iblock.data(), p + 0x28, kIBlockBytes);
    out.generation = u32(0x64);
    out.file_acl = u32(0x68);
    const std::uint32_t size_hi = u32(0x6C);
    // osd2 (Linux layout; the uid/gid high halves sit at the same place for Hurd)
    out.uid |= static_cast<std::uint32_t>(u16(0x78)) << 16;
    out.gid |= static_cast<std::uint32_t>(u16(0x7A)) << 16;
    if (sb.has_huge_file) out.blocks512 |= static_cast<std::uint64_t>(u16(0x74)) << 32;
    if (sb.has_64bit) out.file_acl |= static_cast<std::uint64_t>(u16(0x76)) << 32;
    if ((out.flags & kFlHugeFile) != 0 && sb.has_huge_file)
        out.blocks512 = sat_mul(out.blocks512, sb.block_size / 512);
    if (sb.inode_size > kGoodOldInodeSize) out.extra_isize = u16(0x80);
    if (static_cast<std::size_t>(kGoodOldInodeSize) + out.extra_isize > sb.inode_size)
        out.extra_isize = 0;  // corrupt: treat as no extra fields

    out.size = size_lo;
    const bool is_reg = (out.mode & kIfmt) == kIfreg;
    const bool is_dir = (out.mode & kIfmt) == kIfdir;
    if (is_reg || (sb.has_largedir && is_dir))
        out.size |= static_cast<std::uint64_t>(size_hi) << 32;

    auto decode_time = [&](std::uint32_t sec, std::size_t extra_off, std::optional<std::int64_t>& s,
                           std::optional<std::uint32_t>* ns) {
        std::int64_t v = static_cast<std::int32_t>(sec);
        if (has_extra(out, extra_off + 4)) {
            const std::uint32_t extra = u32(extra_off);
            v += static_cast<std::int64_t>(extra & 3u) << 32;
            if (ns) *ns = extra >> 2;
        }
        s = v;
    };
    decode_time(ctime, 0x84, out.ctime, &out.ctime_nsec);
    decode_time(mtime, 0x88, out.mtime, &out.mtime_nsec);
    decode_time(atime, 0x8C, out.atime, &out.atime_nsec);
    if (has_extra(out, 0x94)) {
        std::optional<std::uint32_t> unused;
        decode_time(u32(0x90), 0x94, out.crtime, &unused);
        // nsec of crtime has no FileMeta field
    }
    if (sb.has_metadata_csum && sb.checksum_type == 1) {
        out.csum_checked = true;
        out.csum_ok = verify_inode_csum(out);
    }
    return true;
}

bool ExtReader::Impl::parse_xattr_entries(const std::uint8_t* base, std::size_t len,
                                          std::size_t first_entry, std::size_t value_base,
                                          std::string& summary, std::uint64_t& count,
                                          std::vector<std::uint8_t>* system_data,
                                          std::string* why) {
    // Every entry is at least 16 bytes plus its name, so the structure bounds
    // the count; the Limits node cap bounds what is reported.
    const std::uint64_t cap = limits().max_nodes_per_fs;
    std::size_t pos = first_entry;
    while (pos + 4 <= len) {
        if (ld<std::uint32_t>(base + pos) == 0) return true;  // terminator
        if (pos + 16 > len) {
            if (why) *why = "xattr entry at " + dec(pos) + " runs past the end";
            return false;
        }
        const std::uint8_t name_len = base[pos];
        const std::uint8_t index = base[pos + 1];
        const std::uint16_t value_offs = ld<std::uint16_t>(base + pos + 2);
        const std::uint32_t value_inum = ld<std::uint32_t>(base + pos + 4);
        const std::uint32_t value_size = ld<std::uint32_t>(base + pos + 8);
        if (pos + 16 + name_len > len) {
            if (why) *why = "xattr name at " + dec(pos) + " runs past the end";
            return false;
        }
        std::string name;
        if (const char* prefix = xattr_prefix(index))
            name = prefix;
        else
            name = "index" + dec(index) + ".";
        name.append(reinterpret_cast<const char*>(base + pos + 16), name_len);
        if (count >= cap) {
            if (why) *why = "more than max_nodes_per_fs (" + dec(cap) + ") xattr entries";
            return false;
        }
        ++count;
        if (!summary.empty()) summary += ';';
        summary += name + "=" + dec(value_size);
        if (value_inum != 0) summary += "@inode" + dec(value_inum);
        if (system_data && index == 7 && name == "system.data" && value_inum == 0) {
            const std::size_t vo = value_base + value_offs;
            if (vo > len || value_size > len - vo) {
                if (why)
                    *why = "system.data value (" + dec(value_size) + " bytes) runs past the end";
                return false;
            }
            system_data->assign(base + vo, base + vo + value_size);
        }
        pos += align4(16 + name_len);
    }
    return true;
}

// "name=size;name=size" for every xattr in the inode body and the EA block.
// `system_data` receives the value of system.data (inline-data continuation).
std::string ExtReader::Impl::xattr_summary(const Inode& in, std::vector<std::uint8_t>* system_data,
                                           std::string* why) {
    std::string summary;
    std::uint64_t count = 0;
    std::string w;
    if (has_extra(in, kGoodOldInodeSize + in.extra_isize)) {
        const std::size_t start = static_cast<std::size_t>(kGoodOldInodeSize) + in.extra_isize;
        if (start + 4 <= in.raw.size() && ld<std::uint32_t>(in.raw.data() + start) == kXattrMagic) {
            // In-inode values are relative to the first entry.
            if (!parse_xattr_entries(in.raw.data(), in.raw.size(), start + 4, start + 4, summary,
                                     count, system_data, &w) &&
                why)
                *why = "in-inode xattrs: " + w;
        }
    }
    if (in.file_acl != 0) {
        std::vector<std::uint8_t>& blk = xattr_buf;
        if (!read_block(in.file_acl, blk, &w)) {
            if (why) *why = "xattr block: " + w;
            return summary;
        }
        if (ld<std::uint32_t>(blk.data()) != kXattrMagic) {
            if (why) *why = "xattr block " + dec(in.file_acl) + " has no EA magic";
            return summary;
        }
        if (!parse_xattr_entries(blk.data(), blk.size(), 32, 0, summary, count, system_data, &w) &&
            why)
            *why = "xattr block " + dec(in.file_acl) + ": " + w;
    }
    return summary;
}

// ---------------------------------------------------------------- block mapping

std::uint64_t ExtReader::Impl::indirect_ptr(std::uint64_t blk, std::uint64_t idx, std::size_t cache,
                                            bool& bad, std::string* why) {
    if (blk == 0) return 0;
    BlockBuf& b = ind_cache[cache];
    if (!read_block_cached(blk, b, why)) {
        bad = true;
        return 0;
    }
    return ld<std::uint32_t>(b.data.data() + idx * 4);
}

template <class Fn>
bool ExtReader::Impl::walk_block_map(const Inode& in, std::uint64_t max_blocks, Fn& fn,
                                     const char** code, std::string* why) {
    const std::uint64_t ppb = sb.block_size / 4;
    auto iblk = [&](std::size_t i) {
        return static_cast<std::uint64_t>(ld<std::uint32_t>(in.iblock.data() + i * 4));
    };
    Run run;
    bool have_run = false;
    auto flush = [&]() {
        if (!have_run) return true;
        have_run = false;
        return fn(run);
    };
    auto add = [&](std::uint64_t logical, std::uint64_t physical) {
        if (have_run && run.physical != 0 && physical == run.physical + run.length &&
            logical == run.logical + run.length) {
            ++run.length;
            return true;
        }
        if (have_run && run.physical == 0 && physical == 0 && logical == run.logical + run.length) {
            ++run.length;
            return true;
        }
        if (!flush()) return false;
        run = Run{logical, 1, physical, false};
        have_run = true;
        return true;
    };
    for (std::uint64_t L = 0; L < max_blocks; ++L) {
        bool bad = false;
        std::uint64_t phys = 0;
        std::uint64_t l = L;
        if (l < 12) {
            phys = iblk(static_cast<std::size_t>(l));
        } else if ((l -= 12) < ppb) {
            phys = indirect_ptr(iblk(12), l, 0, bad, why);
        } else if ((l -= ppb) < ppb * ppb) {
            const std::uint64_t a = indirect_ptr(iblk(13), l / ppb, 1, bad, why);
            phys = bad ? 0 : indirect_ptr(a, l % ppb, 2, bad, why);
        } else if ((l -= ppb * ppb) < ppb * ppb * ppb) {
            const std::uint64_t a = indirect_ptr(iblk(14), l / (ppb * ppb), 3, bad, why);
            const std::uint64_t b = bad ? 0 : indirect_ptr(a, (l / ppb) % ppb, 4, bad, why);
            phys = bad ? 0 : indirect_ptr(b, l % ppb, 5, bad, why);
        } else {
            *code = kCodeBlockmapCorrupt;
            if (why) *why = "logical block " + dec(L) + " is beyond the triple-indirect range";
            flush();
            return false;
        }
        if (bad) {
            *code = kCodeBlockmapCorrupt;
            if (why) *why = "indirect block for logical block " + dec(L) + ": " + *why;
            flush();
            return false;
        }
        if (phys != 0 && phys >= sb.blocks_count) {
            *code = kCodeBlockmapCorrupt;
            if (why)
                *why = "logical block " + dec(L) + " maps to block " + dec(phys) +
                       " beyond blocks_count " + dec(sb.blocks_count);
            flush();
            return false;
        }
        if (!add(L, phys)) return true;  // consumer stopped
    }
    flush();
    return true;
}

template <class Fn>
bool ExtReader::Impl::walk_extent_node(const std::uint8_t* node, std::size_t len, std::size_t depth,
                                       std::optional<std::uint16_t> want_depth,
                                       std::optional<std::uint32_t> want_first,
                                       std::uint64_t max_blocks, std::uint64_t& next_logical,
                                       Fn& fn, bool& stopped, const char** code, std::string* why) {
    *code = kCodeExtentCorrupt;
    if (len < kExtentHeaderSize) {
        if (why) *why = "extent node shorter than its header";
        return false;
    }
    if (ld<std::uint16_t>(node) != kExtentMagic) {
        if (why) *why = "extent node magic " + hex(ld<std::uint16_t>(node)) + " is not 0xf30a";
        return false;
    }
    const std::uint16_t entries = ld<std::uint16_t>(node + 2);
    const std::uint16_t max = ld<std::uint16_t>(node + 4);
    const std::uint16_t node_depth = ld<std::uint16_t>(node + 6);
    const std::size_t fit = (len - kExtentHeaderSize) / kExtentEntrySize;
    if (entries > max || entries > fit) {
        if (why)
            *why = "extent node claims " + dec(entries) + " entries (max " + dec(max) + ", " +
                   dec(fit) + " fit)";
        return false;
    }
    if (node_depth > kMaxExtentDepth || depth + node_depth > kMaxExtentDepth) {
        if (why) *why = "extent tree depth " + dec(depth + node_depth) + " exceeds 5";
        return false;
    }
    if (want_depth && node_depth != *want_depth) {
        if (why)
            *why = "extent node at depth " + dec(depth) + " claims eh_depth " + dec(node_depth) +
                   ", its parent expects " + dec(*want_depth);
        return false;
    }
    if (want_depth && entries == 0) {
        // The kernel and e2fsprogs remove a node that becomes empty
        // (ext4_ext_rm_idx), so an empty non-root node is corruption; it is
        // also what lets a shared subtree be re-walked without progress.
        if (why) *why = "extent node at depth " + dec(depth) + " has no entries";
        return false;
    }
    if (want_first && entries != 0 && ld<std::uint32_t>(node + kExtentHeaderSize) != *want_first) {
        if (why)
            *why = "extent node at depth " + dec(depth) + " starts at logical block " +
                   dec(ld<std::uint32_t>(node + kExtentHeaderSize)) +
                   ", its parent index entry says " + dec(*want_first);
        return false;
    }
    std::optional<std::uint32_t> prev_first;
    for (std::size_t i = 0; i < entries && !stopped; ++i) {
        const std::uint8_t* e = node + kExtentHeaderSize + i * kExtentEntrySize;
        const std::uint32_t first = ld<std::uint32_t>(e);
        if (prev_first && first <= *prev_first) {
            if (why)
                *why = "extent entry " + dec(i) + " at logical block " + dec(first) +
                       " does not follow entry " + dec(i - 1) + " (" + dec(*prev_first) + ")";
            return false;
        }
        prev_first = first;
        if (node_depth == 0) {
            const std::uint16_t raw_len = ld<std::uint16_t>(e + 4);
            const std::uint64_t start =
                (static_cast<std::uint64_t>(ld<std::uint16_t>(e + 6)) << 32) |
                ld<std::uint32_t>(e + 8);
            Run r;
            r.logical = first;
            r.uninit = raw_len > kExtentInitMaxLen;
            r.length = r.uninit ? raw_len - kExtentInitMaxLen : raw_len;
            r.physical = start;
            if (r.length == 0) {  // ext4_valid_extent(): a zero-length extent is corruption
                if (why) *why = "extent at logical block " + dec(r.logical) + " has length 0";
                return false;
            }
            if (r.logical < next_logical) {
                if (why)
                    *why = "extent at logical block " + dec(r.logical) +
                           " overlaps or precedes the previous extent (next expected " +
                           dec(next_logical) + ")";
                return false;
            }
            if (start == 0 || start >= sb.blocks_count || r.length > sb.blocks_count - start) {
                if (why)
                    *why = "extent at logical block " + dec(r.logical) + " maps " + dec(r.length) +
                           " blocks from physical block " + dec(start) + ", outside blocks_count " +
                           dec(sb.blocks_count);
                return false;
            }
            next_logical = r.logical + r.length;
            if (r.logical >= max_blocks) {
                stopped = true;
                return true;
            }
            if (!fn(r)) {
                stopped = true;
                return true;
            }
        } else {
            const std::uint64_t child =
                (static_cast<std::uint64_t>(ld<std::uint16_t>(e + 8)) << 32) |
                ld<std::uint32_t>(e + 4);
            if (first >= max_blocks) {
                stopped = true;
                return true;
            }
            std::vector<std::uint8_t>& buf = extent_bufs[depth + 1];
            if (!read_block(child, buf, why)) {
                if (why) *why = "extent index block: " + *why;
                return false;
            }
            if (!walk_extent_node(buf.data(), buf.size(), depth + 1,
                                  static_cast<std::uint16_t>(node_depth - 1), first, max_blocks,
                                  next_logical, fn, stopped, code, why))
                return false;
        }
    }
    return true;
}

template <class Fn>
bool ExtReader::Impl::map_runs(const Inode& in, std::uint64_t max_blocks, Fn&& fn,
                               const char** code, std::string* why) {
    *code = kCodeMetadataCorrupt;
    if (in.flags & kFlExtents) {
        std::uint64_t next_logical = 0;
        bool stopped = false;
        return walk_extent_node(in.iblock.data(), kIBlockBytes, 0, std::nullopt, std::nullopt,
                                max_blocks, next_logical, fn, stopped, code, why);
    }
    return walk_block_map(in, max_blocks, fn, code, why);
}

bool ExtReader::Impl::inline_data(const Inode& in, std::vector<std::uint8_t>& out,
                                  std::string* why) {
    out.assign(in.iblock.begin(), in.iblock.end());
    std::vector<std::uint8_t> tail;
    std::string w;
    (void)xattr_summary(in, &tail, &w);
    if (!w.empty() && tail.empty() && in.size > kIBlockBytes) {
        if (why) *why = w;
        return false;
    }
    out.insert(out.end(), tail.begin(), tail.end());
    if (in.size > out.size()) {
        if (why)
            *why = "inline data holds " + dec(out.size()) + " bytes but i_size is " + dec(in.size);
        out.resize(static_cast<std::size_t>(std::min<std::uint64_t>(in.size, out.size())));
        return false;
    }
    out.resize(static_cast<std::size_t>(in.size));
    return true;
}

// ext4_inode_is_fast_symlink(): the target is in i_block when the inode owns
// no data blocks (the EA block does not count).
bool ExtReader::Impl::fast_symlink(const Inode& in) const {
    if ((in.mode & kIfmt) != kIflnk) return false;
    if (in.flags & kFlInlineData) return false;
    if (in.flags & kFlEaInode) return in.size != 0 && in.size < kIBlockBytes;
    const std::uint64_t ea_blocks = in.file_acl != 0 ? sb.block_size / 512 : 0;
    return in.blocks512 <= ea_blocks;
}

// ---------------------------------------------------------------- data

bool ExtReader::Impl::write_zeros(Walk& w, std::uint64_t n) {
    if (zero_buf.size() < sb.block_size) zero_buf.assign(sb.block_size, 0);
    while (n > 0) {
        const std::size_t step =
            static_cast<std::size_t>(std::min<std::uint64_t>(n, sb.block_size));
        if (!w.sink->write(std::span<const std::uint8_t>(zero_buf.data(), step))) return false;
        n -= step;
    }
    return true;
}

// Streams `size` bytes of `in` to the open sink file. Returns false only when
// the sink refused a write; map problems become diagnostics and the data is
// zero-filled so later offsets stay right. `unallocated` (history): every
// block is checked against the block bitmap and a reused block is zero-filled
// and counted in `*reused`.
bool ExtReader::Impl::stream_data(Walk& w, const std::string& path, const Inode& in,
                                  std::uint64_t size, bool unallocated, bool& truncated,
                                  std::uint64_t* reused) {
    const std::uint64_t bs = sb.block_size;
    std::uint64_t pos = 0;  // bytes delivered so far
    bool sink_ok = true;
    if (in.flags & kFlInlineData) {
        std::string why;
        if (!inline_data(in, inline_buf, &why)) {
            diag(*w.out, Severity::Warning, kCodeInlineDataCorrupt, "'" + path + "': " + why);
            truncated = true;
        }
        const std::size_t n =
            static_cast<std::size_t>(std::min<std::uint64_t>(size, inline_buf.size()));
        if (n > 0 && !w.sink->write(std::span<const std::uint8_t>(inline_buf.data(), n)))
            return false;
        pos = n;
        if (pos < size && !write_zeros(w, size - pos)) return false;
        return true;
    }
    const std::uint64_t nblocks = (size + bs - 1) / bs;
    std::string why;
    const char* code = kCodeMetadataCorrupt;
    bool bad_map = false;
    auto deliver = [&](const Run& r) -> bool {
        if (pos >= size) return false;
        const std::uint64_t run_start = sat_mul(r.logical, bs);
        if (run_start > pos) {  // hole before this run
            if (!write_zeros(w, std::min(run_start, size) - pos)) {
                sink_ok = false;
                return false;
            }
            pos = std::min(run_start, size);
            if (pos >= size) return false;
        }
        std::uint64_t blk = r.logical + (pos - run_start) / bs;  // first block not yet delivered
        const std::uint64_t run_end = r.logical + r.length;
        while (blk < run_end && pos < size) {
            std::uint64_t n = std::min(run_end - blk, kStreamChunkBlocks);
            const std::uint64_t remaining_bytes = size - pos;
            n = std::min(n, (remaining_bytes + bs - 1) / bs);
            const std::uint64_t phys = r.physical + (blk - r.logical);
            bool zeros = r.uninit || r.physical == 0;
            if (!zeros && unallocated) {
                n = 1;  // per block: the bitmap decides
                const auto alloc = block_allocated(phys);
                if (!alloc || *alloc) {
                    zeros = true;
                    if (reused) ++*reused;
                }
            }
            const std::uint64_t chunk = std::min(n * bs, remaining_bytes);
            if (zeros) {
                if (!write_zeros(w, chunk)) {
                    sink_ok = false;
                    return false;
                }
            } else {
                const auto off = block_offset(phys);
                std::optional<std::uint64_t> end_off;
                if (off && phys + n <= sb.blocks_count) end_off = block_offset(phys + n - 1);
                if (!off || !end_off) {
                    diag(*w.out, Severity::Warning, kCodeDataTruncated,
                         "'" + path + "': block " + dec(phys) + " (logical " + dec(blk) +
                             ") lies outside the image; " + dec(size - pos) + " bytes zero-filled");
                    truncated = true;
                    if (!write_zeros(w, size - pos)) {
                        sink_ok = false;
                        return false;
                    }
                    pos = size;
                    return false;
                }
                std::span<const std::uint8_t> data;
                const auto view = span.view(*off, static_cast<std::size_t>(chunk));
                if (view) {
                    data = *view;
                } else {
                    auto copy = span.bytes(*off, static_cast<std::size_t>(chunk));
                    if (!copy) {
                        diag(*w.out, Severity::Warning, kCodeDataTruncated,
                             "'" + path + "': block " + dec(phys) + " could not be read; " +
                                 dec(chunk) + " bytes zero-filled");
                        truncated = true;
                        if (!write_zeros(w, chunk)) {
                            sink_ok = false;
                            return false;
                        }
                        pos += chunk;
                        blk += n;
                        continue;
                    }
                    data_buf = std::move(*copy);
                    data = data_buf;
                }
                if (!w.sink->write(data)) {
                    sink_ok = false;
                    return false;
                }
            }
            pos += chunk;
            blk += n;
        }
        return pos < size;
    };
    if (!map_runs(in, nblocks, deliver, &code, &why)) {
        bad_map = true;
    }
    if (!sink_ok) return false;
    if (bad_map) {
        diag(*w.out, Severity::Warning, code,
             "'" + path + "': " + why + "; " + dec(size - pos) + " bytes not recovered");
        truncated = true;
        return true;
    }
    if (pos < size && !write_zeros(w, size - pos)) return false;  // trailing hole
    return true;
}

bool ExtReader::Impl::read_symlink(const Inode& in, std::string& target, std::string* why) {
    target.clear();
    if (in.size > limits().max_file_bytes) {
        if (why)
            *why = "symlink target of " + dec(in.size) + " bytes exceeds max_file_bytes (" +
                   dec(limits().max_file_bytes) + ")";
        return false;
    }
    if (in.flags & kFlInlineData) {
        if (!inline_data(in, inline_buf, why)) return false;
        target.assign(inline_buf.begin(), inline_buf.end());
        return true;
    }
    if (fast_symlink(in)) {
        const std::size_t n =
            static_cast<std::size_t>(std::min<std::uint64_t>(in.size, kIBlockBytes));
        target.assign(reinterpret_cast<const char*>(in.iblock.data()), n);
        return true;
    }
    // Slow symlink: the target occupies data blocks (at most a few).
    const std::uint64_t bs = sb.block_size;
    const std::uint64_t nblocks = (in.size + bs - 1) / bs;
    std::uint64_t pos = 0;
    bool ok = true;
    const char* code = nullptr;
    std::string w;
    auto deliver = [&](const Run& r) -> bool {
        if (r.physical == 0 || r.uninit) return true;
        for (std::uint64_t b = 0; b < r.length && pos < in.size; ++b) {
            const std::uint64_t logical = r.logical + b;
            if (logical * bs > pos)
                target.append(static_cast<std::size_t>(logical * bs - pos), '\0');
            pos = logical * bs;
            const std::size_t want = static_cast<std::size_t>(std::min(bs, in.size - pos));
            const auto bytes = span.bytes(
                block_offset(r.physical + b).value_or(std::numeric_limits<std::uint64_t>::max()),
                want);
            if (!bytes) {
                ok = false;
                w = "target block " + dec(r.physical + b) + " lies outside the image";
                return false;
            }
            target.append(reinterpret_cast<const char*>(bytes->data()), bytes->size());
            pos += want;
        }
        return pos < in.size;
    };
    if (!map_runs(in, nblocks, deliver, &code, &w)) ok = false;
    if (!ok) {
        if (why) *why = w;
        return false;
    }
    if (const auto z = target.find('\0'); z != std::string::npos) target.resize(z);
    return true;
}

// ---------------------------------------------------------------- directories

// Remnants of unlinked entries live between the end of a live entry's record
// (8 + name_len, rounded to 4) and its rec_len. Parse them as entries with the
// same validation a live entry gets; step 4 bytes at a time otherwise.
void ExtReader::Impl::scan_slack(Walk& w, const std::uint8_t* blk, std::size_t n, std::size_t from,
                                 std::size_t to, const std::string& path) {
    std::size_t s = from;
    while (s + kDirEntryHeader <= to) {
        const std::uint32_t ino = ld<std::uint32_t>(blk + s);
        const std::uint32_t rec_len =
            rec_len_from_disk(ld<std::uint16_t>(blk + s + 4), sb.block_size);
        std::size_t name_len = blk[s + 6];
        std::uint8_t ft = blk[s + 7];
        if (!sb.has_filetype) {
            name_len = ld<std::uint16_t>(blk + s + 6);
            ft = 0;
        }
        bool ok = ino != 0 && ino <= sb.inodes_count && name_len > 0 && rec_len % 4 == 0 &&
                  rec_len >= align4(kDirEntryHeader + name_len) && s + rec_len <= n &&
                  s + kDirEntryHeader + name_len <= n && (!sb.has_filetype || ft <= kFtSymlink);
        if (ok) {
            for (std::size_t i = 0; i < name_len; ++i) {
                const std::uint8_t c = blk[s + kDirEntryHeader + i];
                if (c == 0 || c == '/') {
                    ok = false;
                    break;
                }
            }
        }
        if (!ok) {
            s += 4;
            continue;
        }
        if (w.hist.size() >= w.opts->limits.max_nodes_per_fs) return;  // reported by the caller
        HistDirent h;
        h.parent_path = path;
        h.name.assign(reinterpret_cast<const char*>(blk + s + kDirEntryHeader), name_len);
        h.inode = ino;
        h.file_type = ft;
        w.hist.push_back(std::move(h));
        s += align4(kDirEntryHeader + name_len);
    }
}

void ExtReader::Impl::parse_dir_block(Walk& w, const std::uint8_t* blk, std::size_t n,
                                      bool inline_dir, bool indexed, std::uint64_t block_index,
                                      const std::string& path, std::vector<DirEntry>& entries,
                                      bool* limit_hit) {
    std::size_t pos = 0;
    bool first = true;
    while (pos + kDirEntryHeader <= n) {
        const std::uint32_t ino = ld<std::uint32_t>(blk + pos);
        const std::uint32_t rec_len =
            inline_dir ? ld<std::uint16_t>(blk + pos + 4)
                       : rec_len_from_disk(ld<std::uint16_t>(blk + pos + 4), sb.block_size);
        std::size_t name_len = blk[pos + 6];
        std::uint8_t ft = blk[pos + 7];
        if (!sb.has_filetype) {
            name_len = ld<std::uint16_t>(blk + pos + 6);
            ft = 0;
        }
        if (rec_len < kDirEntryHeader || rec_len % 4 != 0 || pos + rec_len > n ||
            kDirEntryHeader + name_len > rec_len) {
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "'" + path + "': directory block " + dec(block_index) + " entry at offset " +
                     dec(pos) + " has rec_len " + dec(rec_len) + " / name_len " + dec(name_len) +
                     "; rest of the block skipped");
            return;
        }
        const std::size_t actual = align4(kDirEntryHeader + name_len);
        // An htree index node is a fake empty entry spanning the whole block;
        // its slack is hash/block pairs, not names.
        if (indexed && first && ino == 0 && rec_len == n && !inline_dir) return;
        first = false;
        std::string name(reinterpret_cast<const char*>(blk + pos + kDirEntryHeader), name_len);
        if (ino != 0 && name_len > 0) {
            if (entries.size() >= w.opts->limits.max_nodes_per_fs) {
                if (limit_hit) *limit_hit = true;
                return;
            }
            entries.push_back(DirEntry{ino, ft, name});
        }
        if (w.opts->history) {
            // dx_root keeps its index inside the ".." entry of block 0.
            const bool dx_root = indexed && block_index == 0 && name == "..";
            if (!dx_root && rec_len > actual)
                scan_slack(w, blk, n, pos + actual, pos + rec_len, path);
        }
        pos += rec_len;
    }
}

bool ExtReader::Impl::read_directory(Walk& w, const Inode& dir, const std::string& path,
                                     std::vector<DirEntry>& entries, bool* limit_hit) {
    entries.clear();
    if (limit_hit) *limit_hit = false;
    const bool indexed = (dir.flags & kFlIndex) != 0;
    if (dir.flags & kFlInlineData) {
        std::string why;
        const bool ok = inline_data(dir, inline_buf, &why);
        if (!ok)
            diag(*w.out, Severity::Warning, kCodeInlineDataCorrupt,
                 "'" + path + "': " + why + "; listing " +
                     (inline_buf.size() > 4 ? "partial" : "skipped"));
        if (inline_buf.size() <= 4) return ok;
        // i_block starts with the parent inode number; entries follow.
        parse_dir_block(w, inline_buf.data() + 4, inline_buf.size() - 4, true, indexed, 0, path,
                        entries, limit_hit);
        return ok;
    }
    const std::uint64_t bs = sb.block_size;
    std::uint64_t dir_size = dir.size;
    // A directory's i_size is 64-bit with `largedir`; the same per-entry
    // byte cap that bounds a regular file bounds the blocks read here.
    if (dir_size > w.opts->limits.max_file_bytes) {
        diag(*w.out, Severity::Warning, kCodeLimitFileBytes,
             "'" + path + "': directory size " + dec(dir_size) + " exceeds max_file_bytes (" +
                 dec(w.opts->limits.max_file_bytes) + "); entries beyond it are not listed");
        dir_size = w.opts->limits.max_file_bytes;
        w.out->truncated = true;
    }
    const std::uint64_t nblocks = dir_size / bs;
    if (dir_size % bs != 0)
        diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
             "'" + path + "': directory size " + dec(dir.size) +
                 " is not a multiple of the block size");
    std::string why;
    const char* code = kCodeMetadataCorrupt;
    bool stop = false;
    auto deliver = [&](const Run& r) -> bool {
        if (r.logical >= nblocks) return false;
        if (r.physical == 0 || r.uninit) return true;  // a hole in a directory: nothing to list
        for (std::uint64_t b = 0; b < r.length; ++b) {
            const std::uint64_t logical = r.logical + b;
            if (logical >= nblocks) return false;
            if (!read_block(r.physical + b, dir_buf, &why)) {
                diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                     "'" + path + "': directory block " + dec(logical) + ": " + why + " (skipped)");
                continue;
            }
            parse_dir_block(w, dir_buf.data(), dir_buf.size(), false, indexed, logical, path,
                            entries, limit_hit);
            if (limit_hit && *limit_hit) {
                stop = true;
                return false;
            }
        }
        return true;
    };
    if (!map_runs(dir, nblocks, deliver, &code, &why) && !stop) {
        diag(*w.out, Severity::Warning, code,
             "'" + path + "': directory block map: " + why + "; listing " +
                 (entries.empty() ? "skipped" : "partial"));
        return !entries.empty();
    }
    return true;
}

// ---------------------------------------------------------------- walk

bool ExtReader::Impl::count_node(Walk& w, const std::string& path) {
    const Limits& lim_ = w.opts->limits;
    if (w.nodes >= lim_.max_nodes_per_fs) {
        diag(*w.out, Severity::Warning, kCodeLimitNodes,
             "max_nodes_per_fs (" + dec(lim_.max_nodes_per_fs) + ") reached at '" + path +
                 "'; walk stopped");
        w.out->truncated = true;
        w.stop = true;
        return false;
    }
    if (w.out->entries >= lim_.max_files) {
        diag(*w.out, Severity::Warning, kCodeLimitFiles,
             "max_files (" + dec(lim_.max_files) + ") reached at '" + path + "'; walk stopped");
        w.out->truncated = true;
        w.stop = true;
        return false;
    }
    ++w.nodes;
    return true;
}

FileMeta ExtReader::Impl::make_meta(Walk& w, const std::string& path, const Inode& in) {
    FileMeta m;
    m.path = path;
    m.kind = kind_for_mode(in.mode);
    m.mode = in.mode & 07777u;
    m.uid = in.uid;
    m.gid = in.gid;
    m.inode = in.number;
    m.nlink = in.links;
    m.mtime = in.mtime;
    m.ctime = in.ctime;
    m.atime = in.atime;
    m.crtime = in.crtime;
    m.mtime_nsec = in.mtime_nsec;
    m.ctime_nsec = in.ctime_nsec;
    m.atime_nsec = in.atime_nsec;
    switch (m.kind) {
        case EntryKind::Regular:
            m.size = in.size;
            break;
        case EntryKind::Symlink: {
            std::string why;
            if (!read_symlink(in, m.link_target, &why))
                diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                     "'" + path + "': symlink target unreadable: " + why);
            m.size = in.size;
            break;
        }
        case EntryKind::CharDevice:
        case EntryKind::BlockDevice: {
            // Old encoding in i_block[0] (8:8); new encoding in i_block[1]
            // (major bits 8..19, minor bits 0..7 and 20..31).
            const std::uint32_t old_dev = ld<std::uint32_t>(in.iblock.data());
            if (old_dev != 0) {
                m.rdev_major = (old_dev >> 8) & 0xFFu;
                m.rdev_minor = old_dev & 0xFFu;
            } else {
                const std::uint32_t dev = ld<std::uint32_t>(in.iblock.data() + 4);
                m.rdev_major = (dev >> 8) & 0xFFFu;
                m.rdev_minor = (dev & 0xFFu) | ((dev >> 12) & 0xFFF00u);
            }
            break;
        }
        default:
            break;
    }
    if (in.flags != 0) m.extra["flags"] = hex(in.flags);
    if (in.flags & kFlImmutable) m.extra["immutable"] = "true";
    if (in.flags & kFlAppend) m.extra["append_only"] = "true";
    if (in.flags & kFlInlineData) m.extra["inline"] = "true";
    if (in.flags & kFlEncrypt) m.extra["encrypted"] = "true";
    if (in.flags & kFlVerity) m.extra["verity"] = "true";
    if (in.flags & kFlCasefold) m.extra["casefold"] = "true";
    if (in.flags & kFlCompr) m.extra["compressed"] = "true";
    if (in.generation != 0) m.extra["generation"] = dec(in.generation);
    if (in.dtime != 0) m.extra["dtime"] = dec(in.dtime);
    if (in.csum_checked && !in.csum_ok) {
        m.extra["checksum"] = "mismatch";
        if (w.inode_csum_bad++ == 0) w.inode_csum_first = path + " (inode " + dec(in.number) + ")";
    }
    {
        std::string why;
        const std::string x = xattr_summary(in, nullptr, &why);
        if (!x.empty()) m.extra["xattrs"] = x;
        if (!why.empty())
            diag(*w.out, Severity::Warning, kCodeXattrCorrupt, "'" + path + "': " + why);
    }
    // Per-entry unsupported features: the entry is still listed.
    for (const auto& [bit, what] :
         {std::pair<std::uint32_t, const char*>{
              kFlEncrypt, "encrypted (EXT4_ENCRYPT_FL): data is listed as stored, not decrypted"},
          std::pair<std::uint32_t, const char*>{
              kFlCompr, "compressed (EXT2_COMPR_FL): data is extracted as stored"},
          std::pair<std::uint32_t, const char*>{
              kFlCasefold, "casefold (EXT4_CASEFOLD_FL): names are not folded"}}) {
        if ((in.flags & bit) != 0 && (w.feature_reported & bit) == 0) {
            w.feature_reported |= bit;
            diag(*w.out, Severity::Info, kCodeUnsupportedFeature,
                 "'" + path + "' is " + what + " (reported once)");
        }
    }
    return m;
}

void ExtReader::Impl::emit_regular(Walk& w, FileMeta meta, const Inode& in, bool unallocated) {
    std::uint64_t size = in.size;
    bool truncated = false;
    const bool no_blocks =
        unallocated && !(in.flags & kFlInlineData) &&
        ((in.flags & kFlExtents) != 0 ? (ld<std::uint16_t>(in.iblock.data()) != kExtentMagic ||
                                         ld<std::uint16_t>(in.iblock.data() + 2) == 0)
                                      : std::all_of(in.iblock.begin(), in.iblock.end(),
                                                    [](std::uint8_t b) { return b == 0; }));
    if (unallocated) {
        if (no_blocks) {
            meta.extra["content"] =
                size == 0 ? "unavailable: size 0"
                          : ((in.flags & kFlExtents) ? "unavailable: extents cleared"
                                                     : "unavailable: block map cleared");
        } else {
            meta.extra["content"] = "recovered from unallocated blocks";
        }
    }
    if (size > w.opts->limits.max_file_bytes) {
        diag(*w.out, Severity::Warning, kCodeLimitFileBytes,
             "'" + meta.path + "': size " + dec(size) + " exceeds max_file_bytes (" +
                 dec(w.opts->limits.max_file_bytes) + "); data cut there");
        size = w.opts->limits.max_file_bytes;
        truncated = true;
    }
    Status s = w.sink->begin_file(meta);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return;
    }
    bool sink_ok = true;
    std::uint64_t reused = 0;
    if (w.opts->extract_data && !(in.flags & kFlEncrypt)) {
        if (unallocated && no_blocks) {
            if (size != 0) {
                diag(*w.out, Severity::Info, kCodeDeletedNoBlocks,
                     "'" + meta.path + "' (inode " + dec(in.number) +
                         "): the block references were cleared when it was freed; only metadata "
                         "is recoverable");
                truncated = true;
            }
        } else {
            sink_ok = stream_data(w, meta.path, in, size, unallocated, truncated, &reused);
        }
    } else if (in.flags & kFlEncrypt) {
        truncated = size != 0;
    }
    EntryResult r;
    s = w.sink->end_file(r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        if (r.meta.path.empty()) return;
    }
    if (reused != 0) {
        diag(*w.out, Severity::Warning, kCodeDeletedBlocksReused,
             "'" + meta.path + "' (inode " + dec(in.number) + "): " + dec(reused) +
                 " of its blocks are allocated to something else now; zero-filled");
        r.meta.extra["content"] =
            "recovered from unallocated blocks; " + dec(reused) + " reused blocks zero-filled";
        truncated = true;
    }
    if (!sink_ok || truncated) r.truncated = true;
    if (r.truncated) w.out->truncated = true;
    w.out->bytes += r.digests.bytes;
    w.out->entries++;
    w.out->files++;
    if (meta.deleted) w.out->deleted++;
    if (meta.superseded) w.out->superseded++;
    w.out->entries_out.push_back(std::move(r));
}

bool ExtReader::Impl::emit_other(Walk& w, const FileMeta& meta) {
    EntryResult r;
    const Status s = w.sink->entry(meta, r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return false;
    }
    w.out->entries++;
    switch (meta.kind) {
        case EntryKind::Directory:
            w.out->dirs++;
            break;
        case EntryKind::Symlink:
            w.out->symlinks++;
            break;
        default:
            w.out->others++;
            break;
    }
    if (meta.deleted) w.out->deleted++;
    if (meta.superseded) w.out->superseded++;
    w.out->entries_out.push_back(std::move(r));
    return true;
}

bool ExtReader::Impl::walk_live(Walk& w) {
    struct Frame {
        std::string path;  // "" for the root
        std::uint32_t inode = 0;
        std::vector<DirEntry> entries;
        std::size_t next = 0;
    };
    std::vector<Frame> stack;
    std::string why;

    Inode root;
    if (!read_inode(kRootIno, root, &why)) {
        diag(*w.out, Severity::Error, kCodeMetadataCorrupt, "root inode: " + why);
        return false;
    }
    if ((root.mode & kIfmt) != kIfdir) {
        diag(*w.out, Severity::Error, kCodeRootInvalid,
             "root inode 2 has mode " + hex(root.mode) + ", not a directory");
        return false;
    }
    if (root.csum_checked && !root.csum_ok) {
        if (w.inode_csum_bad++ == 0) w.inode_csum_first = "/ (inode 2)";
    }
    w.reachable.set(kRootIno);
    w.dirs_seen.set(kRootIno);
    {
        Frame f;
        f.inode = kRootIno;
        bool limit_hit = false;
        if (!read_directory(w, root, "", f.entries, &limit_hit) && f.entries.empty()) {
            diag(*w.out, Severity::Error, kCodeMetadataCorrupt,
                 "root directory listing unreadable");
            return false;
        }
        if (limit_hit) {
            diag(*w.out, Severity::Warning, kCodeLimitNodes,
                 "root directory has more than max_nodes_per_fs (" +
                     dec(w.opts->limits.max_nodes_per_fs) + ") entries; listing truncated");
            w.out->truncated = true;
        }
        stack.push_back(std::move(f));
    }

    while (!stack.empty() && !w.stop) {
        Frame& top = stack.back();
        if (top.next >= top.entries.size()) {
            stack.pop_back();
            continue;
        }
        DirEntry entry = std::move(top.entries[top.next++]);
        const std::string parent_path = top.path;
        // `top` may dangle after a push_back below; do not use it past here.

        if (entry.name == "." || entry.name == "..") continue;
        if (entry.name.find('/') != std::string::npos ||
            entry.name.find('\0') != std::string::npos) {
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "directory '" + parent_path +
                     "' has an entry whose name contains '/' or NUL (skipped)");
            continue;
        }
        const std::string path = parent_path.empty() ? entry.name : parent_path + "/" + entry.name;
        if (!count_node(w, path)) break;

        if (entry.inode < sb.first_ino && entry.inode != kRootIno) {
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "'" + path + "' points at reserved inode " + dec(entry.inode) + " (skipped)");
            continue;
        }
        Inode in;
        if (!read_inode(entry.inode, in, &why)) {
            diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                 "'" + path + "': " + why + " (skipped)");
            continue;
        }
        if (in.mode == 0 && in.links == 0) {
            diag(
                *w.out, Severity::Warning, kCodeDirentCorrupt,
                "'" + path + "' points at inode " + dec(entry.inode) + " which is empty (skipped)");
            continue;
        }
        w.reachable.set(entry.inode);
        FileMeta meta = make_meta(w, path, in);
        if (meta.kind == EntryKind::Unknown) {
            diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                 "'" + path + "': inode " + dec(entry.inode) + " has mode " + hex(in.mode) +
                     " with no known type (listed as unknown)");
        }
        if (w.opts->history) w.live[path] = entry.inode;

        if (meta.kind == EntryKind::Regular) {
            emit_regular(w, std::move(meta), in, false);
            continue;
        }
        if (meta.kind == EntryKind::Directory) {
            if (w.dirs_seen.test(entry.inode)) {
                // Either an ancestor (a loop) or a directory hard-linked twice;
                // both are invalid and neither is descended again.
                diag(*w.out, Severity::Warning, kCodeDirLoop,
                     "'" + path + "' refers to directory inode " + dec(entry.inode) +
                         ", which was already listed; not descended");
                continue;
            }
            w.dirs_seen.set(entry.inode);
        }
        const bool placed = emit_other(w, meta);
        if (meta.kind == EntryKind::Directory) {
            if (!placed) continue;  // cannot place children either
            Frame f;
            f.path = path;
            f.inode = entry.inode;
            bool limit_hit = false;
            read_directory(w, in, path, f.entries, &limit_hit);
            if (limit_hit) {
                diag(*w.out, Severity::Warning, kCodeLimitNodes,
                     "'" + path + "' has more than max_nodes_per_fs (" +
                         dec(w.opts->limits.max_nodes_per_fs) + ") entries; listing truncated");
                w.out->truncated = true;
            }
            stack.push_back(std::move(f));
        }
    }
    return true;
}

// History: freed inodes (and allocated but unreachable ones) become deleted
// entries; a name is taken from the slack dirents when one points at the
// inode, else "lost+found/#<inode>". A historical name whose path is live
// with another inode makes the entry superseded. Versions are ordinals per
// path in (dtime, ctime, mtime, inode) order.
void ExtReader::Impl::walk_history(Walk& w) {
    struct Cand {
        std::string path;
        std::uint32_t inode = 0;
        bool allocated = false;
        bool inode_present = true;  // false: only the dirent survives, the inode is empty
        std::uint8_t file_type = 0;
        std::uint32_t dtime = 0;
        std::int64_t ctime = 0, mtime = 0;
        std::uint64_t version = 0;
        std::string other_names;
    };
    if (w.hist.size() >= w.opts->limits.max_nodes_per_fs) {
        diag(*w.out, Severity::Warning, kCodeLimitNodes,
             "more than max_nodes_per_fs (" + dec(w.opts->limits.max_nodes_per_fs) +
                 ") slack directory entries; history names truncated");
        w.out->truncated = true;
    }
    // Names by inode, first seen wins (walk order is deterministic).
    std::map<std::uint32_t, std::vector<const HistDirent*>> names;
    for (const HistDirent& h : w.hist) names[h.inode].push_back(&h);

    std::vector<Cand> cands;
    std::string why;
    auto looks_real = [](const Inode& in) {
        if (in.dtime != 0) return true;
        if (kind_for_mode(in.mode) == EntryKind::Unknown) return false;
        return in.mtime.value_or(0) != 0 || in.ctime.value_or(0) != 0 || in.size != 0;
    };
    // 1. Scan every inode table for freed or orphaned inodes.
    bool scan_stopped = false;
    for (std::uint64_t g = 0; g < sb.groups && !scan_stopped; ++g) {
        GroupDesc gd;
        if (!group_desc(static_cast<std::uint32_t>(g), gd, &why)) {
            diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                 "history: " + why + "; inodes of that group not scanned");
            continue;
        }
        if (gd.flags & kBgInodeUninit) continue;
        const std::uint64_t usable =
            gd.itable_unused < sb.inodes_per_group ? sb.inodes_per_group - gd.itable_unused : 0;
        const bool bitmap_ok = read_block_cached(gd.inode_bitmap, inode_bitmap_buf, &why);
        if (!bitmap_ok)
            diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                 "history: inode bitmap of group " + dec(g) + ": " + why +
                     "; every inode of that group is treated as allocated");
        for (std::uint64_t i = 0; i < usable; ++i) {
            const std::uint64_t ino64 = g * sb.inodes_per_group + i + 1;
            if (ino64 > sb.inodes_count || ino64 > std::numeric_limits<std::uint32_t>::max()) break;
            const std::uint32_t ino = static_cast<std::uint32_t>(ino64);
            if (ino < sb.first_ino) continue;  // reserved inodes are never files
            if (w.reachable.test(ino)) continue;
            const bool allocated =
                !bitmap_ok ||
                ((inode_bitmap_buf.data[static_cast<std::size_t>(i / 8)] >> (i % 8)) & 1u);
            Inode in;
            if (!read_inode(ino, in, &why)) {
                if (i == 0)
                    diag(
                        *w.out, Severity::Warning, kCodeMetadataCorrupt,
                        "history: inode table of group " + dec(g) + ": " + why + "; group skipped");
                break;
            }
            if (!looks_real(in)) continue;
            if (cands.size() >= w.opts->limits.max_nodes_per_fs) {
                diag(*w.out, Severity::Warning, kCodeLimitNodes,
                     "max_nodes_per_fs (" + dec(w.opts->limits.max_nodes_per_fs) +
                         ") freed inodes reached at inode " + dec(ino) + "; history scan stopped");
                w.out->truncated = true;
                scan_stopped = true;
                break;
            }
            Cand c;
            c.inode = ino;
            c.allocated = allocated;
            c.dtime = in.dtime;
            c.ctime = in.ctime.value_or(0);
            c.mtime = in.mtime.value_or(0);
            cands.push_back(std::move(c));
        }
    }
    // 2. Name resolution.
    InodeSet named;
    for (Cand& c : cands) {
        const auto it = names.find(c.inode);
        if (it == names.end()) {
            c.path = "lost+found/#" + dec(c.inode);
            continue;
        }
        named.set(c.inode);
        bool first = true;
        for (const HistDirent* h : it->second) {
            const std::string p = h->parent_path.empty() ? h->name : h->parent_path + "/" + h->name;
            if (first) {
                c.path = p;
                c.file_type = h->file_type;
                first = false;
            } else if (p != c.path) {
                if (!c.other_names.empty()) c.other_names += ';';
                c.other_names += p;
            }
        }
    }
    // Slack names whose inode is reachable are renames (dropped); names whose
    // inode holds nothing become metadata-only deleted entries.
    for (const auto& [ino, list] : names) {
        if (w.reachable.test(ino) || named.test(ino)) continue;
        Cand c;
        c.inode = ino;
        c.inode_present = false;
        const HistDirent* h = list.front();
        c.path = h->parent_path.empty() ? h->name : h->parent_path + "/" + h->name;
        c.file_type = h->file_type;
        for (std::size_t i = 1; i < list.size(); ++i) {
            const std::string p = list[i]->parent_path.empty()
                                      ? list[i]->name
                                      : list[i]->parent_path + "/" + list[i]->name;
            if (p == c.path) continue;
            if (!c.other_names.empty()) c.other_names += ';';
            c.other_names += p;
        }
        cands.push_back(std::move(c));
    }
    // 3. Versions: ordinal per path.
    std::stable_sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        if (a.path != b.path) return a.path < b.path;
        if (a.dtime != b.dtime) return a.dtime < b.dtime;
        if (a.ctime != b.ctime) return a.ctime < b.ctime;
        if (a.mtime != b.mtime) return a.mtime < b.mtime;
        return a.inode < b.inode;
    });
    for (std::size_t i = 0; i < cands.size(); ++i)
        cands[i].version =
            (i > 0 && cands[i - 1].path == cands[i].path) ? cands[i - 1].version + 1 : 1;

    // 4. Emit.
    for (const Cand& c : cands) {
        if (w.stop) break;
        if (!count_node(w, c.path)) break;
        FileMeta meta;
        Inode in;
        if (c.inode_present && read_inode(c.inode, in, &why)) {
            meta = make_meta(w, c.path, in);
        } else {
            meta.path = c.path;
            meta.inode = c.inode;
            meta.kind = kind_for_file_type(c.file_type);
            if (meta.kind == EntryKind::Unknown) meta.kind = EntryKind::Regular;
            meta.extra["content"] = "unavailable: inode cleared";
        }
        if (meta.kind == EntryKind::Unknown) {
            meta.kind = kind_for_file_type(c.file_type);
            if (meta.kind == EntryKind::Unknown) meta.kind = EntryKind::Regular;
        }
        const auto live = w.live.find(c.path);
        if (live != w.live.end() && live->second != c.inode)
            meta.superseded = true;
        else
            meta.deleted = true;
        meta.version = c.version;
        if (!c.other_names.empty()) meta.extra["other_names"] = c.other_names;
        if (c.allocated && c.inode_present)
            meta.extra["orphan"] = "true";  // allocated, no live name
        if (meta.kind == EntryKind::Regular && c.inode_present) {
            emit_regular(w, std::move(meta), in, !c.allocated);
        } else if (meta.kind == EntryKind::Regular) {
            meta.size = 0;
            Status s = w.sink->begin_file(meta);
            if (!s) {
                diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
                continue;
            }
            EntryResult r;
            (void)w.sink->end_file(r);
            r.truncated = true;
            w.out->entries++;
            w.out->files++;
            if (meta.deleted) w.out->deleted++;
            if (meta.superseded) w.out->superseded++;
            w.out->entries_out.push_back(std::move(r));
        } else {
            emit_other(w, meta);
        }
    }
}

// ---------------------------------------------------------------- public API

ExtReader::ExtReader() : impl_(std::make_unique<Impl>()) {}
ExtReader::~ExtReader() = default;

std::string ExtReader::format() const {
    return impl_->opened ? impl_->sb.format : "ext";
}

Status ExtReader::open(const Span& span) {
    Impl& im = *impl_;
    im = Impl{};
    im.span = span;
    if (Status s = im.parse_superblock(); !s) return s;
    im.check_group_descriptors();
    im.opened = true;
    return Status::success();
}

FilesystemInfo ExtReader::info() const {
    const Impl& im = *impl_;
    FilesystemInfo fi;
    fi.format = im.opened ? im.sb.format : "ext";
    if (!im.opened) return fi;
    const Superblock& sb = im.sb;
    fi.label = sb.volume_name;
    fi.size = sat_mul(sb.blocks_count, sb.block_size);
    fi.block_size = static_cast<std::uint32_t>(sb.block_size);
    fi.endian = Endian::Little;
    fi.attrs["volume_name"] = sb.volume_name;
    fi.attrs["uuid"] = uuid_text(sb.uuid.data());
    fi.attrs["block_size"] = dec(sb.block_size);
    fi.attrs["blocks_count"] = dec(sb.blocks_count);
    fi.attrs["inode_count"] = dec(sb.inodes_count);
    fi.attrs["free_blocks"] = dec(sb.free_blocks);
    fi.attrs["free_inodes"] = dec(sb.free_inodes);
    fi.attrs["block_groups"] = dec(sb.groups);
    fi.attrs["blocks_per_group"] = dec(sb.blocks_per_group);
    fi.attrs["inodes_per_group"] = dec(sb.inodes_per_group);
    fi.attrs["inode_size"] = dec(sb.inode_size);
    fi.attrs["first_ino"] = dec(sb.first_ino);
    fi.attrs["rev_level"] = dec(sb.rev_level);
    fi.attrs["feature_compat"] = hex_fixed(sb.compat, 8);
    fi.attrs["feature_incompat"] = hex_fixed(sb.incompat, 8);
    fi.attrs["feature_ro_compat"] = hex_fixed(sb.ro_compat, 8);
    fi.attrs["features"] = flag_names(sb.compat, kCompatNames) + "|" +
                           flag_names(sb.incompat, kIncompatNames) + "|" +
                           flag_names(sb.ro_compat, kRoCompatNames);
    fi.attrs["state"] =
        (sb.state & 2) != 0 ? "errors" : ((sb.state & 1) != 0 ? "clean" : "not-clean");
    fi.attrs["errors_behaviour"] = dec(sb.errors);
    fi.attrs["last_mount_time"] = dec(sb.mtime);
    fi.attrs["last_write_time"] = dec(sb.wtime);
    fi.attrs["last_check_time"] = dec(sb.lastcheck);
    fi.attrs["mkfs_time"] = dec(sb.mkfs_time);
    fi.attrs["mount_count"] = dec(sb.mnt_count);
    fi.attrs["max_mount_count"] = dec(sb.max_mnt_count);
    fi.attrs["last_mounted"] = sb.last_mounted;
    fi.attrs["creator_os"] = creator_os_name(sb.creator_os);
    fi.attrs["has_journal"] = sb.has_journal ? "true" : "false";
    fi.attrs["journal_inode"] =
        dec(sb.has_journal ? (sb.journal_inum != 0 ? sb.journal_inum : kJournalIno) : 0u);
    fi.attrs["needs_recovery"] = (sb.incompat & kIncompatRecover) != 0 ? "true" : "false";
    fi.attrs["csum_type"] = sb.has_metadata_csum
                                ? (sb.checksum_type == 1 ? "crc32c" : dec(sb.checksum_type))
                                : (sb.has_gdt_csum ? "crc16" : "none");
    fi.attrs["desc_size"] = dec(sb.desc_size);
    if (sb.encoding != 0) fi.attrs["encoding"] = dec(sb.encoding);
    return fi;
}

Status ExtReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& im = *impl_;
    if (!im.opened) return Status::fail("ext: walk before a successful open");
    out = WalkResult{};
    for (const Diagnostic& d : im.open_diags) out.diagnostics.push_back(d);
    im.lim = &opts.limits;
    im.gd_cache.clear();

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;
    const bool ok = im.walk_live(w);
    if (ok && opts.history && !w.stop) im.walk_history(w);
    if (w.inode_csum_bad != 0)
        im.diag(out, Severity::Warning, kCodeInodeCsumMismatch,
                dec(w.inode_csum_bad) +
                    " inode checksum(s) do not match (first: " + w.inode_csum_first +
                    "); those inodes were modified without the "
                    "filesystem's knowledge or the image is damaged; entries carry "
                    "extra.checksum=mismatch");
    im.lim = nullptr;  // `opts` does not outlive this call
    if (!ok) return Status::fail("ext-metadata-corrupt: root directory unreadable");
    return Status::success();
}

// One class, three format ids (the validator emits whichever the feature
// flags imply). The macro names its registrar after the type, so aliases keep
// the three registrations distinct.
using Ext2Reader = ExtReader;
using Ext3Reader = ExtReader;
OMNITRACE_REGISTER_FILESYSTEM("ext2", Ext2Reader);
OMNITRACE_REGISTER_FILESYSTEM("ext3", Ext3Reader);
OMNITRACE_REGISTER_FILESYSTEM("ext4", ExtReader);

}  // namespace omnitrace::fs
