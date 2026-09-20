// Qnx6Reader.cpp — QNX6 (fs-qnx6, "Power-Safe") reader with snapshot history.
// See Qnx6Reader.h and docs/formats/qnx6.md.
//
// Format knowledge: the QNX SDP fs-qnx6 documentation, the Linux fs/qnx6
// driver (inode.c, dir.c, namei.c) and NFI's qnxmount qnx6 parser, all read
// for understanding; nothing is copied. Every fact used here was checked
// against the automotive corpus images (docs/formats/qnx6.md "Verified on").
//
// Pipeline:
//   open()  parse the primary superblock at 0x2000 and the second one after
//           the last data block; pick the current snapshot by serial (the
//           checksum-valid one wins, then the higher serial, then the primary)
//   walk()  live tree: root inode 1, directory entries in on-disk order,
//           long names through the longfile table, data streamed block by
//           block through the pointer tree (holes are zeros)
//           history: the other superblock is a complete earlier snapshot;
//           every entry of it whose inode record or path differs from the
//           live tree is emitted as superseded (same path still live) or
//           deleted (path gone), then every inode-table record no live entry
//           names is emitted as deleted, streaming only blocks the current
//           bitmap shows free
#include "Qnx6Reader.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/core/Endian.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_qnx6() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants
// Format constants (fs-qnx6 on-disk layout); not tunable limits.
constexpr std::uint32_t kMagic = 0x68191122u;
constexpr std::uint64_t kBootblockSize = 0x2000;   // primary superblock offset
constexpr std::uint64_t kSuperblockSize = 0x1000;  // area a superblock occupies
constexpr std::uint64_t kSuperblockArea = 0x3000;  // boot block + primary superblock
constexpr std::uint64_t kSuperblockBytes = 512;
constexpr std::uint32_t kHole = 0xFFFFFFFFu;  // unused block pointer
constexpr unsigned kMaxLevels = 5;            // QNX6_PTR_MAX_LEVELS
constexpr std::uint64_t kInodeSize = 128;
constexpr std::uint64_t kDirentSize = 32;
constexpr std::uint8_t kShortNameMax = 27;
constexpr std::uint8_t kLongNameMarker = 0xFF;
constexpr std::uint64_t kLongNameMax = 510;
constexpr std::uint64_t kMinBlocksize = 512;
constexpr std::uint64_t kMaxBlocksize = 65536;
constexpr std::uint32_t kRootIno = 1;
constexpr std::array<std::uint8_t, 4> kBootMagic = {0xEB, 0x10, 0x90, 0x00};
// QNX's PATH_MAX: a symlink target longer than this is corrupt, not data.
constexpr std::uint64_t kMaxSymlinkTarget = 1024;

constexpr std::uint32_t kIfMt = 0170000, kIfSock = 0140000, kIfLnk = 0120000, kIfReg = 0100000,
                        kIfBlk = 0060000, kIfDir = 0040000, kIfChr = 0020000, kIfFifo = 0010000;

// Diagnostic codes. Tests and downstream agents key on these strings.
constexpr const char* kCodeSuperblockBadCrc = "qnx6-superblock-bad-crc";
constexpr const char* kCodeSuperblockSingle = "qnx6-superblock-single";
constexpr const char* kCodeSerialTie = "qnx6-serial-tie";
constexpr const char* kCodeBadSuperblock = "qnx6-bad-superblock";
constexpr const char* kCodeTruncated = "qnx6-truncated";
constexpr const char* kCodeInodeTreeCorrupt = "qnx6-inode-tree-corrupt";
constexpr const char* kCodeLongfileCorrupt = "qnx6-longfile-corrupt";
constexpr const char* kCodeLongfileChecksum = "qnx6-longfile-checksum";
constexpr const char* kCodeDirentCorrupt = "qnx6-dirent-corrupt";
constexpr const char* kCodeDirLoop = "qnx6-dir-loop";
constexpr const char* kCodeBlockOutOfRange = "qnx6-block-out-of-range";
constexpr const char* kCodeDeletedBlocksReused = "qnx6-deleted-blocks-reused";
constexpr const char* kCodeBadSymlink = "qnx6-bad-symlink";
constexpr const char* kCodeLimitNodes = "qnx6-limit-nodes";
constexpr const char* kCodeLimitFiles = "qnx6-limit-files";
constexpr const char* kCodeLimitFileBytes = "qnx6-limit-file-bytes";
constexpr const char* kCodeLimitVersions = "qnx6-limit-versions";
constexpr const char* kCodeUnsupportedFeature = "qnx6-unsupported-feature";
constexpr const char* kCodeSinkError = "qnx6-sink-error";

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
std::string hex_bytes(std::span<const std::uint8_t> b) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (const std::uint8_t x : b) {
        out.push_back(digits[x >> 4]);
        out.push_back(digits[x & 0xF]);
    }
    return out;
}

std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    if (a == 0 || b == 0) return 0;
    return a > UINT64_MAX / b ? UINT64_MAX : a * b;
}
std::uint64_t round_up(std::uint64_t v, std::uint64_t to) {
    return to == 0 ? v : (v + to - 1) / to * to;
}
bool is_pow2(std::uint64_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

// ------------------------------------------------------------------ checksums
// Superblock: CRC-32, polynomial 0x04C11DB7, MSB first, seed 0, no final xor
// (the kernel's crc32_be(0, ...)) over bytes 8..511.
struct CrcBeTable {
    std::array<std::uint32_t, 256> t{};
    constexpr CrcBeTable() {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i << 24;
            for (int k = 0; k < 8; ++k) c = (c & 0x80000000u) ? (c << 1) ^ 0x04C11DB7u : (c << 1);
            t[i] = c;
        }
    }
};
constexpr CrcBeTable kCrcBe{};

std::uint32_t crc32_be(std::span<const std::uint8_t> data) {
    std::uint32_t crc = 0;
    for (const std::uint8_t b : data) crc = kCrcBe.t[((crc >> 24) ^ b) & 0xFFu] ^ (crc << 8);
    return crc;
}

// Long file name checksum as fs-qnx6 stores it in the directory entry.
std::uint32_t longname_checksum(std::span<const std::uint8_t> name) {
    std::uint32_t crc = 0;
    for (const std::uint8_t c : name) {
        // The kernel adds a `char`, so bytes >= 0x80 sign-extend on the
        // usual targets; mirror that.
        const std::uint32_t v =
            static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(c)));
        crc = ((crc >> 1) + v) ^ ((crc & 1u) ? 0x80000000u : 0u);
    }
    return crc;
}

std::uint64_t fnv1a(std::span<const std::uint8_t> data) {
    std::uint64_t h = 0xcbf29ce484222325ull;
    for (const std::uint8_t b : data) {
        h ^= b;
        h *= 0x100000001b3ull;
    }
    return h;
}

// ------------------------------------------------------------------ on-disk records

// A block pointer tree: 16 direct pointers, `levels` of indirection, `size`
// bytes. Root nodes in the superblock and inodes share the shape.
struct Tree {
    std::uint64_t size = 0;
    std::array<std::uint32_t, 16> ptr{};
    std::uint8_t levels = 0;
};

struct Super {
    std::uint64_t off = 0;
    std::uint32_t crc = 0;
    std::uint64_t serial = 0;
    std::uint32_t ctime = 0, atime = 0, flags = 0;
    std::uint16_t version1 = 0, version2 = 0;
    std::array<std::uint8_t, 16> volumeid{};
    std::uint32_t blocksize = 0, num_inodes = 0, free_inodes = 0, num_blocks = 0, free_blocks = 0,
                  allocgroup = 0;
    Tree inodes, bitmap, longfile, iclaim, iextra;
    std::uint8_t inodes_mode = 0;
    bool crc_ok = false;
};

struct Inode {
    std::uint64_t size = 0;
    std::uint32_t uid = 0, gid = 0;
    std::uint32_t ftime = 0, mtime = 0, atime = 0, ctime = 0;
    std::uint16_t mode = 0, ext_mode = 0;
    Tree tree;
    std::uint8_t status = 0;
    std::uint64_t hash = 0;           // over the raw record
    std::uint64_t hash_nostatus = 0;  // raw record with the status byte zeroed
    bool empty() const {
        if (mode != 0 || size != 0) return false;
        for (const std::uint32_t p : tree.ptr)
            if (p != 0 && p != kHole) return false;
        return true;
    }
};

Tree tree_at(const std::uint8_t* p, Endian e) {
    Tree t;
    t.size = load_int<std::uint64_t>(p, e);
    for (std::size_t i = 0; i < 16; ++i) t.ptr[i] = load_int<std::uint32_t>(p + 8 + 4 * i, e);
    t.levels = p[72];
    return t;
}

std::optional<Super> parse_super(const Span& span, std::uint64_t off, Endian e) {
    std::array<std::uint8_t, 512> raw{};
    if (span.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    if (load_int<std::uint32_t>(raw.data(), e) != kMagic) return std::nullopt;
    Super s;
    s.off = off;
    s.crc = load_int<std::uint32_t>(raw.data() + 4, e);
    s.serial = load_int<std::uint64_t>(raw.data() + 8, e);
    s.ctime = load_int<std::uint32_t>(raw.data() + 16, e);
    s.atime = load_int<std::uint32_t>(raw.data() + 20, e);
    s.flags = load_int<std::uint32_t>(raw.data() + 24, e);
    s.version1 = load_int<std::uint16_t>(raw.data() + 28, e);
    s.version2 = load_int<std::uint16_t>(raw.data() + 30, e);
    std::copy(raw.begin() + 32, raw.begin() + 48, s.volumeid.begin());
    s.blocksize = load_int<std::uint32_t>(raw.data() + 48, e);
    s.num_inodes = load_int<std::uint32_t>(raw.data() + 52, e);
    s.free_inodes = load_int<std::uint32_t>(raw.data() + 56, e);
    s.num_blocks = load_int<std::uint32_t>(raw.data() + 60, e);
    s.free_blocks = load_int<std::uint32_t>(raw.data() + 64, e);
    s.allocgroup = load_int<std::uint32_t>(raw.data() + 68, e);
    s.inodes = tree_at(raw.data() + 72, e);
    s.inodes_mode = raw[72 + 73];
    s.bitmap = tree_at(raw.data() + 152, e);
    s.longfile = tree_at(raw.data() + 232, e);
    s.iclaim = tree_at(raw.data() + 312, e);
    s.iextra = tree_at(raw.data() + 392, e);
    s.crc_ok =
        crc32_be(std::span<const std::uint8_t>(raw.data() + 8, kSuperblockBytes - 8)) == s.crc;
    return s;
}

// Why a superblock cannot be used, or empty.
std::string super_problem(const Super& s) {
    if (!is_pow2(s.blocksize) || s.blocksize < kMinBlocksize || s.blocksize > kMaxBlocksize)
        return "blocksize " + dec(s.blocksize) + " is not a power of two in 512..65536";
    if (s.num_blocks == 0) return "num_blocks is 0";
    if (s.num_inodes == 0) return "num_inodes is 0";
    if (s.inodes.levels > kMaxLevels || s.bitmap.levels > kMaxLevels ||
        s.longfile.levels > kMaxLevels)
        return "a root node has " +
               dec(std::max({s.inodes.levels, s.bitmap.levels, s.longfile.levels})) +
               " levels of indirection (max 5)";
    if (s.inodes.size < kInodeSize)
        return "inode table size " + dec(s.inodes.size) + " cannot hold the root inode";
    return {};
}

EntryKind kind_from_mode(std::uint32_t mode) {
    switch (mode & kIfMt) {
        case kIfReg:
            return EntryKind::Regular;
        case kIfDir:
            return EntryKind::Directory;
        case kIfLnk:
            return EntryKind::Symlink;
        case kIfChr:
            return EntryKind::CharDevice;
        case kIfBlk:
            return EntryKind::BlockDevice;
        case kIfFifo:
            return EntryKind::Fifo;
        case kIfSock:
            return EntryKind::Socket;
        default:
            return EntryKind::Unknown;
    }
}

// Result of resolving a file block through a pointer tree.
enum class MapResult { Ok, Hole, OutOfRange, Unreadable };

}  // namespace

// ------------------------------------------------------------------ Impl

struct Qnx6Reader::Impl {
    Span span;
    bool opened = false;
    Endian endian = Endian::Little;
    std::optional<Super> primary, secondary;
    const Super* cur = nullptr;  // current snapshot
    const Super* old = nullptr;  // previous snapshot, when usable
    std::uint64_t bs = 0, data_start = 0, num_blocks = 0, total_size = 0;
    unsigned ptr_shift = 0;  // log2(bs / 4): pointers per indirect block
    bool truncated_image = false;
    std::uint64_t longfile_slots = 0, longfile_count = 0;
    std::vector<Diagnostic> open_diags;
    const Limits* lim = nullptr;

    // Small direct-mapped cache of metadata blocks (inode table, directory,
    // longfile, bitmap and indirect blocks). Data blocks bypass it. A
    // performance knob, not an input guard.
    static constexpr std::size_t kCacheSlots = 32;
    struct CacheSlot {
        std::uint32_t block = kHole;
        std::vector<std::uint8_t> data;
    };
    std::array<CacheSlot, kCacheSlots> cache{};

    // Per-walk state.
    struct LiveRec {
        std::uint32_t ino = 0;
        std::uint64_t hash = 0;
    };
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        bool stop = false;
        std::uint64_t nodes = 0;  // metadata records parsed, against max_nodes_per_fs
        std::vector<std::uint8_t> data;
        std::vector<std::uint8_t> zeros;
        std::map<std::string, LiveRec> live_by_path;
        std::set<std::uint32_t> live_inos;
        std::map<std::uint32_t, std::string> old_path_of;    // ino -> first old-snapshot path
        std::map<std::uint32_t, std::uint64_t> old_deleted;  // ino -> hash_nostatus, if emitted
        std::map<std::string, std::uint32_t> versions_of;    // path -> history entries emitted
        std::uint64_t versions_dropped = 0, reused_files = 0, longfile_checksum_bad = 0,
                      dirents_corrupt = 0, longfile_corrupt = 0, blocks_out_of_range = 0;
    };
    struct HistFlags {
        bool deleted = false, superseded = false;
        std::uint64_t version = 0;
    };

    // blocks
    const std::vector<std::uint8_t>* meta_block(std::uint32_t b);
    bool read_block(std::uint32_t b, std::vector<std::uint8_t>& buf) const;
    MapResult map_block(const Tree& t, std::uint64_t fileblock, std::uint32_t& out);
    const std::vector<std::uint8_t>* tree_block(const Tree& t, std::uint64_t fileblock,
                                                MapResult& why, bool& hole);
    bool block_free(std::uint32_t b);

    // records
    std::optional<Inode> read_inode(const Super& s, std::uint32_t ino, std::string& why);
    std::optional<std::string> long_name(const Super& s, std::uint32_t index,
                                         std::uint32_t checksum, Walk& w, std::string& why);
    std::uint64_t inode_capacity(const Super& s) const {
        return std::min<std::uint64_t>(s.num_inodes, s.inodes.size / kInodeSize);
    }

    // emission
    FileMeta make_meta(const std::string& path, std::uint32_t ino, const Inode& in,
                       const HistFlags& hf) const;
    bool stream_data(const Inode& in, const std::string& path, Walk& w, bool check_free,
                     std::vector<Diagnostic>& diags, bool& truncated);
    std::vector<std::uint8_t> small_content(const Inode& in, std::uint64_t cap, Walk& w,
                                            bool check_free, std::vector<Diagnostic>& diags,
                                            bool& truncated);
    void emit(const std::string& path, std::uint32_t ino, const Inode& in, const HistFlags& hf,
              bool check_free, Walk& w, std::map<std::string, std::string> extra);
    void count_entry(WalkResult& out, const FileMeta& m) const;
    bool check_files(const std::string& path, Walk& w);
    bool check_nodes(Walk& w);
    bool check_versions(const std::string& path, Walk& w);

    // walk phases
    void walk_snapshot(const Super& s, bool live, Walk& w);
    void walk_deleted_inodes(Walk& w);

    void diag(WalkResult& out, Severity sev, const char* code, std::string msg) const {
        out.diagnostics.push_back({sev, code, std::move(msg)});
    }
};

// ------------------------------------------------------------------ blocks

bool Qnx6Reader::Impl::read_block(std::uint32_t b, std::vector<std::uint8_t>& buf) const {
    if (b == kHole || b >= num_blocks) return false;
    const std::uint64_t off = data_start + static_cast<std::uint64_t>(b) * bs;
    buf.resize(static_cast<std::size_t>(bs));
    return span.read(off, std::span<std::uint8_t>(buf.data(), buf.size())) == buf.size();
}

const std::vector<std::uint8_t>* Qnx6Reader::Impl::meta_block(std::uint32_t b) {
    if (b == kHole || b >= num_blocks) return nullptr;
    CacheSlot& slot = cache[b % kCacheSlots];
    if (slot.block == b) return &slot.data;
    if (!read_block(b, slot.data)) {
        slot.block = kHole;
        return nullptr;
    }
    slot.block = b;
    return &slot.data;
}

// Resolve file block `fileblock` of tree `t` to a device block, descending
// the indirection levels the way fs-qnx6 does: the direct pointer index is
// the file block shifted right by ptr_shift * levels, then each level takes
// the next ptr_shift bits.
MapResult Qnx6Reader::Impl::map_block(const Tree& t, std::uint64_t fileblock, std::uint32_t& out) {
    const unsigned levels = t.levels;
    if (levels > kMaxLevels) return MapResult::OutOfRange;
    unsigned bitdelta = ptr_shift * levels;
    const std::uint64_t direct = bitdelta >= 64 ? 0 : fileblock >> bitdelta;
    if (direct >= 16) return MapResult::OutOfRange;
    std::uint32_t ptr = t.ptr[static_cast<std::size_t>(direct)];
    const std::uint64_t mask = (std::uint64_t{1} << ptr_shift) - 1;
    for (unsigned l = 0; l < levels; ++l) {
        if (ptr == kHole) {
            out = kHole;
            return MapResult::Hole;
        }
        const std::vector<std::uint8_t>* blk = meta_block(ptr);
        if (!blk) return ptr >= num_blocks ? MapResult::OutOfRange : MapResult::Unreadable;
        bitdelta -= ptr_shift;
        const std::uint64_t idx = (bitdelta >= 64 ? 0 : fileblock >> bitdelta) & mask;
        ptr = load_int<std::uint32_t>(blk->data() + idx * 4, endian);
    }
    out = ptr;
    if (ptr == kHole) return MapResult::Hole;
    if (ptr >= num_blocks) return MapResult::OutOfRange;
    return MapResult::Ok;
}

// A metadata block of a tree file through the cache; `hole` set (and nullptr
// returned) for an unused pointer.
const std::vector<std::uint8_t>* Qnx6Reader::Impl::tree_block(const Tree& t,
                                                              std::uint64_t fileblock,
                                                              MapResult& why, bool& hole) {
    hole = false;
    std::uint32_t b = kHole;
    why = map_block(t, fileblock, b);
    if (why == MapResult::Hole) {
        hole = true;
        return nullptr;
    }
    if (why != MapResult::Ok) return nullptr;
    const std::vector<std::uint8_t>* blk = meta_block(b);
    if (!blk) why = MapResult::Unreadable;
    return blk;
}

// Block `b` is free in the current snapshot's bitmap. The bitmap covers the
// whole partition from byte 0 in block units, so data block `b` is bit
// (data_start / bs) + b; one bit set = allocated. Anything the bitmap does
// not cover is treated as allocated.
bool Qnx6Reader::Impl::block_free(std::uint32_t b) {
    const std::uint64_t bit = data_start / bs + b;
    const std::uint64_t byte = bit / 8;
    if (byte >= cur->bitmap.size) return false;
    MapResult why = MapResult::Ok;
    bool hole = false;
    const std::vector<std::uint8_t>* blk = tree_block(cur->bitmap, byte / bs, why, hole);
    if (hole) return true;  // an unused bitmap block reads as zeros: free
    if (!blk) return false;
    const std::uint8_t v = (*blk)[static_cast<std::size_t>(byte % bs)];
    return ((v >> (bit % 8)) & 1u) == 0;
}

// ------------------------------------------------------------------ records

std::optional<Inode> Qnx6Reader::Impl::read_inode(const Super& s, std::uint32_t ino,
                                                  std::string& why) {
    if (ino == 0 || ino > inode_capacity(s)) {
        why = "inode " + dec(ino) + " is outside the inode table (" + dec(inode_capacity(s)) +
              " records)";
        return std::nullopt;
    }
    const std::uint64_t off = static_cast<std::uint64_t>(ino - 1) * kInodeSize;
    MapResult mr = MapResult::Ok;
    bool hole = false;
    const std::vector<std::uint8_t>* blk = tree_block(s.inodes, off / bs, mr, hole);
    if (hole) {
        why = "inode " + dec(ino) + " lies in an unused block of the inode table";
        return std::nullopt;
    }
    if (!blk) {
        why =
            "inode " + dec(ino) + ": inode table block " + dec(off / bs) +
            (mr == MapResult::OutOfRange ? " points outside the data area" : " could not be read");
        return std::nullopt;
    }
    const std::uint8_t* p = blk->data() + off % bs;  // 128 divides every block size
    Inode in;
    in.size = load_int<std::uint64_t>(p, endian);
    in.uid = load_int<std::uint32_t>(p + 8, endian);
    in.gid = load_int<std::uint32_t>(p + 12, endian);
    in.ftime = load_int<std::uint32_t>(p + 16, endian);
    in.mtime = load_int<std::uint32_t>(p + 20, endian);
    in.atime = load_int<std::uint32_t>(p + 24, endian);
    in.ctime = load_int<std::uint32_t>(p + 28, endian);
    in.mode = load_int<std::uint16_t>(p + 32, endian);
    in.ext_mode = load_int<std::uint16_t>(p + 34, endian);
    in.tree.size = in.size;
    for (std::size_t i = 0; i < 16; ++i)
        in.tree.ptr[i] = load_int<std::uint32_t>(p + 36 + 4 * i, endian);
    in.tree.levels = p[100];
    in.status = p[101];
    std::array<std::uint8_t, kInodeSize> raw{};
    std::copy(p, p + kInodeSize, raw.begin());
    in.hash = fnv1a(raw);
    raw[101] = 0;
    in.hash_nostatus = fnv1a(raw);
    return in;
}

// Long file name `index` (in blocks of the longfile table): u16 length then
// the name, at most 510 bytes.
std::optional<std::string> Qnx6Reader::Impl::long_name(const Super& s, std::uint32_t index,
                                                       std::uint32_t checksum, Walk& w,
                                                       std::string& why) {
    const std::uint64_t off = sat_mul(index, bs);
    if (sat_add(off, 2) > s.longfile.size) {
        why = "long name index " + dec(index) + " is past the longfile table (" +
              dec(s.longfile.size) + " bytes)";
        return std::nullopt;
    }
    MapResult mr = MapResult::Ok;
    bool hole = false;
    const std::vector<std::uint8_t>* blk = tree_block(s.longfile, index, mr, hole);
    if (!blk) {
        why = "long name index " + dec(index) +
              (hole ? " lies in an unused block" : " could not be read");
        return std::nullopt;
    }
    const std::uint64_t len = load_int<std::uint16_t>(blk->data(), endian);
    if (len == 0 || len > kLongNameMax || len + 2 > bs) {
        why = "long name index " + dec(index) + " has length " + dec(len);
        return std::nullopt;
    }
    const std::span<const std::uint8_t> name(blk->data() + 2, static_cast<std::size_t>(len));
    if (longname_checksum(name) != checksum) w.longfile_checksum_bad++;
    return std::string(name.begin(), name.end());
}

// ------------------------------------------------------------------ emission

FileMeta Qnx6Reader::Impl::make_meta(const std::string& path, std::uint32_t ino, const Inode& in,
                                     const HistFlags& hf) const {
    FileMeta m;
    m.path = path;
    m.kind = kind_from_mode(in.mode);
    if (m.kind == EntryKind::Unknown && in.mode == 0) m.kind = EntryKind::Regular;
    m.mode = in.mode & 07777u;
    m.uid = in.uid;
    m.gid = in.gid;
    m.size = m.kind == EntryKind::Directory ? 0 : in.size;
    m.mtime = static_cast<std::int64_t>(in.mtime);
    m.atime = static_cast<std::int64_t>(in.atime);
    m.ctime = static_cast<std::int64_t>(in.ctime);
    m.crtime = static_cast<std::int64_t>(in.ftime);
    m.inode = ino;
    m.nlink = 1;  // fs-qnx6 keeps no link count in the inode
    m.deleted = hf.deleted;
    m.superseded = hf.superseded;
    m.version = hf.version;
    m.extra["status"] = hex(in.status);
    if (in.ext_mode != 0) m.extra["ext_mode"] = hex(in.ext_mode);
    if (in.tree.levels != 0) m.extra["levels"] = dec(in.tree.levels);
    return m;
}

// Stream the data blocks of `in` to the Sink in file order. Holes are zeros;
// a block outside the data area (or, with `check_free`, one the current
// bitmap shows allocated again) is zero-filled and the entry marked
// truncated. Returns false when the Sink refused.
bool Qnx6Reader::Impl::stream_data(const Inode& in, const std::string& path, Walk& w,
                                   bool check_free, std::vector<Diagnostic>& diags,
                                   bool& truncated) {
    const Limits& L = *lim;
    std::uint64_t total = in.size;
    if (total > L.max_file_bytes) {
        diags.push_back({Severity::Warning, kCodeLimitFileBytes,
                         "'" + path + "': size " + dec(in.size) + " exceeds max_file_bytes (" +
                             dec(L.max_file_bytes) + "); data cut there"});
        total = L.max_file_bytes;
        truncated = true;
    }
    if (w.zeros.size() != bs) w.zeros.assign(static_cast<std::size_t>(bs), 0);
    bool range_reported = false, reused_reported = false;
    std::uint64_t pos = 0;
    for (std::uint64_t fb = 0; pos < total; ++fb) {
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(bs, total - pos));
        std::uint32_t b = kHole;
        const MapResult mr = map_block(in.tree, fb, b);
        const std::uint8_t* src = w.zeros.data();
        if (mr == MapResult::Ok) {
            if (check_free && !block_free(b)) {
                if (!reused_reported) {
                    diags.push_back({Severity::Warning, kCodeDeletedBlocksReused,
                                     "'" + path + "': block " + dec(b) + " (file block " + dec(fb) +
                                         ") is allocated again in the current snapshot; "
                                         "zero-filled"});
                    reused_reported = true;
                    w.reused_files++;
                }
                truncated = true;
            } else if (read_block(b, w.data)) {
                src = w.data.data();
            } else {
                truncated = true;
                if (!range_reported) {
                    diags.push_back({Severity::Warning, kCodeBlockOutOfRange,
                                     "'" + path + "': block " + dec(b) + " (file block " + dec(fb) +
                                         ") could not be read; zero-filled"});
                    range_reported = true;
                    w.blocks_out_of_range++;
                }
            }
        } else if (mr != MapResult::Hole) {
            truncated = true;
            if (!range_reported) {
                diags.push_back({Severity::Warning, kCodeBlockOutOfRange,
                                 "'" + path + "': file block " + dec(fb) +
                                     (mr == MapResult::OutOfRange
                                          ? " maps outside the data area (or the tree is "
                                            "deeper than the pointers allow)"
                                          : " sits behind an unreadable indirect block") +
                                     "; zero-filled from here"});
                range_reported = true;
                w.blocks_out_of_range++;
            }
        }
        if (Status st = w.sink->write(std::span<const std::uint8_t>(src, n)); !st) return false;
        pos += n;
    }
    return true;
}

// Whole content in memory, capped at `cap` bytes (symlink targets).
std::vector<std::uint8_t> Qnx6Reader::Impl::small_content(const Inode& in, std::uint64_t cap,
                                                          Walk& w, bool check_free,
                                                          std::vector<Diagnostic>& diags,
                                                          bool& truncated) {
    std::vector<std::uint8_t> out;
    const std::uint64_t total = std::min(in.size, cap);
    if (w.zeros.size() != bs) w.zeros.assign(static_cast<std::size_t>(bs), 0);
    std::uint64_t pos = 0;
    for (std::uint64_t fb = 0; pos < total; ++fb) {
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(bs, total - pos));
        std::uint32_t b = kHole;
        const MapResult mr = map_block(in.tree, fb, b);
        const std::uint8_t* src = w.zeros.data();
        if (mr == MapResult::Ok && (!check_free || block_free(b)) && read_block(b, w.data)) {
            src = w.data.data();
        } else if (mr != MapResult::Hole) {
            truncated = true;
            diags.push_back({Severity::Warning,
                             mr == MapResult::Ok && check_free ? kCodeDeletedBlocksReused
                                                               : kCodeBlockOutOfRange,
                             "inode data block " + dec(fb) + " unavailable; zero-filled"});
        }
        out.insert(out.end(), src, src + n);
        pos += n;
    }
    return out;
}

void Qnx6Reader::Impl::count_entry(WalkResult& out, const FileMeta& m) const {
    out.entries++;
    switch (m.kind) {
        case EntryKind::Regular:
            out.files++;
            break;
        case EntryKind::Directory:
            out.dirs++;
            break;
        case EntryKind::Symlink:
            out.symlinks++;
            break;
        default:
            out.others++;
            break;
    }
    if (m.superseded) out.superseded++;
    if (m.deleted) out.deleted++;
}

bool Qnx6Reader::Impl::check_files(const std::string& path, Walk& w) {
    const Limits& L = w.opts->limits;
    if (w.out->entries >= L.max_files) {
        diag(*w.out, Severity::Warning, kCodeLimitFiles,
             "max_files (" + dec(L.max_files) + ") reached at '" + path + "'; walk stopped");
        w.out->truncated = true;
        w.stop = true;
        return false;
    }
    return true;
}

bool Qnx6Reader::Impl::check_nodes(Walk& w) {
    const Limits& L = w.opts->limits;
    if (++w.nodes > L.max_nodes_per_fs) {
        diag(*w.out, Severity::Warning, kCodeLimitNodes,
             "max_nodes_per_fs (" + dec(L.max_nodes_per_fs) +
                 ") metadata records parsed; walk stopped");
        w.out->truncated = true;
        w.stop = true;
        return false;
    }
    return true;
}

// History entries per path against Limits::max_versions_per_entry.
bool Qnx6Reader::Impl::check_versions(const std::string& path, Walk& w) {
    std::uint32_t& n = w.versions_of[path];
    if (n >= w.opts->limits.max_versions_per_entry) {
        w.versions_dropped++;
        return false;
    }
    ++n;
    return true;
}

void Qnx6Reader::Impl::emit(const std::string& path, std::uint32_t ino, const Inode& in,
                            const HistFlags& hf, bool check_free, Walk& w,
                            std::map<std::string, std::string> extra) {
    if (!check_files(path, w)) return;
    FileMeta m = make_meta(path, ino, in, hf);
    for (auto& [k, v] : extra) m.extra[k] = v;
    std::vector<Diagnostic> diags;
    bool truncated = false;
    if (m.kind == EntryKind::Regular) {
        Status s = w.sink->begin_file(m);
        if (!s) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
            return;
        }
        bool sink_ok = true;
        if (w.opts->extract_data) sink_ok = stream_data(in, path, w, check_free, diags, truncated);
        EntryResult r;
        s = w.sink->end_file(r);
        if (!s) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
            if (r.meta.path.empty()) return;
        }
        if (!sink_ok || truncated) r.truncated = true;
        for (Diagnostic& d : diags) r.diagnostics.push_back(std::move(d));
        w.out->bytes += r.digests.bytes;
        count_entry(*w.out, r.meta);
        w.out->entries_out.push_back(std::move(r));
        return;
    }
    if (m.kind == EntryKind::Symlink) {
        if (in.size > kMaxSymlinkTarget) {
            diags.push_back({Severity::Warning, kCodeBadSymlink,
                             "'" + path + "': symlink target length " + dec(in.size) +
                                 " exceeds PATH_MAX (" + dec(kMaxSymlinkTarget) + "); target cut"});
            truncated = true;
        }
        const std::vector<std::uint8_t> t =
            small_content(in, kMaxSymlinkTarget, w, check_free, diags, truncated);
        m.link_target.assign(t.begin(), t.end());
        m.size = t.size();
    }
    EntryResult r;
    const Status s = w.sink->entry(m, r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
        return;
    }
    r.truncated = r.truncated || truncated;
    for (Diagnostic& d : diags) r.diagnostics.push_back(std::move(d));
    count_entry(*w.out, r.meta);
    w.out->entries_out.push_back(std::move(r));
}

// ------------------------------------------------------------------ walks

// Walk one snapshot from its root inode, directory entries in on-disk order.
// `live`: emit everything and record it. Otherwise (the previous snapshot)
// emit only what differs from the live tree, as superseded or deleted.
void Qnx6Reader::Impl::walk_snapshot(const Super& s, bool live, Walk& w) {
    struct Frame {
        std::uint32_t ino;
        Tree tree;
        std::string path;
        std::uint64_t pos = 0;  // byte offset in the directory data
        bool bad_block_reported = false;
    };
    std::string why;
    const auto root = read_inode(s, kRootIno, why);
    if (!root) {
        diag(*w.out, live ? Severity::Error : Severity::Warning, kCodeInodeTreeCorrupt,
             std::string(live ? "current" : "previous") + " snapshot (serial " + dec(s.serial) +
                 "): root inode unreadable: " + why);
        return;
    }
    if ((root->mode & kIfMt) != kIfDir) {
        diag(*w.out, live ? Severity::Error : Severity::Warning, kCodeInodeTreeCorrupt,
             std::string(live ? "current" : "previous") + " snapshot (serial " + dec(s.serial) +
                 "): root inode mode " + hex(root->mode) + " is not a directory");
        return;
    }
    if (live) w.live_inos.insert(kRootIno);
    std::set<std::uint32_t> visited{kRootIno};
    std::vector<Frame> stack;
    stack.push_back({kRootIno, root->tree, "", 0});
    const std::uint64_t entries_per_block = bs / kDirentSize;

    while (!stack.empty() && !w.stop) {
        Frame& top = stack.back();
        if (top.pos >= top.tree.size) {
            stack.pop_back();
            continue;
        }
        const std::uint64_t fileblock = top.pos / bs;
        // Every directory block is a metadata record against max_nodes_per_fs:
        // a directory whose size claims 2^56 bytes of holes or unmapped blocks
        // ends with the node budget, not with one diagnostic per block.
        if (top.pos % bs == 0 && !check_nodes(w)) break;
        MapResult mr = MapResult::Ok;
        bool hole = false;
        const std::vector<std::uint8_t>* blk = tree_block(top.tree, fileblock, mr, hole);
        if (!blk) {
            if (!hole && !top.bad_block_reported) {
                top.bad_block_reported = true;
                diag(*w.out, Severity::Warning, kCodeInodeTreeCorrupt,
                     "directory '" + top.path + "' (inode " + dec(top.ino) + "): block " +
                         dec(fileblock) +
                         (mr == MapResult::OutOfRange ? " maps outside the data area"
                                                      : " could not be read") +
                         "; the block is skipped (later unmapped blocks of this directory "
                         "are not reported)");
            }
            top.pos = sat_mul(fileblock + 1, bs);
            continue;
        }
        const std::uint64_t slot = (top.pos % bs) / kDirentSize;
        top.pos += kDirentSize;
        if (slot >= entries_per_block) continue;  // cannot happen: bs is a multiple of 32
        const std::uint8_t* e = blk->data() + slot * kDirentSize;
        const std::uint32_t ino = load_int<std::uint32_t>(e, endian);
        const std::uint8_t len = e[4];
        if (ino == 0) continue;  // free slot
        if (!check_nodes(w)) break;

        const std::string parent_path = top.path;
        const std::uint32_t parent_ino = top.ino;
        // `top` may dangle after a push_back below; do not use it past here.

        std::string name;
        if (len == kLongNameMarker) {
            const std::uint32_t index = load_int<std::uint32_t>(e + 8, endian);
            const std::uint32_t checksum = load_int<std::uint32_t>(e + 12, endian);
            const auto ln = long_name(s, index, checksum, w, why);
            if (!ln) {
                w.longfile_corrupt++;
                diag(*w.out, Severity::Warning, kCodeLongfileCorrupt,
                     "directory '" + parent_path + "' (inode " + dec(parent_ino) + "): " + why +
                         "; entry for inode " + dec(ino) + " skipped");
                continue;
            }
            name = *ln;
        } else if (len == 0 || len > kShortNameMax) {
            w.dirents_corrupt++;
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "directory '" + parent_path + "' (inode " + dec(parent_ino) +
                     "): entry for inode " + dec(ino) + " has name length " + dec(len) +
                     "; skipped");
            continue;
        } else {
            name.assign(reinterpret_cast<const char*>(e + 5), len);
        }
        if (name == "." || name == "..") continue;
        if (name.find('/') != std::string::npos || name.find('\0') != std::string::npos) {
            w.dirents_corrupt++;
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "directory '" + parent_path + "' (inode " + dec(parent_ino) +
                     "): entry for inode " + dec(ino) + " has a name with '/' or NUL; skipped");
            continue;
        }
        const std::string path = parent_path.empty() ? name : parent_path + "/" + name;

        const auto in = read_inode(s, ino, why);
        if (!in) {
            diag(*w.out, Severity::Warning, kCodeInodeTreeCorrupt, "'" + path + "': " + why);
            continue;
        }
        if (in->mode == 0) {
            w.dirents_corrupt++;
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "'" + path + "' names inode " + dec(ino) + ", whose record is unused; skipped");
            continue;
        }
        const bool is_dir = (in->mode & kIfMt) == kIfDir;

        HistFlags hf;
        bool emit_it = true;
        if (live) {
            hf.version = s.serial;
            w.live_by_path[path] = {ino, in->hash};
            w.live_inos.insert(ino);
        } else {
            const auto lp = w.live_by_path.find(path);
            const bool identical =
                lp != w.live_by_path.end() && lp->second.ino == ino && lp->second.hash == in->hash;
            if (!w.old_path_of.count(ino)) w.old_path_of[ino] = path;
            hf.version = s.serial;
            if (identical) {
                emit_it = false;
            } else if (lp != w.live_by_path.end()) {
                hf.superseded = true;
            } else {
                hf.deleted = true;
                w.old_deleted[ino] = in->hash_nostatus;
            }
            if (emit_it && !check_versions(path, w)) emit_it = false;
        }

        if (is_dir) {
            bool loop = false;
            for (const Frame& f : stack)
                if (f.ino == ino) loop = true;
            const bool seen = !loop && visited.count(ino) != 0;
            if (loop) {
                diag(*w.out, Severity::Warning, kCodeDirLoop,
                     "'" + path + "' refers to ancestor directory inode " + dec(ino) +
                         "; not descended");
                continue;
            }
            if (emit_it) {
                std::map<std::string, std::string> extra;
                emit(path, ino, *in, hf, false, w, extra);
            }
            if (seen) {
                diag(*w.out, Severity::Warning, kCodeDirLoop,
                     "'" + path + "' is a second name for directory inode " + dec(ino) +
                         "; listed once, not descended again");
                continue;
            }
            visited.insert(ino);
            stack.push_back({ino, in->tree, path, 0});
            continue;
        }
        if (emit_it) emit(path, ino, *in, hf, false, w, {});
    }
}

// Inode-table records of the current snapshot that no live entry names but
// that still describe a file: emitted as deleted, streaming only blocks the
// current bitmap shows free.
void Qnx6Reader::Impl::walk_deleted_inodes(Walk& w) {
    const std::uint64_t capacity = inode_capacity(*cur);
    std::uint64_t orphans = 0;
    for (std::uint64_t ino = 1; ino <= capacity && !w.stop; ++ino) {
        const std::uint32_t n = static_cast<std::uint32_t>(ino);
        if (w.live_inos.count(n)) continue;
        if (!check_nodes(w)) break;
        std::string why;
        const auto in = read_inode(*cur, n, why);
        if (!in || in->empty()) continue;
        const auto od = w.old_deleted.find(n);
        if (od != w.old_deleted.end() && od->second == in->hash_nostatus)
            continue;  // already emitted, with intact data, from the previous snapshot
        std::string path;
        const auto op = w.old_path_of.find(n);
        std::map<std::string, std::string> extra;
        extra["record"] = "inode-table";
        if (op != w.old_path_of.end()) {
            path = op->second;
        } else {
            path = "lost+found/#" + dec(n);
            extra["orphan"] = "true";
            orphans++;
        }
        if (!check_versions(path, w)) continue;
        HistFlags hf;
        hf.deleted = true;
        hf.version = cur->serial;
        Inode copy = *in;
        if ((copy.mode & kIfMt) == kIfDir) {
            // A deleted directory's entries are not walked: its children are
            // reached through their own records.
            emit(path, n, copy, hf, true, w, extra);
            continue;
        }
        emit(path, n, copy, hf, true, w, extra);
    }
    if (orphans != 0)
        diag(*w.out, Severity::Info, kCodeDirentCorrupt,
             dec(orphans) +
                 " inode-table record(s) with data that neither snapshot names; emitted under "
                 "lost+found/#<inode>");
}

// ------------------------------------------------------------------ public API

Qnx6Reader::Qnx6Reader() : impl_(std::make_unique<Impl>()) {}
Qnx6Reader::~Qnx6Reader() = default;

std::string Qnx6Reader::format() const {
    return "qnx6";
}

Status Qnx6Reader::open(const Span& span) {
    Impl& im = *impl_;
    im = Impl{};
    im.span = span;

    // Primary superblock at 0x2000, either byte order.
    for (const Endian e : {Endian::Little, Endian::Big}) {
        im.primary = parse_super(span, kBootblockSize, e);
        if (im.primary) {
            im.endian = e;
            break;
        }
    }
    std::string primary_problem = im.primary ? super_problem(*im.primary) : "no magic at 0x2000";
    if (!primary_problem.empty() && im.primary) {
        im.open_diags.push_back({Severity::Warning, kCodeBadSuperblock,
                                 "primary superblock unusable: " + primary_problem});
    }

    // Second superblock: after the last data block per the primary; when the
    // primary is unusable, at the tail of the Span (one superblock area of
    // any supported block size before the end).
    if (im.primary && primary_problem.empty()) {
        const Super& p = *im.primary;
        const std::uint64_t ds = round_up(kSuperblockArea, p.blocksize);
        const std::uint64_t at = sat_add(ds, sat_mul(p.num_blocks, p.blocksize));
        if (at < span.size()) im.secondary = parse_super(span, at, im.endian);
        if (!im.secondary && span.matches_at(0, kBootMagic)) {
            for (const Endian he : {Endian::Little, Endian::Big}) {
                const auto sblk1 = span.at<std::uint32_t>(12, he);
                if (!sblk1) break;
                const std::uint64_t hint = sat_mul(*sblk1, 512);
                if (hint != kBootblockSize && hint < span.size()) {
                    im.secondary = parse_super(span, hint, im.endian);
                    if (im.secondary) break;
                }
            }
        }
    } else {
        for (std::uint64_t tail = kSuperblockSize; tail <= kMaxBlocksize && !im.secondary;
             tail <<= 1) {
            if (span.size() < tail + kSuperblockArea) break;
            for (const Endian e : {Endian::Little, Endian::Big}) {
                im.secondary = parse_super(span, span.size() - tail, e);
                if (im.secondary) {
                    im.endian = e;
                    break;
                }
            }
        }
    }
    std::string secondary_problem = im.secondary ? super_problem(*im.secondary) : "not found";
    if (im.secondary && !secondary_problem.empty()) {
        im.open_diags.push_back(
            {Severity::Warning, kCodeBadSuperblock,
             "second superblock at " + hex(im.secondary->off) + " unusable: " + secondary_problem});
        im.secondary.reset();
    }
    if (im.primary && !primary_problem.empty()) im.primary.reset();
    if (!im.primary && !im.secondary) {
        return Status::fail("qnx6-no-superblock: " + primary_problem + "; second superblock " +
                            secondary_problem);
    }
    if (im.primary && !im.primary->crc_ok)
        im.open_diags.push_back(
            {Severity::Warning, kCodeSuperblockBadCrc,
             "primary superblock checksum " + hex(im.primary->crc) + " does not verify"});
    if (im.secondary && !im.secondary->crc_ok)
        im.open_diags.push_back({Severity::Warning, kCodeSuperblockBadCrc,
                                 "second superblock at " + hex(im.secondary->off) + " checksum " +
                                     hex(im.secondary->crc) + " does not verify"});

    // Current snapshot: the checksum-valid one wins; among equals the higher
    // serial, and the primary on a tie (fs-qnx6 and the kernel do the same).
    if (im.primary && im.secondary) {
        const Super& p = *im.primary;
        const Super& s = *im.secondary;
        const bool prefer_second =
            (s.crc_ok && !p.crc_ok) || (s.crc_ok == p.crc_ok && s.serial > p.serial);
        im.cur = prefer_second ? &s : &p;
        im.old = prefer_second ? &p : &s;
        if (p.serial == s.serial)
            im.open_diags.push_back({Severity::Info, kCodeSerialTie,
                                     "both superblocks carry serial " + dec(p.serial) +
                                         "; the primary is the current snapshot and the "
                                         "second holds no distinct history"});
    } else {
        im.cur = im.primary ? &*im.primary : &*im.secondary;
        im.old = nullptr;
        im.open_diags.push_back({Severity::Info, kCodeSuperblockSingle,
                                 std::string(im.primary ? "no second" : "no primary") +
                                     " superblock; only one snapshot is available, so "
                                     "snapshot history cannot be recovered"});
    }
    if (im.old && im.old->blocksize != im.cur->blocksize) {
        im.open_diags.push_back({Severity::Warning, kCodeBadSuperblock,
                                 "the two superblocks disagree on blocksize (" +
                                     dec(im.cur->blocksize) + " vs " + dec(im.old->blocksize) +
                                     "); the previous snapshot is ignored"});
        im.old = nullptr;
    }

    im.bs = im.cur->blocksize;
    im.data_start = round_up(kSuperblockArea, im.bs);
    im.num_blocks = im.cur->num_blocks;
    im.ptr_shift = 0;
    while ((std::uint64_t{1} << im.ptr_shift) < im.bs / 4) ++im.ptr_shift;
    im.total_size = sat_add(sat_add(im.data_start, sat_mul(im.num_blocks, im.bs)),
                            round_up(kSuperblockSize, im.bs));
    if (im.total_size > span.size()) {
        im.truncated_image = true;
        im.open_diags.push_back({Severity::Warning, kCodeTruncated,
                                 "num_blocks " + dec(im.num_blocks) + " x blocksize " + dec(im.bs) +
                                     " claims " + dec(im.total_size) + " bytes but only " +
                                     dec(span.size()) +
                                     " are available; blocks past the end read as out of range"});
    }
    if (im.cur->version1 != 4)
        im.open_diags.push_back({Severity::Warning, kCodeUnsupportedFeature,
                                 "superblock version " + dec(im.cur->version1) + "." +
                                     dec(im.cur->version2) +
                                     "; this reader's layout was verified on version 4.x only"});
    if (im.cur->iclaim.size != 0 || im.cur->iextra.size != 0)
        im.open_diags.push_back({Severity::Info, kCodeUnsupportedFeature,
                                 "the iclaim (" + dec(im.cur->iclaim.size) + " bytes) / iextra (" +
                                     dec(im.cur->iextra.size) +
                                     " bytes) trees are not decoded by this reader"});

    // Long file names in use (bounded by the default node budget).
    im.opened = true;
    {
        const Limits defaults;
        im.longfile_slots = im.cur->longfile.size / im.bs;
        const std::uint64_t scan = std::min(im.longfile_slots, defaults.max_nodes_per_fs);
        for (std::uint64_t i = 0; i < scan; ++i) {
            MapResult mr = MapResult::Ok;
            bool hole = false;
            const std::vector<std::uint8_t>* blk = im.tree_block(im.cur->longfile, i, mr, hole);
            if (!blk) continue;
            const std::uint16_t len = load_int<std::uint16_t>(blk->data(), im.endian);
            if (len != 0 && len <= kLongNameMax) im.longfile_count++;
        }
    }
    return Status::success();
}

FilesystemInfo Qnx6Reader::info() const {
    const Impl& im = *impl_;
    FilesystemInfo fi;
    fi.format = "qnx6";
    if (!im.opened) return fi;
    const Super& c = *im.cur;
    fi.endian = im.endian;
    fi.size = im.total_size;
    fi.block_size = static_cast<std::uint32_t>(im.bs);
    fi.attrs["endian"] = endian_name(im.endian);
    fi.attrs["blocksize"] = dec(c.blocksize);
    fi.attrs["num_blocks"] = dec(c.num_blocks);
    fi.attrs["num_inodes"] = dec(c.num_inodes);
    fi.attrs["free_inodes"] = dec(c.free_inodes);
    fi.attrs["free_blocks"] = dec(c.free_blocks);
    fi.attrs["serial"] = dec(c.serial);
    fi.attrs["ctime"] = dec(c.ctime);
    fi.attrs["atime"] = dec(c.atime);
    fi.attrs["flags"] = hex(c.flags);
    fi.attrs["version"] = dec(c.version1) + "." + dec(c.version2);
    fi.attrs["volume_id"] = hex_bytes(c.volumeid);
    fi.attrs["data_start"] = hex(im.data_start);
    fi.attrs["blocks_per_group"] = dec(c.allocgroup);
    fi.attrs["root_levels"] = dec(c.inodes.levels);
    fi.attrs["inode_table_size"] = dec(c.inodes.size);
    fi.attrs["longfile_size"] = dec(c.longfile.size);
    fi.attrs["longfile_slots"] = dec(im.longfile_slots);
    fi.attrs["longfile_count"] = dec(im.longfile_count);
    fi.attrs["current_superblock"] = im.primary && im.cur == &*im.primary ? "primary" : "secondary";
    fi.attrs["superblock_crc"] = c.crc_ok ? "ok" : "bad";
    if (im.old) {
        fi.attrs["second_superblock_offset"] = hex(im.old->off);
        fi.attrs["second_serial"] = dec(im.old->serial);
    } else if (im.primary && im.secondary) {
        fi.attrs["second_superblock_offset"] = hex(im.secondary->off);
        fi.attrs["second_serial"] = dec(im.secondary->serial);
    } else {
        fi.attrs["second_superblock_offset"] = "none";
    }
    if (im.truncated_image) fi.attrs["truncated"] = "true";
    return fi;
}

Status Qnx6Reader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& im = *impl_;
    if (!im.opened) return Status::fail("qnx6: walk before a successful open");
    out = WalkResult{};
    for (const Diagnostic& d : im.open_diags) out.diagnostics.push_back(d);
    im.lim = &opts.limits;

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;

    im.walk_snapshot(*im.cur, /*live=*/true, w);
    if (opts.history && !w.stop) {
        if (im.old && im.old->serial != im.cur->serial) im.walk_snapshot(*im.old, false, w);
        if (!w.stop) im.walk_deleted_inodes(w);
    }

    if (w.versions_dropped != 0)
        im.diag(out, Severity::Warning, kCodeLimitVersions,
                dec(w.versions_dropped) + " history entr(ies) dropped by max_versions_per_entry (" +
                    dec(opts.limits.max_versions_per_entry) + "); the live tree is complete");
    if (w.reused_files != 0)
        im.diag(out, Severity::Warning, kCodeDeletedBlocksReused,
                dec(w.reused_files) +
                    " deleted entr(ies) had blocks the current snapshot allocated again; those "
                    "blocks were zero-filled and the entries marked truncated");
    if (w.longfile_checksum_bad != 0)
        im.diag(out, Severity::Info, kCodeLongfileChecksum,
                dec(w.longfile_checksum_bad) +
                    " long file name(s) whose directory-entry checksum does not match the name "
                    "(an MMI variant, or a stale entry); the names were used");
    im.lim = nullptr;  // `opts` does not outlive this call
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("qnx6", Qnx6Reader);

}  // namespace omnitrace::fs
