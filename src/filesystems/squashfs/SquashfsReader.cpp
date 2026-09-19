// SquashfsReader.cpp — SquashFS v4 reader. See SquashfsReader.h and
// docs/formats/squashfs.md.
//
// Format knowledge: Linux fs/squashfs/squashfs_fs.h and the squashfs-tools
// documentation (https://dr-emann.github.io/squashfs/). All integers are in
// the byte order implied by the superblock magic; every read goes through
// Span or a decoded metadata block held in a bounded LRU cache.
#include "SquashfsReader.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <list>
#include <map>
#include <vector>

#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Endian.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_squashfs() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants
// These are format constants (from squashfs_fs.h), not tunable limits.
constexpr std::uint64_t kSuperblockSize = 96;
constexpr std::uint16_t kMajor = 4;
constexpr std::size_t kMetadataSize = 8192;             // SQUASHFS_METADATA_SIZE
constexpr std::uint16_t kMetaUncompressed = 0x8000;     // SQUASHFS_COMPRESSED_BIT
constexpr std::uint32_t kBlockUncompressed = 1u << 24;  // SQUASHFS_COMPRESSED_BIT_BLOCK
constexpr std::uint32_t kBlockSizeMask = kBlockUncompressed - 1;
constexpr std::uint32_t kInvalidFrag = 0xFFFFFFFFu;           // SQUASHFS_INVALID_FRAG
constexpr std::uint32_t kInvalidXattr = 0xFFFFFFFFu;          // SQUASHFS_INVALID_XATTR
constexpr std::uint64_t kInvalidBlk = 0xFFFFFFFFFFFFFFFFull;  // SQUASHFS_INVALID_BLK
constexpr std::uint16_t kMinBlockLog = 12;                    // SQUASHFS_FILE_MIN 4 KiB
constexpr std::uint16_t kMaxBlockLog = 20;                    // SQUASHFS_FILE_MAX 1 MiB
constexpr std::size_t kInodeHeaderSize = 16;
constexpr std::size_t kDirHeaderSize = 12;
constexpr std::size_t kDirEntrySize = 8;
constexpr std::size_t kFragEntrySize = 16;
constexpr std::size_t kXattrIdSize = 16;
constexpr std::size_t kIdSize = 4;

// Superblock flags.
constexpr std::uint16_t kFlagCompressorOptions = 0x0400;

// Inode types.
enum InodeType : std::uint16_t {
    kDir = 1,
    kFile = 2,
    kSymlink = 3,
    kBlkdev = 4,
    kChrdev = 5,
    kFifo = 6,
    kSocket = 7,
    kLDir = 8,
    kLFile = 9,
    kLSymlink = 10,
    kLBlkdev = 11,
    kLChrdev = 12,
    kLFifo = 13,
    kLSocket = 14,
};

// Working-set size of the metadata block cache (blocks of <= 8 KiB). This is a
// performance knob, not an input guard: the walk is correct with any value.
constexpr std::size_t kMetaCacheBlocks = 64;

// Diagnostic codes. Tests and downstream agents key on these strings.
constexpr const char* kCodeUnsupportedCompression = "squashfs-unsupported-compression";
constexpr const char* kCodeMetadataCorrupt = "squashfs-metadata-corrupt";
constexpr const char* kCodeBlockCorrupt = "squashfs-block-corrupt";
constexpr const char* kCodeDataTruncated = "squashfs-data-truncated";
constexpr const char* kCodeDirLoop = "squashfs-dir-loop";
constexpr const char* kCodeBadInodeType = "squashfs-bad-inode-type";
constexpr const char* kCodeBadEntryName = "squashfs-bad-entry-name";
constexpr const char* kCodeBadFragment = "squashfs-bad-fragment";
constexpr const char* kCodeBadId = "squashfs-bad-id";
constexpr const char* kCodeBadXattr = "squashfs-bad-xattr";
constexpr const char* kCodeTruncatedImage = "squashfs-truncated-image";
constexpr const char* kCodeMinorVersion = "squashfs-minor-version";
constexpr const char* kCodeLimitNodes = "squashfs-limit-nodes";
constexpr const char* kCodeLimitFiles = "squashfs-limit-files";
constexpr const char* kCodeLimitFileBytes = "squashfs-limit-file-bytes";
constexpr const char* kCodeSinkError = "squashfs-sink-error";
constexpr const char* kCodeRootInvalid = "squashfs-root-invalid";

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

std::optional<compress::Codec> codec_for(std::uint16_t id) {
    switch (id) {
        case 1:
            return compress::Codec::Zlib;
        case 2:
            return compress::Codec::Lzma;
        case 3:
            return compress::Codec::Lzo1x;
        case 4:
            return compress::Codec::Xz;
        case 5:
            return compress::Codec::Lz4;
        case 6:
            return compress::Codec::Zstd;
        default:
            return std::nullopt;
    }
}

// ------------------------------------------------------------------ superblock

struct Superblock {
    Endian endian = Endian::Little;
    std::string magic;
    std::uint32_t inodes = 0, mkfs_time = 0, block_size = 0, fragments = 0;
    std::uint16_t compression = 0, block_log = 0, flags = 0, no_ids = 0, major = 0, minor = 0;
    std::uint64_t root_inode = 0, bytes_used = 0;
    std::uint64_t id_table_start = 0, xattr_id_table_start = 0, inode_table_start = 0;
    std::uint64_t directory_table_start = 0, fragment_table_start = 0, export_table_start = 0;
};

// Decoded metadata block plus the offset of the block that follows it.
struct MetaBlock {
    std::vector<std::uint8_t> data;
    std::uint64_t next = 0;
};

// Position inside the metadata stream: absolute (Span-relative) offset of the
// block and the byte offset within its decoded contents.
struct MetaCursor {
    std::uint64_t block = 0;
    std::size_t pos = 0;
};

// Parsed inode. Only the union of fields the walk needs; type-specific fields
// are zero when they do not apply. For regular files the block list is NOT
// read here: `blocks_cursor` points at it so the data path can stream sizes.
struct Inode {
    std::uint16_t type = 0;
    std::uint16_t mode = 0;
    std::uint16_t uid_idx = 0, gid_idx = 0;
    std::uint32_t mtime = 0;
    std::uint32_t inode_number = 0;
    std::uint32_t nlink = 1;
    std::uint32_t xattr_idx = kInvalidXattr;
    // file
    std::uint64_t start_block = 0;
    std::uint64_t file_size = 0;
    std::uint64_t sparse = 0;
    std::uint32_t fragment = kInvalidFrag;
    std::uint32_t block_offset = 0;
    MetaCursor blocks_cursor;
    // dir
    std::uint32_t dir_start_block = 0;
    std::uint16_t dir_block_offset = 0;
    std::uint32_t dir_size = 0;
    std::uint32_t parent_inode = 0;
    // symlink
    std::string target;
    // device
    std::uint32_t rdev = 0;
};

struct DirEntry {
    std::uint64_t inode_ref = 0;
    std::uint32_t inode_number = 0;
    std::uint16_t type = 0;
    std::string name;
};

bool is_dir_type(std::uint16_t t) {
    return t == kDir || t == kLDir;
}

EntryKind kind_for(std::uint16_t t) {
    switch (t) {
        case kDir:
        case kLDir:
            return EntryKind::Directory;
        case kFile:
        case kLFile:
            return EntryKind::Regular;
        case kSymlink:
        case kLSymlink:
            return EntryKind::Symlink;
        case kBlkdev:
        case kLBlkdev:
            return EntryKind::BlockDevice;
        case kChrdev:
        case kLChrdev:
            return EntryKind::CharDevice;
        case kFifo:
        case kLFifo:
            return EntryKind::Fifo;
        case kSocket:
        case kLSocket:
            return EntryKind::Socket;
        default:
            return EntryKind::Unknown;
    }
}

}  // namespace

// ------------------------------------------------------------------ Impl

struct SquashfsReader::Impl {
    Span span;
    Superblock sb;
    std::optional<compress::Codec> codec;
    bool opened = false;
    std::vector<Diagnostic> open_diags;               // reported at the start of every walk
    std::map<std::string, std::string> option_attrs;  // decoded compressor options

    // id table, loaded at open (at most 65535 entries)
    std::vector<std::uint32_t> ids;
    bool ids_ok = false;

    // xattr id table header
    bool has_xattrs = false;
    std::uint64_t xattr_table_start = 0;
    std::uint32_t xattr_ids = 0;
    std::uint64_t xattr_index_start = 0;

    // metadata LRU cache keyed by absolute block offset
    using LruList = std::list<std::pair<std::uint64_t, std::shared_ptr<const MetaBlock>>>;
    LruList lru;
    std::map<std::uint64_t, LruList::iterator> lru_index;

    // one-block fragment cache
    std::uint64_t frag_cache_start = kInvalidBlk;
    std::vector<std::uint8_t> frag_cache;
    bool frag_cache_ok = false;

    // scratch buffers reused across blocks
    std::vector<std::uint8_t> raw_buf, out_buf, zero_buf;

    // Limits in force for the current walk (rule 4: every guard is a Limits
    // field). Set by walk(); the defaults apply when a table is read at open.
    const Limits* lim = nullptr;
    const Limits& limits() const {
        static const Limits kDefault{};
        return lim ? *lim : kDefault;
    }

    // per-walk state
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        std::uint64_t nodes = 0;
        bool bad_id_reported = false;
        bool stop = false;  // a limit tripped: unwind
    };

    template <class T>
    T ld(const std::uint8_t* p) const {
        return load_int<T>(p, sb.endian);
    }

    void diag(WalkResult& out, Severity s, const char* code, std::string msg) const {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }

    // -------------------------------------------------------------- superblock
    Status parse_superblock();
    Status load_compressor_options();
    void load_id_table();
    void load_xattr_header();

    // -------------------------------------------------------------- metadata
    std::shared_ptr<const MetaBlock> meta_block(std::uint64_t off, std::string* why);
    bool meta_read(MetaCursor& c, std::span<std::uint8_t> out, std::string* why);
    template <class T>
    bool meta_int(MetaCursor& c, T& v, std::string* why) {
        std::uint8_t buf[sizeof(T)];
        if (!meta_read(c, std::span<std::uint8_t>(buf, sizeof(T)), why)) return false;
        v = ld<T>(buf);
        return true;
    }
    MetaCursor cursor_for_ref(std::uint64_t table_start, std::uint64_t ref) const {
        MetaCursor c;
        const std::uint64_t block = ref >> 16;
        c.block = block > std::numeric_limits<std::uint64_t>::max() - table_start
                      ? std::numeric_limits<std::uint64_t>::max()
                      : table_start + block;
        c.pos = static_cast<std::size_t>(ref & 0xFFFFu);
        return c;
    }
    // Reads the N-th 8-byte entry of an index list at `index_start` and then
    // the metadata block it points at.
    std::shared_ptr<const MetaBlock> indexed_block(std::uint64_t index_start, std::uint64_t n,
                                                   std::string* why);

    // -------------------------------------------------------------- tables
    bool lookup_id(std::uint16_t idx, std::uint32_t& out) const {
        if (!ids_ok || idx >= ids.size()) return false;
        out = ids[idx];
        return true;
    }
    bool lookup_fragment(std::uint32_t idx, std::uint64_t& start, std::uint32_t& size,
                         std::string* why);
    bool lookup_xattr_count(std::uint32_t idx, std::uint32_t& count, std::string* why);

    // -------------------------------------------------------------- inodes / dirs
    bool read_inode(std::uint64_t ref, Inode& ino, std::string* why, const char** code = nullptr);
    // `limit_hit` is set when Limits::max_nodes_per_fs stopped the listing
    // (entries holds what was read so far); other failures leave it false.
    bool read_directory(const Inode& dir, std::vector<DirEntry>& entries, std::string* why,
                        bool* limit_hit = nullptr);

    // -------------------------------------------------------------- walk
    FileMeta make_meta(const std::string& path, const Inode& ino, Walk& w);
    bool walk_dir(const Inode& root, Walk& w);
    void emit_regular(const FileMeta& meta, Inode& ino, Walk& w);
    bool stream_file(const FileMeta& meta, Inode& ino, Walk& w, bool& truncated);
    bool decode_fragment(std::uint64_t start, std::uint32_t size, std::string* why);
    bool write_zeros(Walk& w, std::uint64_t n, std::string* why);
};

// ---------------------------------------------------------------- superblock

Status SquashfsReader::Impl::parse_superblock() {
    if (span.size() < kSuperblockSize)
        return Status::fail("squashfs-bad-superblock: fewer than 96 bytes");
    const auto magic = span.bytes(0, 4);
    if (!magic) return Status::fail("squashfs-bad-superblock: unreadable magic");
    sb.magic.assign(magic->begin(), magic->end());
    // "hsqs" is the little-endian magic, "sqsh" big-endian. Vendors alter the
    // magic (DD-WRT "shsq"/"qshs"); for those pick whichever order makes the
    // major version read as 4.
    bool known = false;
    if (sb.magic == "hsqs") {
        sb.endian = Endian::Little;
        known = true;
    } else if (sb.magic == "sqsh") {
        sb.endian = Endian::Big;
        known = true;
    } else if (sb.magic == "shsq" || sb.magic == "qshs") {
        const auto le = span.at<std::uint16_t>(28, Endian::Little);
        const auto be = span.at<std::uint16_t>(28, Endian::Big);
        sb.endian = (le && *le == kMajor) ? Endian::Little
                                          : ((be && *be == kMajor) ? Endian::Big : Endian::Little);
        known = true;
    }
    if (!known) return Status::fail("squashfs-bad-superblock: magic is not a SquashFS magic");

    const Endian e = sb.endian;
    auto g16 = [&](std::uint64_t off) { return *span.at<std::uint16_t>(off, e); };
    auto g32 = [&](std::uint64_t off) { return *span.at<std::uint32_t>(off, e); };
    auto g64 = [&](std::uint64_t off) { return *span.at<std::uint64_t>(off, e); };
    sb.inodes = g32(4);
    sb.mkfs_time = g32(8);
    sb.block_size = g32(12);
    sb.fragments = g32(16);
    sb.compression = g16(20);
    sb.block_log = g16(22);
    sb.flags = g16(24);
    sb.no_ids = g16(26);
    sb.major = g16(28);
    sb.minor = g16(30);
    sb.root_inode = g64(32);
    sb.bytes_used = g64(40);
    sb.id_table_start = g64(48);
    sb.xattr_id_table_start = g64(56);
    sb.inode_table_start = g64(64);
    sb.directory_table_start = g64(72);
    sb.fragment_table_start = g64(80);
    sb.export_table_start = g64(88);

    if (sb.major != kMajor)
        return Status::fail("squashfs-unsupported-version: major " + dec(sb.major) +
                            " (only 4 is supported)");
    if (sb.block_log < kMinBlockLog || sb.block_log > kMaxBlockLog)
        return Status::fail("squashfs-bad-superblock: block_log " + dec(sb.block_log) +
                            " outside 12..20");
    if (sb.block_size != (1u << sb.block_log))
        return Status::fail("squashfs-bad-superblock: block_size " + dec(sb.block_size) +
                            " != 1 << block_log " + dec(sb.block_log));
    if (sb.bytes_used < kSuperblockSize)
        return Status::fail("squashfs-bad-superblock: bytes_used " + dec(sb.bytes_used) +
                            " smaller than the superblock");
    if (sb.minor != 0)
        open_diags.push_back({Severity::Info, kCodeMinorVersion,
                              "SquashFS 4." + dec(sb.minor) + " superblock; parsed as 4.0"});
    if (sb.bytes_used > span.size())
        open_diags.push_back({Severity::Warning, kCodeTruncatedImage,
                              "bytes_used " + dec(sb.bytes_used) + " exceeds the " +
                                  dec(span.size()) + " bytes available"});
    codec = codec_for(sb.compression);
    if (!codec)
        open_diags.push_back({Severity::Error, kCodeUnsupportedCompression,
                              "compression id " + dec(sb.compression) +
                                  " is not known; compressed blocks cannot be decoded"});
    return Status::success();
}

Status SquashfsReader::Impl::load_compressor_options() {
    if (!(sb.flags & kFlagCompressorOptions)) return Status::success();
    std::string why;
    const auto blk = meta_block(kSuperblockSize, &why);
    if (!blk) {
        open_diags.push_back(
            {Severity::Warning, kCodeMetadataCorrupt, "compressor options block: " + why});
        return Status::success();
    }
    const std::vector<std::uint8_t>& d = blk->data;
    auto u32 = [&](std::size_t off, const char* name) {
        if (off + 4 <= d.size()) option_attrs[name] = dec(ld<std::uint32_t>(d.data() + off));
    };
    auto u16 = [&](std::size_t off, const char* name) {
        if (off + 2 <= d.size()) option_attrs[name] = dec(ld<std::uint16_t>(d.data() + off));
    };
    switch (sb.compression) {
        case 1:
            u32(0, "gzip_level");
            u16(4, "gzip_window");
            u16(6, "gzip_strategies");
            break;
        case 3:
            u32(0, "lzo_algorithm");
            u32(4, "lzo_level");
            break;
        case 4:
            u32(0, "xz_dict_size");
            u32(4, "xz_filters");
            break;
        case 5:
            u32(0, "lz4_version");
            u32(4, "lz4_flags");
            break;
        case 6:
            u32(0, "zstd_level");
            break;
        default:
            option_attrs["compression_options_bytes"] = dec(d.size());
            break;
    }
    return Status::success();
}

void SquashfsReader::Impl::load_id_table() {
    ids.clear();
    ids_ok = false;
    if (sb.no_ids == 0) {
        ids_ok = true;
        return;
    }
    const std::uint64_t blocks =
        (static_cast<std::uint64_t>(sb.no_ids) * kIdSize + kMetadataSize - 1) / kMetadataSize;
    ids.reserve(sb.no_ids);
    for (std::uint64_t b = 0; b < blocks; ++b) {
        std::string why;
        const auto blk = indexed_block(sb.id_table_start, b, &why);
        if (!blk) {
            open_diags.push_back(
                {Severity::Warning, kCodeMetadataCorrupt, "id table block " + dec(b) + ": " + why});
            ids.clear();
            return;
        }
        const std::size_t want =
            std::min<std::size_t>(sb.no_ids - ids.size(), kMetadataSize / kIdSize);
        if (blk->data.size() < want * kIdSize) {
            open_diags.push_back({Severity::Warning, kCodeMetadataCorrupt,
                                  "id table block " + dec(b) + " holds " + dec(blk->data.size()) +
                                      " bytes, expected " + dec(want * kIdSize)});
            ids.clear();
            return;
        }
        for (std::size_t i = 0; i < want; ++i)
            ids.push_back(ld<std::uint32_t>(blk->data.data() + i * kIdSize));
    }
    ids_ok = true;
}

void SquashfsReader::Impl::load_xattr_header() {
    has_xattrs = false;
    if (sb.xattr_id_table_start == kInvalidBlk) return;
    const auto start = span.at<std::uint64_t>(sb.xattr_id_table_start, sb.endian);
    const auto count = span.at<std::uint32_t>(sb.xattr_id_table_start + 8, sb.endian);
    if (!start || !count) {
        open_diags.push_back(
            {Severity::Warning, kCodeMetadataCorrupt,
             "xattr id table header at " + hex(sb.xattr_id_table_start) + " is outside the image"});
        return;
    }
    xattr_table_start = *start;
    xattr_ids = *count;
    xattr_index_start = sb.xattr_id_table_start + 16;
    has_xattrs = true;
}

// ---------------------------------------------------------------- metadata

std::shared_ptr<const MetaBlock> SquashfsReader::Impl::meta_block(std::uint64_t off,
                                                                  std::string* why) {
    const auto hit = lru_index.find(off);
    if (hit != lru_index.end()) {
        lru.splice(lru.begin(), lru, hit->second);
        return hit->second->second;
    }
    const auto hdr = span.at<std::uint16_t>(off, sb.endian);
    if (!hdr) {
        if (why) *why = "metadata block header at " + hex(off) + " is outside the image";
        return nullptr;
    }
    const std::size_t on_disk = *hdr & 0x7FFFu;
    const bool compressed = (*hdr & kMetaUncompressed) == 0;
    if (on_disk == 0 || on_disk > kMetadataSize) {
        if (why) *why = "metadata block at " + hex(off) + " has on-disk size " + dec(on_disk);
        return nullptr;
    }
    auto blk = std::make_shared<MetaBlock>();
    blk->next = off + 2 + on_disk;
    const auto view = span.view(off + 2, on_disk);
    std::span<const std::uint8_t> in;
    if (view) {
        in = *view;
    } else {
        auto copy = span.bytes(off + 2, on_disk);
        if (!copy) {
            if (why)
                *why = "metadata block at " + hex(off) + " (" + dec(on_disk) +
                       " bytes) runs past the image";
            return nullptr;
        }
        raw_buf = std::move(*copy);
        in = raw_buf;
    }
    if (compressed) {
        if (!codec) {
            if (why)
                *why = "metadata block at " + hex(off) +
                       " is compressed with unsupported compression id " + dec(sb.compression);
            return nullptr;
        }
        const Status s = compress::decompress(*codec, in, blk->data, kMetadataSize);
        if (!s) {
            if (why)
                *why = "metadata block at " + hex(off) + " does not decompress (" + s.error + ")";
            return nullptr;
        }
    } else {
        blk->data.assign(in.begin(), in.end());
    }
    lru.emplace_front(off, blk);
    lru_index[off] = lru.begin();
    while (lru.size() > kMetaCacheBlocks) {
        lru_index.erase(lru.back().first);
        lru.pop_back();
    }
    return blk;
}

bool SquashfsReader::Impl::meta_read(MetaCursor& c, std::span<std::uint8_t> out, std::string* why) {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto blk = meta_block(c.block, why);
        if (!blk) return false;
        if (c.pos > blk->data.size()) {
            if (why)
                *why = "offset " + dec(c.pos) + " inside metadata block at " + hex(c.block) +
                       " exceeds its " + dec(blk->data.size()) + " bytes";
            return false;
        }
        const std::size_t avail = blk->data.size() - c.pos;
        if (avail == 0) {
            // Exhausted this block: continue in the next one. An empty block
            // would loop forever; meta_block rejects on_disk == 0 so `next`
            // always advances.
            c.block = blk->next;
            c.pos = 0;
            continue;
        }
        const std::size_t n = std::min(avail, out.size() - done);
        std::memcpy(out.data() + done, blk->data.data() + c.pos, n);
        c.pos += n;
        done += n;
    }
    return true;
}

std::shared_ptr<const MetaBlock> SquashfsReader::Impl::indexed_block(std::uint64_t index_start,
                                                                     std::uint64_t n,
                                                                     std::string* why) {
    if (n > (std::numeric_limits<std::uint64_t>::max() - index_start) / 8) {
        if (why) *why = "index entry " + dec(n) + " overflows";
        return nullptr;
    }
    const auto ptr = span.at<std::uint64_t>(index_start + n * 8, sb.endian);
    if (!ptr) {
        if (why)
            *why = "index entry " + dec(n) + " at " + hex(index_start + n * 8) +
                   " is outside the image";
        return nullptr;
    }
    return meta_block(*ptr, why);
}

// ---------------------------------------------------------------- tables

bool SquashfsReader::Impl::lookup_fragment(std::uint32_t idx, std::uint64_t& start,
                                           std::uint32_t& size, std::string* why) {
    if (idx >= sb.fragments) {
        if (why) *why = "fragment index " + dec(idx) + " >= fragment count " + dec(sb.fragments);
        return false;
    }
    constexpr std::size_t per_block = kMetadataSize / kFragEntrySize;
    const auto blk = indexed_block(sb.fragment_table_start, idx / per_block, why);
    if (!blk) return false;
    const std::size_t off = (idx % per_block) * kFragEntrySize;
    if (off + kFragEntrySize > blk->data.size()) {
        if (why) *why = "fragment entry " + dec(idx) + " lies past the end of its metadata block";
        return false;
    }
    start = ld<std::uint64_t>(blk->data.data() + off);
    size = ld<std::uint32_t>(blk->data.data() + off + 8);
    return true;
}

bool SquashfsReader::Impl::lookup_xattr_count(std::uint32_t idx, std::uint32_t& count,
                                              std::string* why) {
    if (!has_xattrs) {
        if (why)
            *why = "inode references xattr id " + dec(idx) + " but the image has no xattr table";
        return false;
    }
    if (idx >= xattr_ids) {
        if (why) *why = "xattr id " + dec(idx) + " >= xattr id count " + dec(xattr_ids);
        return false;
    }
    constexpr std::size_t per_block = kMetadataSize / kXattrIdSize;
    const auto blk = indexed_block(xattr_index_start, idx / per_block, why);
    if (!blk) return false;
    const std::size_t off = (idx % per_block) * kXattrIdSize;
    if (off + kXattrIdSize > blk->data.size()) {
        if (why) *why = "xattr id entry " + dec(idx) + " lies past the end of its metadata block";
        return false;
    }
    count = ld<std::uint32_t>(blk->data.data() + off + 8);
    return true;
}

// ---------------------------------------------------------------- inodes

bool SquashfsReader::Impl::read_inode(std::uint64_t ref, Inode& ino, std::string* why,
                                      const char** code) {
    ino = Inode{};
    if (code) *code = kCodeMetadataCorrupt;
    MetaCursor c = cursor_for_ref(sb.inode_table_start, ref);
    std::uint8_t h[kInodeHeaderSize];
    if (!meta_read(c, h, why)) return false;
    ino.type = ld<std::uint16_t>(h + 0);
    ino.mode = ld<std::uint16_t>(h + 2);
    ino.uid_idx = ld<std::uint16_t>(h + 4);
    ino.gid_idx = ld<std::uint16_t>(h + 6);
    ino.mtime = ld<std::uint32_t>(h + 8);
    ino.inode_number = ld<std::uint32_t>(h + 12);

    std::uint8_t b[40];
    auto u32 = [&](std::size_t off) { return ld<std::uint32_t>(b + off); };
    auto u16 = [&](std::size_t off) { return ld<std::uint16_t>(b + off); };
    auto u64 = [&](std::size_t off) { return ld<std::uint64_t>(b + off); };
    auto need = [&](std::size_t n) { return meta_read(c, std::span<std::uint8_t>(b, n), why); };

    switch (ino.type) {
        case kDir:  // u32 start_block, u32 nlink, u16 file_size, u16 offset, u32 parent
            if (!need(16)) return false;
            ino.dir_start_block = u32(0);
            ino.nlink = u32(4);
            ino.dir_size = u16(8);
            ino.dir_block_offset = u16(10);
            ino.parent_inode = u32(12);
            return true;
        case kLDir:  // u32 nlink, u32 file_size, u32 start_block, u32 parent, u16 i_count, u16
                     // offset, u32 xattr
            if (!need(24)) return false;
            ino.nlink = u32(0);
            ino.dir_size = u32(4);
            ino.dir_start_block = u32(8);
            ino.parent_inode = u32(12);
            ino.dir_block_offset = u16(18);
            ino.xattr_idx = u32(20);
            // index entries follow; nothing after them is needed
            return true;
        case kFile:  // u32 start_block, u32 fragment, u32 offset, u32 file_size, then u32
                     // block_sizes[]
            if (!need(16)) return false;
            ino.start_block = u32(0);
            ino.fragment = u32(4);
            ino.block_offset = u32(8);
            ino.file_size = u32(12);
            ino.blocks_cursor = c;
            return true;
        case kLFile:  // u64 start_block, u64 file_size, u64 sparse, u32 nlink, u32 fragment, u32
                      // offset, u32 xattr, block_sizes[]
            if (!need(40)) return false;
            ino.start_block = u64(0);
            ino.file_size = u64(8);
            ino.sparse = u64(16);
            ino.nlink = u32(24);
            ino.fragment = u32(28);
            ino.block_offset = u32(32);
            ino.xattr_idx = u32(36);
            ino.blocks_cursor = c;
            return true;
        case kSymlink:
        case kLSymlink: {  // u32 nlink, u32 target_size, char target[], (u32 xattr)
            if (!need(8)) return false;
            ino.nlink = u32(0);
            const std::uint32_t tsize = u32(4);
            // target_size is attacker-controlled (up to 4 GiB): never allocate it
            // up front. Cap it with the per-entry byte limit and read it through
            // the metadata stream in bounded pieces, so memory grows only with
            // bytes that really exist.
            if (tsize > limits().max_file_bytes) {
                if (code) *code = kCodeLimitFileBytes;
                if (why)
                    *why = "symlink target of " + dec(tsize) + " bytes exceeds max_file_bytes (" +
                           dec(limits().max_file_bytes) + ")";
                return false;
            }
            ino.target.clear();
            std::uint8_t piece[512];
            for (std::uint32_t left = tsize; left > 0;) {
                const std::size_t n = std::min<std::size_t>(left, sizeof piece);
                if (!meta_read(c, std::span<std::uint8_t>(piece, n), why)) return false;
                ino.target.append(reinterpret_cast<const char*>(piece), n);
                left -= static_cast<std::uint32_t>(n);
            }
            if (ino.type == kLSymlink) {
                if (!need(4)) return false;
                ino.xattr_idx = u32(0);
            }
            return true;
        }
        case kBlkdev:
        case kChrdev:  // u32 nlink, u32 rdev
            if (!need(8)) return false;
            ino.nlink = u32(0);
            ino.rdev = u32(4);
            return true;
        case kLBlkdev:
        case kLChrdev:  // u32 nlink, u32 rdev, u32 xattr
            if (!need(12)) return false;
            ino.nlink = u32(0);
            ino.rdev = u32(4);
            ino.xattr_idx = u32(8);
            return true;
        case kFifo:
        case kSocket:  // u32 nlink
            if (!need(4)) return false;
            ino.nlink = u32(0);
            return true;
        case kLFifo:
        case kLSocket:  // u32 nlink, u32 xattr
            if (!need(8)) return false;
            ino.nlink = u32(0);
            ino.xattr_idx = u32(4);
            return true;
        default:
            if (code) *code = kCodeBadInodeType;
            if (why)
                *why = "inode type " + dec(ino.type) + " at reference " + hex(ref) +
                       " is not a SquashFS inode type";
            return false;
    }
}

bool SquashfsReader::Impl::read_directory(const Inode& dir, std::vector<DirEntry>& entries,
                                          std::string* why, bool* limit_hit) {
    entries.clear();
    if (limit_hit) *limit_hit = false;
    // The kernel treats file_size as (bytes on disk + 3); a size of 3 or less
    // is an empty directory.
    if (dir.dir_size <= 3) return true;
    std::uint64_t remaining = dir.dir_size - 3;
    MetaCursor c = cursor_for_ref(
        sb.directory_table_start,
        (static_cast<std::uint64_t>(dir.dir_start_block) << 16) | dir.dir_block_offset);
    while (remaining > 0) {
        if (remaining < kDirHeaderSize) {
            if (why)
                *why = dec(remaining) +
                       " trailing bytes in a directory listing are too short for a header";
            return false;
        }
        std::uint8_t h[kDirHeaderSize];
        if (!meta_read(c, h, why)) return false;
        remaining -= kDirHeaderSize;
        const std::uint32_t count = ld<std::uint32_t>(h + 0) + 1;  // stored as count - 1
        const std::uint32_t start = ld<std::uint32_t>(h + 4);
        const std::uint32_t base_inode = ld<std::uint32_t>(h + 8);
        for (std::uint32_t i = 0; i < count; ++i) {
            // A listing is bounded only by dir_size (up to 4 GiB of metadata
            // stream); cap the entries held in memory by the node limit.
            if (entries.size() >= limits().max_nodes_per_fs) {
                if (limit_hit) *limit_hit = true;
                if (why)
                    *why = "listing has more than max_nodes_per_fs (" +
                           dec(limits().max_nodes_per_fs) + ") entries";
                return false;
            }
            if (remaining < kDirEntrySize) {
                if (why)
                    *why = "directory entry " + dec(i) + " of " + dec(count) +
                           " runs past the listing";
                return false;
            }
            std::uint8_t e[kDirEntrySize];
            if (!meta_read(c, e, why)) return false;
            remaining -= kDirEntrySize;
            DirEntry d;
            const std::uint16_t offset = ld<std::uint16_t>(e + 0);
            const std::int16_t inode_delta = ld<std::int16_t>(e + 2);
            d.type = ld<std::uint16_t>(e + 4);
            const std::size_t name_len = static_cast<std::size_t>(ld<std::uint16_t>(e + 6)) + 1;
            d.inode_ref = (static_cast<std::uint64_t>(start) << 16) | offset;
            d.inode_number =
                static_cast<std::uint32_t>(static_cast<std::int64_t>(base_inode) + inode_delta);
            if (remaining < name_len) {
                if (why)
                    *why =
                        "directory entry name (" + dec(name_len) + " bytes) runs past the listing";
                return false;
            }
            std::vector<std::uint8_t> name(name_len);
            if (!meta_read(c, name, why)) return false;
            remaining -= name_len;
            d.name.assign(name.begin(), name.end());
            entries.push_back(std::move(d));
        }
    }
    return true;
}

// ---------------------------------------------------------------- walk

FileMeta SquashfsReader::Impl::make_meta(const std::string& path, const Inode& ino, Walk& w) {
    FileMeta m;
    m.path = path;
    m.kind = kind_for(ino.type);
    m.mode = ino.mode;
    m.mtime = static_cast<std::int64_t>(ino.mtime);
    m.inode = ino.inode_number;
    m.nlink = ino.nlink;
    std::uint32_t uid = 0, gid = 0;
    const bool uid_ok = lookup_id(ino.uid_idx, uid);
    const bool gid_ok = lookup_id(ino.gid_idx, gid);
    m.uid = uid;
    m.gid = gid;
    if ((!uid_ok || !gid_ok) && !w.bad_id_reported) {
        w.bad_id_reported = true;
        diag(*w.out, Severity::Warning, kCodeBadId,
             "'" + path + "' references id index " + dec(uid_ok ? ino.gid_idx : ino.uid_idx) +
                 " outside the id table (" + dec(ids.size()) +
                 " entries); uid/gid reported as 0 (reported once)");
    }
    switch (m.kind) {
        case EntryKind::Regular:
            m.size = ino.file_size;
            break;
        case EntryKind::Symlink:
            m.link_target = ino.target;
            m.size = ino.target.size();
            break;
        case EntryKind::CharDevice:
        case EntryKind::BlockDevice:
            // Linux new_encode_dev(): major in bits 8..19, minor in bits 0..7 and 20..31.
            m.rdev_major = (ino.rdev >> 8) & 0xFFFu;
            m.rdev_minor = (ino.rdev & 0xFFu) | ((ino.rdev >> 12) & 0xFFF00u);
            break;
        default:
            break;
    }
    if (ino.type == kLFile && ino.sparse != 0) m.extra["sparse"] = dec(ino.sparse);
    if (ino.xattr_idx != kInvalidXattr) {
        std::uint32_t count = 0;
        std::string why;
        if (lookup_xattr_count(ino.xattr_idx, count, &why)) {
            m.extra["xattrs"] = dec(count);
        } else {
            diag(*w.out, Severity::Warning, kCodeBadXattr, "'" + path + "': " + why);
        }
    }
    return m;
}

bool SquashfsReader::Impl::write_zeros(Walk& w, std::uint64_t n, std::string* why) {
    if (zero_buf.size() < sb.block_size)
        zero_buf.assign(sb.block_size, static_cast<std::uint8_t>(0));
    while (n > 0) {
        const std::size_t step =
            static_cast<std::size_t>(std::min<std::uint64_t>(n, sb.block_size));
        const Status s = w.sink->write(std::span<const std::uint8_t>(zero_buf.data(), step));
        if (!s) {
            if (why) *why = s.error;
            return false;
        }
        n -= step;
    }
    return true;
}

bool SquashfsReader::Impl::decode_fragment(std::uint64_t start, std::uint32_t size,
                                           std::string* why) {
    if (frag_cache_ok && frag_cache_start == start) return true;
    frag_cache_ok = false;
    frag_cache_start = start;
    const std::size_t on_disk = size & kBlockSizeMask;
    const bool compressed = (size & kBlockUncompressed) == 0;
    if (on_disk == 0 || on_disk > sb.block_size) {
        if (why) *why = "fragment block at " + hex(start) + " has on-disk size " + dec(on_disk);
        return false;
    }
    const auto view = span.view(start, on_disk);
    std::span<const std::uint8_t> in;
    if (view) {
        in = *view;
    } else {
        auto copy = span.bytes(start, on_disk);
        if (!copy) {
            if (why)
                *why = "fragment block at " + hex(start) + " (" + dec(on_disk) +
                       " bytes) runs past the image";
            return false;
        }
        raw_buf = std::move(*copy);
        in = raw_buf;
    }
    if (compressed) {
        if (!codec) {
            if (why)
                *why = "fragment block at " + hex(start) +
                       " is compressed with unsupported compression id " + dec(sb.compression);
            return false;
        }
        const Status s = compress::decompress(*codec, in, frag_cache, sb.block_size);
        if (!s) {
            if (why)
                *why = "fragment block at " + hex(start) + " does not decompress (" + s.error + ")";
            return false;
        }
    } else {
        frag_cache.assign(in.begin(), in.end());
    }
    frag_cache_ok = true;
    return true;
}

// Streams one regular file's data to the sink. Returns false only when the
// sink refused a write (the caller then ends the entry and records it);
// decode problems are reported as diagnostics and the file continues with
// zeros so that offsets of everything after the bad block stay right.
bool SquashfsReader::Impl::stream_file(const FileMeta& meta, Inode& ino, Walk& w, bool& truncated) {
    const std::uint64_t bs = sb.block_size;
    const std::uint64_t size = ino.file_size;
    const bool has_fragment = ino.fragment != kInvalidFrag;
    // Blocks covered by the block list: whole blocks, plus the partial tail
    // when it is not packed into a fragment.
    const std::uint64_t nblocks = has_fragment ? size / bs : (size + bs - 1) / bs;
    std::uint64_t pos = ino.start_block;  // Span-relative offset of the next data block
    std::uint64_t written = 0;
    std::string why;
    bool block_list_lost = false;

    for (std::uint64_t i = 0; i < nblocks; ++i) {
        const std::uint64_t expected = std::min<std::uint64_t>(bs, size - i * bs);
        std::uint32_t bsize = 0;
        if (block_list_lost || !meta_int(ino.blocks_cursor, bsize, &why)) {
            // The block list itself is unreadable: nothing after this point can
            // be located. Stop the data here rather than pad to a size the
            // image may have invented.
            if (!block_list_lost)
                diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                     "'" + meta.path + "': block list unreadable after block " + dec(i) + ": " +
                         why);
            block_list_lost = true;
            truncated = true;
            return true;
        }
        const std::uint32_t on_disk = bsize & kBlockSizeMask;
        const bool compressed = (bsize & kBlockUncompressed) == 0;
        if (on_disk == 0) {
            // Sparse block: `expected` bytes of zeros, nothing on disk.
            if (!write_zeros(w, expected, &why)) return false;
            written += expected;
            continue;
        }
        if (on_disk > bs) {
            // The block list is not trustworthy past this point: the offsets of
            // every later block derive from this size. Stop the data here.
            diag(*w.out, Severity::Warning, kCodeBlockCorrupt,
                 "'" + meta.path + "': data block " + dec(i) + " claims " + dec(on_disk) +
                     " bytes on disk, more than block_size " + dec(bs) + "; " +
                     dec(size - written) + " bytes not recovered");
            truncated = true;
            return true;
        }
        if (on_disk > span.size() || pos > span.size() - on_disk) {
            // Past the end of the image: everything after this is missing too.
            diag(*w.out, Severity::Warning, kCodeDataTruncated,
                 "'" + meta.path + "': data block " + dec(i) + " at " + hex(pos) + " (" +
                     dec(on_disk) + " bytes) lies past the end of the image; " +
                     dec(size - written) + " bytes missing");
            truncated = true;
            return true;
        }
        bool ok = true;
        std::span<const std::uint8_t> data;
        {
            const auto view = span.view(pos, on_disk);
            if (view) {
                data = *view;
            } else {
                auto copy = span.bytes(pos, on_disk);
                if (copy) {
                    raw_buf = std::move(*copy);
                    data = raw_buf;
                } else {
                    ok = false;
                    why = "source refused to read " + dec(on_disk) + " bytes at " + hex(pos);
                }
            }
        }
        if (ok) {
            if (compressed) {
                if (!codec) {
                    ok = false;
                    why = "unsupported compression id " + dec(sb.compression);
                } else {
                    const Status s = compress::decompress_exact(*codec, data, out_buf,
                                                                static_cast<std::size_t>(expected));
                    if (s)
                        data = out_buf;
                    else {
                        ok = false;
                        why = s.error;
                    }
                }
            } else if (data.size() != expected) {
                ok = false;
                why =
                    "stored block holds " + dec(data.size()) + " bytes, expected " + dec(expected);
            }
        }
        if (ok) {
            const Status s = w.sink->write(data);
            if (!s) {
                why = s.error;
                return false;
            }
        } else {
            diag(*w.out, Severity::Warning, kCodeBlockCorrupt,
                 "'" + meta.path + "': data block " + dec(i) + " at " + hex(pos) + ": " + why +
                     "; zero-filled");
            truncated = true;
            if (!write_zeros(w, expected, &why)) return false;
        }
        written += expected;
        pos += on_disk;  // pos + on_disk <= span.size() was checked above
    }

    if (has_fragment && written < size) {
        const std::uint64_t tail = size - written;
        std::uint64_t fstart = 0;
        std::uint32_t fsize = 0;
        bool ok = lookup_fragment(ino.fragment, fstart, fsize, &why);
        const char* code = kCodeBadFragment;
        if (ok) {
            ok = decode_fragment(fstart, fsize, &why);
            code = kCodeBlockCorrupt;
        }
        if (ok &&
            (ino.block_offset > frag_cache.size() || tail > frag_cache.size() - ino.block_offset)) {
            ok = false;
            why = "tail of " + dec(tail) + " bytes at offset " + dec(ino.block_offset) +
                  " exceeds the fragment block (" + dec(frag_cache.size()) + " bytes)";
        }
        if (ok) {
            const Status s = w.sink->write(std::span<const std::uint8_t>(
                frag_cache.data() + ino.block_offset, static_cast<std::size_t>(tail)));
            if (!s) return false;
        } else {
            diag(*w.out, Severity::Warning, code,
                 "'" + meta.path + "': fragment " + dec(ino.fragment) + ": " + why +
                     "; zero-filled");
            truncated = true;
            if (!write_zeros(w, tail, &why)) return false;
        }
    }
    return true;
}

void SquashfsReader::Impl::emit_regular(const FileMeta& meta, Inode& ino, Walk& w) {
    Status s = w.sink->begin_file(meta);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return;
    }
    bool truncated = false;
    bool sink_ok = true;
    if (w.opts->extract_data) sink_ok = stream_file(meta, ino, w, truncated);
    EntryResult r;
    s = w.sink->end_file(r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        // The sink may still have produced a (truncated) result; keep it if it
        // names the entry.
        if (r.meta.path.empty()) return;
    }
    if (!sink_ok) {
        // A refused write mid-file (a Limits guard in the sink). The sink has
        // already marked the entry truncated and attached its own diagnostic.
        r.truncated = true;
    }
    if (truncated) r.truncated = true;
    w.out->bytes += r.digests.bytes;
    w.out->entries++;
    w.out->files++;
    w.out->entries_out.push_back(std::move(r));
}

bool SquashfsReader::Impl::walk_dir(const Inode& root, Walk& w) {
    bool root_ok = true;
    struct Frame {
        std::string path;  // "" for the root
        std::uint64_t inode_ref;
        std::vector<DirEntry> entries;
        std::size_t next = 0;
    };
    const Limits& walk_lim = w.opts->limits;
    std::vector<Frame> stack;
    std::string why;

    {
        Frame f;
        f.inode_ref = sb.root_inode;
        bool limit_hit = false;
        if (!read_directory(root, f.entries, &why, &limit_hit)) {
            if (limit_hit) {
                diag(*w.out, Severity::Warning, kCodeLimitNodes,
                     "root directory listing: " + why + "; listing truncated");
                w.out->truncated = true;
            } else {
                root_ok = false;
                diag(*w.out, Severity::Error, kCodeMetadataCorrupt,
                     "root directory listing: " + why +
                         (f.entries.empty() ? "" : " (partial listing kept)"));
            }
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

        if (entry.name.empty() || entry.name == "." || entry.name == ".." ||
            entry.name.find('/') != std::string::npos ||
            entry.name.find('\0') != std::string::npos) {
            diag(*w.out, Severity::Warning, kCodeBadEntryName,
                 "directory '" + parent_path + "' has an entry named '" + entry.name +
                     "' (skipped)");
            continue;
        }
        const std::string path = parent_path.empty() ? entry.name : parent_path + "/" + entry.name;

        if (w.nodes >= walk_lim.max_nodes_per_fs) {
            diag(*w.out, Severity::Warning, kCodeLimitNodes,
                 "max_nodes_per_fs (" + dec(walk_lim.max_nodes_per_fs) + ") reached at '" + path +
                     "'; walk stopped");
            w.out->truncated = true;
            w.stop = true;
            break;
        }
        if (w.out->entries >= walk_lim.max_files) {
            diag(*w.out, Severity::Warning, kCodeLimitFiles,
                 "max_files (" + dec(walk_lim.max_files) + ") reached at '" + path +
                     "'; walk stopped");
            w.out->truncated = true;
            w.stop = true;
            break;
        }
        ++w.nodes;

        Inode ino;
        const char* code = kCodeMetadataCorrupt;
        if (!read_inode(entry.inode_ref, ino, &why, &code)) {
            diag(*w.out, Severity::Warning, code, "'" + path + "': " + why + " (skipped)");
            continue;
        }

        FileMeta meta = make_meta(path, ino, w);
        if (meta.kind == EntryKind::Regular) {
            emit_regular(meta, ino, w);
            continue;
        }

        if (meta.kind == EntryKind::Directory) {
            // A directory whose inode is one of its own ancestors is a loop.
            bool loop = false;
            for (const Frame& f : stack) {
                if (f.inode_ref == entry.inode_ref) {
                    loop = true;
                    break;
                }
            }
            if (loop) {
                diag(*w.out, Severity::Warning, kCodeDirLoop,
                     "'" + path + "' refers to an ancestor directory (inode reference " +
                         hex(entry.inode_ref) + "); not descended");
                continue;
            }
        }

        EntryResult r;
        const Status s = w.sink->entry(meta, r);
        if (!s) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
            if (meta.kind == EntryKind::Directory) continue;  // cannot place children either
        } else {
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
            w.out->entries_out.push_back(std::move(r));
        }

        if (meta.kind == EntryKind::Directory) {
            Frame f;
            f.path = path;
            f.inode_ref = entry.inode_ref;
            bool limit_hit = false;
            if (!read_directory(ino, f.entries, &why, &limit_hit)) {
                if (limit_hit) {
                    diag(*w.out, Severity::Warning, kCodeLimitNodes,
                         "'" + path + "': " + why + "; listing truncated");
                    w.out->truncated = true;
                } else {
                    diag(*w.out, Severity::Warning, kCodeMetadataCorrupt,
                         "'" + path + "': " + why + "; listing " +
                             (f.entries.empty() ? "skipped" : "partial"));
                }
            }
            stack.push_back(std::move(f));
        }
    }
    return root_ok || w.out->entries > 0;
}

// ---------------------------------------------------------------- public API

SquashfsReader::SquashfsReader() : impl_(std::make_unique<Impl>()) {}
SquashfsReader::~SquashfsReader() = default;

std::string SquashfsReader::format() const {
    return "squashfs";
}

Status SquashfsReader::open(const Span& span) {
    Impl& im = *impl_;
    im = Impl{};
    im.span = span;
    if (Status s = im.parse_superblock(); !s) return s;
    im.load_compressor_options();
    im.load_id_table();
    im.load_xattr_header();
    im.opened = true;
    return Status::success();
}

FilesystemInfo SquashfsReader::info() const {
    const Impl& im = *impl_;
    FilesystemInfo fi;
    fi.format = "squashfs";
    if (!im.opened) return fi;
    const Superblock& sb = im.sb;
    fi.size = sb.bytes_used;
    fi.block_size = sb.block_size;
    fi.compression = compression_name(sb.compression);
    fi.endian = sb.endian;
    fi.attrs["version"] = dec(sb.major) + "." + dec(sb.minor);
    fi.attrs["magic"] = sb.magic;
    fi.attrs["inodes"] = dec(sb.inodes);
    fi.attrs["fragments"] = dec(sb.fragments);
    fi.attrs["flags"] = hex(sb.flags);
    fi.attrs["compression_id"] = dec(sb.compression);
    fi.attrs["id_count"] = dec(sb.no_ids);
    fi.attrs["mkfs_time"] = dec(sb.mkfs_time);
    fi.attrs["root_inode"] = hex(sb.root_inode);
    fi.attrs["exportable"] = sb.export_table_start != kInvalidBlk ? "true" : "false";
    fi.attrs["xattr_ids"] = im.has_xattrs ? dec(im.xattr_ids) : "0";
    for (const auto& [k, v] : im.option_attrs) fi.attrs[k] = v;
    return fi;
}

Status SquashfsReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& im = *impl_;
    if (!im.opened) return Status::fail("squashfs: walk before a successful open");
    out = WalkResult{};
    for (const Diagnostic& d : im.open_diags) out.diagnostics.push_back(d);
    im.lim = &opts.limits;

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;

    Inode root;
    std::string why;
    if (!im.read_inode(im.sb.root_inode, root, &why)) {
        im.diag(out, Severity::Error, kCodeMetadataCorrupt,
                "root inode " + hex(im.sb.root_inode) + ": " + why);
        return Status::fail("squashfs-metadata-corrupt: root inode: " + why);
    }
    if (!is_dir_type(root.type)) {
        im.diag(out, Severity::Error, kCodeRootInvalid,
                "root inode has type " + dec(root.type) + ", not a directory");
        return Status::fail("squashfs-root-invalid: root inode is not a directory");
    }
    const bool ok = im.walk_dir(root, w);
    im.lim = nullptr;  // `opts` does not outlive this call
    if (!ok) return Status::fail("squashfs-metadata-corrupt: root directory listing unreadable");
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("squashfs", SquashfsReader);

}  // namespace omnitrace::fs
