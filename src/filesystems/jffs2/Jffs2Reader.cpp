// Jffs2Reader.cpp — JFFS2 reader with version history. See Jffs2Reader.h and
// docs/formats/jffs2.md.
//
// Format knowledge: Linux include/uapi/linux/jffs2.h, fs/jffs2/{scan.c,
// readinode.c, dir.c, write.c, compr_*.c} and mtd-utils mkfs.jffs2, read for
// understanding; the OpenWrt compr_lzma.c patch for compression id 8. Every
// byte of evidence is read through Span; every cap is a Limits field.
//
// Pipeline:
//   open()  scan every node (header CRC with the obsolete-bit rule, node and
//           data CRCs, per-type sanity), keep compact records, build indexes
//   walk()  live tree: newest dirent per (pino, name) wins, ino 0 deletes;
//           per inode the newest node gives metadata and the data fragments
//           applied in version order give the content (a coverage plan is
//           computed first so each contributing node is decoded once, in file
//           offset order, one node at a time)
//           history: every earlier content state of every inode, every inode
//           without a live name, every explicit unlink record
//   Version numbers are path-scoped (docs/formats/jffs2.md "Version
//   numbers"): a dry traversal of the live tree first resolves every path,
//   then every state of every inode that ever held a path is numbered in one
//   sequence so (path, version) is unique and DiskSink never collides.
#include "Jffs2Reader.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <iterator>
#include <map>
#include <numeric>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Endian.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_jffs2() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants
// Format constants from include/uapi/linux/jffs2.h; not tunable limits.
constexpr std::uint16_t kMagic = 0x1985;
constexpr std::uint16_t kAccurate = 0x2000;  // JFFS2_NODE_ACCURATE
constexpr std::uint16_t kTypeDirent = 0xE001;
constexpr std::uint16_t kTypeInode = 0xE002;
constexpr std::uint16_t kTypeCleanmarker = 0x2003;
constexpr std::uint16_t kTypePadding = 0x2004;
constexpr std::uint16_t kTypeSummary = 0x2006;
constexpr std::uint16_t kTypeXattr = 0xE008;
constexpr std::uint16_t kTypeXref = 0xE009;

constexpr std::uint64_t kHdrSize = 12;     // struct jffs2_unknown_node
constexpr std::uint64_t kInodeSize = 68;   // struct jffs2_raw_inode
constexpr std::uint64_t kDirentSize = 40;  // struct jffs2_raw_dirent
constexpr std::uint64_t kXattrSize = 32;   // struct jffs2_raw_xattr
constexpr std::uint64_t kXrefSize = 28;    // struct jffs2_raw_xref
constexpr std::uint64_t kSummarySize = 32;
constexpr std::uint32_t kXrefDeleteMarker = 0x80000000u;  // XREF_DELETE_MARKER

constexpr std::uint8_t kComprNone = 0;
constexpr std::uint8_t kComprZero = 1;
constexpr std::uint8_t kComprRtime = 2;
constexpr std::uint8_t kComprRubinMips = 3;
constexpr std::uint8_t kComprCopy = 4;
constexpr std::uint8_t kComprDynRubin = 5;
constexpr std::uint8_t kComprZlib = 6;
constexpr std::uint8_t kComprLzo = 7;
constexpr std::uint8_t kComprLzma = 8;  // OpenWrt patch

// Dirent `type` (DT_* values).
constexpr std::uint8_t kDtFifo = 1, kDtChr = 2, kDtDir = 4, kDtBlk = 6, kDtReg = 8, kDtLnk = 10,
                       kDtSock = 12;

constexpr std::uint32_t kIfMt = 0170000, kIfSock = 0140000, kIfLnk = 0120000, kIfReg = 0100000,
                        kIfBlk = 0060000, kIfDir = 0040000, kIfChr = 0020000, kIfFifo = 0010000;

constexpr std::uint32_t kRootIno = 1;

// OpenWrt's compr_lzma.c encodes with lc=0, lp=0, pb=0 and an 8 KiB
// dictionary and stores the raw LZMA1 stream without a header. The reader
// synthesizes the 13-byte LZMA-alone header so core/Compression.h can decode
// it. A larger dictionary would decode too; this is the value the encoder
// used.
constexpr std::uint32_t kLzmaDictSize = 8192;

// Scan and zero-fill buffer. A performance knob, not an input guard: the walk
// is correct with any value.
constexpr std::size_t kChunk = 64 * 1024;

// Diagnostic codes. Tests and downstream agents key on these strings.
constexpr const char* kCodeNodeCrcMismatch = "jffs2-node-crc-mismatch";
constexpr const char* kCodeDataCrcMismatch = "jffs2-data-crc-mismatch";
constexpr const char* kCodeNameCrcMismatch = "jffs2-name-crc-mismatch";
constexpr const char* kCodeUnsupportedCompression = "jffs2-unsupported-compression";
constexpr const char* kCodeDecompressFailed = "jffs2-decompress-failed";
constexpr const char* kCodeOrphanInode = "jffs2-orphan-inode";
constexpr const char* kCodeMissingInode = "jffs2-missing-inode";
constexpr const char* kCodeDirLoop = "jffs2-dir-loop";
constexpr const char* kCodeLimitNodes = "jffs2-limit-nodes";
constexpr const char* kCodeLimitFiles = "jffs2-limit-files";
constexpr const char* kCodeLimitVersions = "jffs2-limit-versions";
constexpr const char* kCodeLimitFileBytes = "jffs2-limit-file-bytes";
constexpr const char* kCodeLimitDecompressRatio = "jffs2-limit-decompress-ratio";
constexpr const char* kCodeUnknownNodetype = "jffs2-unknown-nodetype";
constexpr const char* kCodeIsizeExceedsData = "jffs2-isize-exceeds-data";
constexpr const char* kCodeNodeTruncated = "jffs2-node-truncated";
constexpr const char* kCodeNodeMalformed = "jffs2-node-malformed";
constexpr const char* kCodeBadEntryName = "jffs2-bad-entry-name";
constexpr const char* kCodeSinkError = "jffs2-sink-error";

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

// ------------------------------------------------------------------ crc32
// JFFS2 uses the reflected 0xEDB88320 CRC-32 with seed 0 and no final xor
// (crc32_le(0, ...) in the kernel).
struct Crc32Table {
    std::array<std::uint32_t, 256> t{};
    constexpr Crc32Table() {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1u) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
            t[i] = c;
        }
    }
};
constexpr Crc32Table kCrc{};

std::uint32_t crc32_update(std::uint32_t crc, std::span<const std::uint8_t> data) {
    for (const std::uint8_t b : data) crc = kCrc.t[(crc ^ b) & 0xffu] ^ (crc >> 8);
    return crc;
}

const char* compr_name(std::uint8_t c) {
    switch (c) {
        case kComprNone:
            return "none";
        case kComprZero:
            return "zero";
        case kComprRtime:
            return "rtime";
        case kComprRubinMips:
            return "rubinmips";
        case kComprCopy:
            return "copy";
        case kComprDynRubin:
            return "dynrubin";
        case kComprZlib:
            return "zlib";
        case kComprLzo:
            return "lzo";
        case kComprLzma:
            return "lzma";
        default:
            return "unknown";
    }
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

EntryKind kind_from_dtype(std::uint8_t t) {
    switch (t) {
        case kDtReg:
            return EntryKind::Regular;
        case kDtDir:
            return EntryKind::Directory;
        case kDtLnk:
            return EntryKind::Symlink;
        case kDtChr:
            return EntryKind::CharDevice;
        case kDtBlk:
            return EntryKind::BlockDevice;
        case kDtFifo:
            return EntryKind::Fifo;
        case kDtSock:
            return EntryKind::Socket;
        default:
            return EntryKind::Unknown;
    }
}

// ------------------------------------------------------------------ node records

struct InodeNode {
    std::uint64_t off = 0;  // Span-relative offset of the node header
    std::uint32_t ino = 0, version = 0, mode = 0, isize = 0;
    std::uint32_t atime = 0, mtime = 0, ctime = 0;
    std::uint32_t offset = 0, csize = 0, dsize = 0;
    std::uint16_t uid = 0, gid = 0, flags = 0;
    std::uint8_t compr = 0, usercompr = 0;
    bool obsolete = false;  // ACCURATE bit cleared in place
    bool crc_ok = true;     // node_crc verified
    bool data_ok = true;    // data_crc verified over csize bytes
    bool usable() const { return crc_ok && data_ok && !obsolete; }
};

struct DirentNode {
    std::uint64_t off = 0;
    std::uint32_t pino = 0, version = 0, ino = 0, mctime = 0;
    std::uint8_t type = 0;
    bool obsolete = false;
    bool crc_ok = true;   // node_crc
    bool name_ok = true;  // name_crc
    std::string name;
    bool usable() const { return crc_ok && name_ok && !obsolete; }
};

struct XattrNode {
    std::uint32_t xid = 0, version = 0;
    std::uint8_t xprefix = 0;
    std::string name;
};

struct XrefNode {
    std::uint32_t ino = 0, xid = 0, xseqno = 0;
};

struct Counts {
    std::uint64_t nodes = 0, inode_nodes = 0, dirent_nodes = 0, cleanmarkers = 0, padding = 0,
                  summary = 0, xattr = 0, xref = 0, unknown = 0, obsolete = 0, node_crc_bad = 0,
                  data_crc_bad = 0, name_crc_bad = 0, truncated = 0, malformed = 0, unlinks = 0;
};

// One contiguous file range served by one inode node.
struct Frag {
    std::uint64_t start = 0, end = 0;  // file offsets, half-open
    std::size_t node = 0;              // index into Impl::inodes
};

// The reconstruction of one inode state: which node serves each byte range,
// and the size to truncate to. Holes are zeros.
struct Plan {
    std::vector<Frag> frags;        // sorted by start, non-overlapping
    std::uint64_t isize = 0;        // from the newest node in the state
    std::size_t newest = 0;         // index of the newest node in the state
    std::size_t count = 0;          // nodes in the state
    bool crc_bad = false;           // a node in the state failed a CRC
    bool obsolete = false;          // a node in the state was obsoleted in place
    std::set<std::uint8_t> codecs;  // compression ids of the frags that contribute
};

// Interval map used while building a Plan: later insertions overwrite.
class Coverage {
   public:
    void insert(std::uint64_t s, std::uint64_t e, std::size_t node) {
        if (e <= s) return;
        auto it = map_.lower_bound(s);
        if (it != map_.begin()) {
            auto prev = std::prev(it);
            if (prev->second.end > s) it = prev;
        }
        std::vector<Frag> keep;
        while (it != map_.end() && it->second.start < e) {
            const Frag f = it->second;
            if (f.start < s) keep.push_back({f.start, s, f.node});
            if (f.end > e) keep.push_back({e, f.end, f.node});
            it = map_.erase(it);
        }
        for (const Frag& f : keep) map_[f.start] = f;
        map_[s] = {s, e, node};
    }
    void truncate(std::uint64_t size) {
        auto it = map_.lower_bound(size);
        map_.erase(it, map_.end());
        if (!map_.empty()) {
            auto last = std::prev(map_.end());
            if (last->second.end > size) last->second.end = size;
        }
    }
    std::uint64_t extent() const { return map_.empty() ? 0 : std::prev(map_.end())->second.end; }
    std::vector<Frag> frags() const {
        std::vector<Frag> out;
        out.reserve(map_.size());
        for (const auto& kv : map_) out.push_back(kv.second);
        return out;
    }

   private:
    std::map<std::uint64_t, Frag> map_;
};

}  // namespace

// ------------------------------------------------------------------ Impl

struct Jffs2Reader::Impl {
    Span span;
    bool opened = false;
    Endian endian = Endian::Little;
    std::uint64_t first_node = 0;

    // Scan results. `inodes` is sorted by (ino, version, off) after the scan;
    // `dirents` stays in flash order.
    std::vector<InodeNode> inodes;
    std::vector<DirentNode> dirents;
    std::vector<XattrNode> xattrs;
    std::vector<XrefNode> xrefs;
    Counts counts;
    std::uint64_t last_node_end = 0;
    std::uint64_t erase_size = 0;  // inferred from cleanmarker spacing; 0 = unknown
    std::uint64_t cleanmarker_gcd = 0;
    std::set<std::uint8_t> compressors;
    std::uint64_t scan_cap = 0;
    bool scan_capped = false;
    std::vector<Diagnostic> open_diags;

    // Indexes.
    std::map<std::uint32_t, std::pair<std::size_t, std::size_t>> ino_range;  // [begin, end)
    std::map<std::pair<std::uint32_t, std::string>, std::size_t> live_best;  // usable dirents
    std::map<std::uint32_t, std::vector<std::size_t>> live_children;         // pino -> dirents
    std::map<std::pair<std::uint32_t, std::string>, std::vector<std::size_t>>
        dirent_history;                                   // crc-ok dirents by version
    std::map<std::uint32_t, std::size_t> last_dirent_of;  // ino -> newest crc-ok dirent naming it
    std::map<std::uint32_t, std::uint32_t> live_nlink;
    std::map<std::uint32_t, std::vector<std::string>> xattr_names;  // ino -> names
    std::uint64_t live_inode_count = 0, deleted_inode_count = 0, multi_version_count = 0;

    // One state of a path in its version sequence: the state after `count`
    // nodes of inode `ino`, or an explicit unlink record (`dirent` set).
    struct VersionPoint {
        std::uint32_t group = 0;  // holder's rank in the path (unlinks: the unlinked inode's)
        std::uint32_t ino = 0;    // 0 for an unlink record
        std::size_t count = 0;
        std::size_t dirent = 0;
        bool unlink = false;
        bool live = false;          // the state the live tree shows
        bool final = false;         // the newest state of the inode
        std::uint32_t raw = 0;      // JFFS2 node version (inode node, or dirent for unlinks)
        std::uint64_t version = 0;  // path-scoped version assigned to the entry
    };
    // Everything that ever occupied one path.
    struct PathSpace {
        std::vector<std::uint32_t> holders;                          // inodes, ascending
        std::vector<std::pair<std::size_t, std::uint32_t>> unlinks;  // (dirent, prior inode)
    };

    // Per-walk state.
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        bool stop = false;
        bool dry = false;  // traverse the live tree without emitting (path resolution only)
        std::map<std::uint32_t, std::string> live_path;    // first live path in walk order
        std::map<std::uint32_t, std::size_t> live_dirent;  // ino -> dirent that gave live_path
        std::set<std::uint32_t> walked_dirs;
        std::vector<std::uint8_t> zeros;
        std::vector<std::uint8_t> decoded;  // one decoded node
        std::size_t decoded_node = static_cast<std::size_t>(-1);
        std::vector<std::uint8_t> raw;  // compressed bytes when the Source cannot map
        std::uint64_t versions_capped_paths = 0;
        std::uint64_t orphans = 0;
        std::uint64_t unsupported_nodes = 0;
        std::set<std::uint8_t> unsupported_codecs;
        std::map<std::uint32_t, std::string> hist_dir_path;  // memo for hist_path_of_dir
        // Version namespace (build_version_space).
        std::map<std::string, PathSpace> spaces;              // path -> what held it
        std::map<std::uint32_t, std::string> deleted_path;    // deleted ino -> its path
        std::map<std::uint32_t, std::uint64_t> live_version;  // live ino -> its version
        std::set<std::uint32_t> orphan_inos;
    };
    const Limits* lim = nullptr;

    // scan
    Status scan(std::uint64_t max_nodes);
    void build_indexes();
    std::uint32_t crc_range(std::uint64_t off, std::uint64_t n) const;

    // reconstruction
    std::vector<std::size_t> chain_of(std::uint32_t ino, bool all) const;
    Plan plan_of(const std::vector<std::size_t>& chain, std::size_t count) const;
    bool decode_node(std::size_t idx, Walk& w, std::string& why, const char*& code);
    bool stream_plan(const Plan& p, const std::string& path, Walk& w,
                     const std::function<Status(std::span<const std::uint8_t>)>& write,
                     std::vector<Diagnostic>& diags, bool& truncated);
    bool write_zeros(Walk& w, std::uint64_t n,
                     const std::function<Status(std::span<const std::uint8_t>)>& write);
    std::vector<std::uint8_t> small_content(const Plan& p, Walk& w, std::vector<Diagnostic>& diags,
                                            bool& truncated);

    // emission
    FileMeta make_meta(const std::string& path, const InodeNode& n, const Plan& p,
                       std::uint32_t nlink) const;
    void set_kind_data(FileMeta& m, const Plan& p, Walk& w, std::vector<Diagnostic>& diags,
                       bool& truncated);
    void count_entry(WalkResult& out, const FileMeta& m);
    void emit_regular(const FileMeta& meta, const Plan& p, Walk& w);
    bool emit_other(const FileMeta& meta, Walk& w, std::vector<Diagnostic> diags);
    void emit_state(const std::string& path, const std::vector<std::size_t>& chain,
                    const VersionPoint& pt, bool deleted, bool superseded, std::uint32_t nlink,
                    Walk& w, std::map<std::string, std::string> extra);
    bool check_limits(const std::string& path, Walk& w);

    // version namespace
    std::vector<std::size_t> version_points(const std::vector<std::size_t>& chain) const;
    std::vector<VersionPoint> number_path(const PathSpace& space, const Walk& w) const;
    void build_version_space(Walk& w) const;
    std::string holders_text(const std::string& path, const Walk& w) const;

    // walk phases
    void walk_live(Walk& w);
    void walk_history(Walk& w);
    std::string hist_path_of_dir(std::uint32_t ino, Walk& w) const;
    std::string hist_path_of(std::uint32_t ino, Walk& w, bool& orphan) const;

    void diag(WalkResult& out, Severity s, const char* code, std::string msg) const {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }
};

// ------------------------------------------------------------------ scan

std::uint32_t Jffs2Reader::Impl::crc_range(std::uint64_t off, std::uint64_t n) const {
    std::uint32_t crc = 0;
    std::array<std::uint8_t, kChunk> buf{};
    while (n > 0) {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(n, buf.size()));
        const std::size_t got = span.read(off, std::span<std::uint8_t>(buf.data(), want));
        if (got == 0) return ~crc;  // short read: cannot match anything sensible
        crc = crc32_update(crc, std::span<const std::uint8_t>(buf.data(), got));
        off += got;
        n -= got;
    }
    return crc;
}

Status Jffs2Reader::Impl::scan(std::uint64_t max_nodes) {
    inodes.clear();
    dirents.clear();
    xattrs.clear();
    xrefs.clear();
    counts = Counts{};
    compressors.clear();
    open_diags.clear();
    last_node_end = 0;
    cleanmarker_gcd = 0;
    erase_size = 0;
    scan_cap = max_nodes;
    scan_capped = false;

    bool endian_known = false;
    std::uint64_t pos = 0;
    const std::uint64_t size = span.size();
    std::vector<std::uint8_t> buf(kChunk + kHdrSize);
    std::uint64_t buf_base = 0;
    std::size_t buf_len = 0;
    bool have_buf = false;
    std::uint64_t unknown_seen = 0;
    std::map<std::uint16_t, std::uint64_t> unknown_types;
    std::uint64_t cleanmarker_first = 0;

    auto parse_header = [&](const std::uint8_t* raw, Endian e, std::uint16_t& nodetype,
                            std::uint32_t& totlen, bool& obsolete) -> bool {
        if (load_int<std::uint16_t>(raw, e) != kMagic) return false;
        nodetype = load_int<std::uint16_t>(raw + 2, e);
        totlen = load_int<std::uint32_t>(raw + 4, e);
        const std::uint32_t stored = load_int<std::uint32_t>(raw + 8, e);
        obsolete = false;
        if (crc32_update(0, std::span<const std::uint8_t>(raw, 8)) == stored) return true;
        if ((nodetype & kAccurate) != 0) return false;
        // Obsoleted in place (fs/jffs2/scan.c): the CRC was computed with the
        // ACCURATE bit set.
        std::array<std::uint8_t, 8> fixed{};
        std::copy(raw, raw + 8, fixed.begin());
        const std::uint16_t t = static_cast<std::uint16_t>(nodetype | kAccurate);
        if (e == Endian::Little) {
            fixed[2] = static_cast<std::uint8_t>(t & 0xFF);
            fixed[3] = static_cast<std::uint8_t>(t >> 8);
        } else {
            fixed[2] = static_cast<std::uint8_t>(t >> 8);
            fixed[3] = static_cast<std::uint8_t>(t & 0xFF);
        }
        if (crc32_update(0, fixed) != stored) return false;
        obsolete = true;
        return true;
    };

    while (pos + kHdrSize <= size) {
        if (!have_buf || pos < buf_base || pos + kHdrSize > buf_base + buf_len) {
            buf_base = pos;
            buf_len = span.read(pos, std::span<std::uint8_t>(buf.data(), buf.size()));
            have_buf = true;
            if (buf_len < kHdrSize) break;
        }
        const std::uint8_t* p = buf.data() + (pos - buf_base);
        if (p[0] == 0xFF && p[1] == 0xFF && p[2] == 0xFF && p[3] == 0xFF) {
            pos += 4;
            continue;
        }
        std::uint16_t nodetype = 0;
        std::uint32_t totlen = 0;
        bool obsolete = false;
        bool ok = false;
        if (endian_known) {
            ok = parse_header(p, endian, nodetype, totlen, obsolete);
        } else {
            if (p[0] == 0x85 && p[1] == 0x19) {
                ok = parse_header(p, Endian::Little, nodetype, totlen, obsolete);
                if (ok) endian = Endian::Little;
            } else if (p[0] == 0x19 && p[1] == 0x85) {
                ok = parse_header(p, Endian::Big, nodetype, totlen, obsolete);
                if (ok) endian = Endian::Big;
            }
            if (ok) {
                endian_known = true;
                first_node = pos;
            }
        }
        if (!ok) {
            pos += 4;
            continue;
        }
        if (totlen < kHdrSize) {
            counts.malformed++;
            pos += 4;
            continue;
        }
        if (totlen > size - pos) {
            // Header verified but the body runs past the data: a truncated
            // image or a hostile length. Nothing after the header is trusted.
            counts.truncated++;
            pos += 4;
            continue;
        }
        if (counts.nodes >= max_nodes) {
            scan_capped = true;
            break;
        }
        counts.nodes++;
        if (obsolete) counts.obsolete++;
        const std::uint16_t type = static_cast<std::uint16_t>(nodetype | kAccurate);
        const std::uint64_t node_off = pos;
        const std::uint64_t next = pos + ((static_cast<std::uint64_t>(totlen) + 3) & ~3ull);
        last_node_end = std::min(size, std::max(last_node_end, pos + totlen));

        switch (type) {
            case kTypeInode: {
                counts.inode_nodes++;
                if (totlen < kInodeSize) {
                    counts.malformed++;
                    break;
                }
                std::array<std::uint8_t, kInodeSize> r{};
                if (span.read(node_off, std::span<std::uint8_t>(r.data(), r.size())) != r.size())
                    break;
                InodeNode n;
                n.off = node_off;
                n.obsolete = obsolete;
                n.ino = load_int<std::uint32_t>(r.data() + 12, endian);
                n.version = load_int<std::uint32_t>(r.data() + 16, endian);
                n.mode = load_int<std::uint32_t>(r.data() + 20, endian);
                n.uid = load_int<std::uint16_t>(r.data() + 24, endian);
                n.gid = load_int<std::uint16_t>(r.data() + 26, endian);
                n.isize = load_int<std::uint32_t>(r.data() + 28, endian);
                n.atime = load_int<std::uint32_t>(r.data() + 32, endian);
                n.mtime = load_int<std::uint32_t>(r.data() + 36, endian);
                n.ctime = load_int<std::uint32_t>(r.data() + 40, endian);
                n.offset = load_int<std::uint32_t>(r.data() + 44, endian);
                n.csize = load_int<std::uint32_t>(r.data() + 48, endian);
                n.dsize = load_int<std::uint32_t>(r.data() + 52, endian);
                n.compr = r[56];
                n.usercompr = r[57];
                n.flags = load_int<std::uint16_t>(r.data() + 58, endian);
                const std::uint32_t data_crc = load_int<std::uint32_t>(r.data() + 60, endian);
                const std::uint32_t node_crc = load_int<std::uint32_t>(r.data() + 64, endian);
                n.crc_ok = crc32_update(0, std::span<const std::uint8_t>(r.data(), 60)) == node_crc;
                if (!n.crc_ok) counts.node_crc_bad++;
                if (n.csize > totlen - kInodeSize) {
                    counts.malformed++;
                    n.data_ok = false;
                    n.csize = 0;  // nothing trustworthy to read
                    n.dsize = 0;
                } else {
                    n.data_ok = crc_range(node_off + kInodeSize, n.csize) == data_crc;
                    if (!n.data_ok) counts.data_crc_bad++;
                }
                if (n.crc_ok) compressors.insert(n.compr);
                inodes.push_back(n);
                break;
            }
            case kTypeDirent: {
                counts.dirent_nodes++;
                if (totlen < kDirentSize) {
                    counts.malformed++;
                    break;
                }
                std::array<std::uint8_t, kDirentSize> r{};
                if (span.read(node_off, std::span<std::uint8_t>(r.data(), r.size())) != r.size())
                    break;
                DirentNode d;
                d.off = node_off;
                d.obsolete = obsolete;
                d.pino = load_int<std::uint32_t>(r.data() + 12, endian);
                d.version = load_int<std::uint32_t>(r.data() + 16, endian);
                d.ino = load_int<std::uint32_t>(r.data() + 20, endian);
                d.mctime = load_int<std::uint32_t>(r.data() + 24, endian);
                const std::uint8_t nsize = r[28];
                d.type = r[29];
                const std::uint32_t node_crc = load_int<std::uint32_t>(r.data() + 32, endian);
                const std::uint32_t name_crc = load_int<std::uint32_t>(r.data() + 36, endian);
                d.crc_ok = crc32_update(0, std::span<const std::uint8_t>(r.data(), 32)) == node_crc;
                if (!d.crc_ok) counts.node_crc_bad++;
                if (nsize > totlen - kDirentSize) {
                    counts.malformed++;
                    d.name_ok = false;
                } else {
                    auto name = span.bytes(node_off + kDirentSize, nsize);
                    if (!name) break;
                    d.name.assign(name->begin(), name->end());
                    d.name_ok = crc32_update(0, *name) == name_crc;
                    if (!d.name_ok) counts.name_crc_bad++;
                }
                if (d.crc_ok && d.ino == 0) counts.unlinks++;
                dirents.push_back(std::move(d));
                break;
            }
            case kTypeXattr: {
                counts.xattr++;
                if (totlen < kXattrSize) {
                    counts.malformed++;
                    break;
                }
                std::array<std::uint8_t, kXattrSize> r{};
                if (span.read(node_off, std::span<std::uint8_t>(r.data(), r.size())) != r.size())
                    break;
                const std::uint32_t node_crc = load_int<std::uint32_t>(r.data() + 28, endian);
                if (crc32_update(0, std::span<const std::uint8_t>(r.data(), 28)) != node_crc) {
                    counts.node_crc_bad++;
                    break;
                }
                XattrNode x;
                x.xid = load_int<std::uint32_t>(r.data() + 12, endian);
                x.version = load_int<std::uint32_t>(r.data() + 16, endian);
                x.xprefix = r[20];
                const std::uint8_t name_len = r[21];
                if (name_len > totlen - kXattrSize) {
                    counts.malformed++;
                    break;
                }
                if (auto name = span.bytes(node_off + kXattrSize, name_len))
                    x.name.assign(name->begin(), name->end());
                xattrs.push_back(std::move(x));
                break;
            }
            case kTypeXref: {
                counts.xref++;
                if (totlen < kXrefSize) {
                    counts.malformed++;
                    break;
                }
                std::array<std::uint8_t, kXrefSize> r{};
                if (span.read(node_off, std::span<std::uint8_t>(r.data(), r.size())) != r.size())
                    break;
                const std::uint32_t node_crc = load_int<std::uint32_t>(r.data() + 24, endian);
                if (crc32_update(0, std::span<const std::uint8_t>(r.data(), 24)) != node_crc) {
                    counts.node_crc_bad++;
                    break;
                }
                XrefNode x;
                x.ino = load_int<std::uint32_t>(r.data() + 12, endian);
                x.xid = load_int<std::uint32_t>(r.data() + 16, endian);
                x.xseqno = load_int<std::uint32_t>(r.data() + 20, endian);
                xrefs.push_back(x);
                break;
            }
            case kTypeCleanmarker:
                counts.cleanmarkers++;
                if (counts.cleanmarkers == 1) {
                    cleanmarker_first = node_off;
                } else {
                    const std::uint64_t delta = node_off - cleanmarker_first;
                    cleanmarker_gcd =
                        cleanmarker_gcd == 0 ? delta : std::gcd(cleanmarker_gcd, delta);
                }
                break;
            case kTypePadding:
                counts.padding++;
                break;
            case kTypeSummary:
                counts.summary++;
                if (totlen < kSummarySize) counts.malformed++;
                break;
            default:
                counts.unknown++;
                unknown_seen++;
                unknown_types[type]++;
                break;
        }
        pos = next;
    }

    if (!endian_known) return Status::fail("jffs2-no-nodes: no CRC-valid node header found");

    // Erase size: the largest power of two dividing the cleanmarker spacing,
    // relative to the first cleanmarker (they sit at erase-block starts).
    if (cleanmarker_gcd != 0) {
        std::uint64_t e = 1;
        while ((cleanmarker_gcd & e) == 0 && e < (1ull << 40)) e <<= 1;
        if (e >= 4096) erase_size = e;
    }

    std::stable_sort(inodes.begin(), inodes.end(), [](const InodeNode& a, const InodeNode& b) {
        if (a.ino != b.ino) return a.ino < b.ino;
        if (a.version != b.version) return a.version < b.version;
        return a.off < b.off;
    });

    if (scan_capped) {
        open_diags.push_back({Severity::Warning, kCodeLimitNodes,
                              "max_nodes_per_fs (" + dec(max_nodes) + ") reached at " + hex(pos) +
                                  "; nodes after it were not scanned"});
    }
    if (counts.truncated != 0)
        open_diags.push_back({Severity::Warning, kCodeNodeTruncated,
                              dec(counts.truncated) +
                                  " node header(s) whose totlen runs past the end of the data "
                                  "(truncated image or hostile length); skipped"});
    if (counts.malformed != 0)
        open_diags.push_back({Severity::Warning, kCodeNodeMalformed,
                              dec(counts.malformed) +
                                  " node(s) with a length field inconsistent with totlen or a "
                                  "totlen below the type's minimum; their payload was ignored"});
    if (counts.node_crc_bad != 0)
        open_diags.push_back({Severity::Warning, kCodeNodeCrcMismatch,
                              dec(counts.node_crc_bad) +
                                  " node(s) failed node_crc; ignored for the live tree, kept for "
                                  "history with extra crc=bad"});
    if (counts.data_crc_bad != 0)
        open_diags.push_back({Severity::Warning, kCodeDataCrcMismatch,
                              dec(counts.data_crc_bad) +
                                  " inode node(s) failed data_crc; ignored for the live tree, kept "
                                  "for history with extra crc=bad"});
    if (counts.name_crc_bad != 0)
        open_diags.push_back(
            {Severity::Warning, kCodeNameCrcMismatch,
             dec(counts.name_crc_bad) + " dirent node(s) failed name_crc; not used for any path"});
    if (unknown_seen != 0) {
        std::string types;
        for (const auto& [t, n] : unknown_types)
            types += (types.empty() ? "" : ", ") + hex(t) + " x" + dec(n);
        open_diags.push_back({Severity::Info, kCodeUnknownNodetype,
                              dec(unknown_seen) +
                                  " node(s) of a type this reader does not decode (" + types +
                                  "); skipped by totlen"});
    }
    build_indexes();
    return Status::success();
}

void Jffs2Reader::Impl::build_indexes() {
    ino_range.clear();
    live_best.clear();
    live_children.clear();
    dirent_history.clear();
    last_dirent_of.clear();
    live_nlink.clear();
    xattr_names.clear();
    live_inode_count = deleted_inode_count = multi_version_count = 0;

    for (std::size_t i = 0; i < inodes.size();) {
        std::size_t j = i;
        while (j < inodes.size() && inodes[j].ino == inodes[i].ino) ++j;
        ino_range[inodes[i].ino] = {i, j};
        i = j;
    }

    for (std::size_t i = 0; i < dirents.size(); ++i) {
        const DirentNode& d = dirents[i];
        if (!d.crc_ok || !d.name_ok) continue;
        const auto key = std::make_pair(d.pino, d.name);
        dirent_history[key].push_back(i);
        if (d.ino != 0) {
            auto it = last_dirent_of.find(d.ino);
            if (it == last_dirent_of.end() || dirents[it->second].version < d.version ||
                (dirents[it->second].version == d.version && dirents[it->second].off < d.off))
                last_dirent_of[d.ino] = i;
        }
        if (!d.usable()) continue;
        auto it = live_best.find(key);
        if (it == live_best.end() || dirents[it->second].version < d.version ||
            (dirents[it->second].version == d.version && dirents[it->second].off < d.off))
            live_best[key] = i;
    }
    for (auto& [key, v] : dirent_history) {
        std::stable_sort(v.begin(), v.end(), [&](std::size_t a, std::size_t b) {
            if (dirents[a].version != dirents[b].version)
                return dirents[a].version < dirents[b].version;
            return dirents[a].off < dirents[b].off;
        });
    }
    // live_best is keyed by (pino, name) with std::string ordering, which is
    // bytewise (char_traits<char> compares as unsigned char): the walk order.
    for (const auto& [key, idx] : live_best) {
        const DirentNode& d = dirents[idx];
        if (d.ino == 0) continue;
        live_children[d.pino].push_back(idx);
        live_nlink[d.ino]++;
    }

    std::set<std::uint32_t> live_inos;
    for (const auto& [ino, n] : live_nlink) live_inos.insert(ino);
    for (const auto& [ino, range] : ino_range) {
        if (ino == kRootIno || live_inos.count(ino))  // the root is always live
            live_inode_count++;
        else
            deleted_inode_count++;
        std::set<std::uint32_t> versions;
        for (std::size_t i = range.first; i < range.second; ++i) versions.insert(inodes[i].version);
        if (versions.size() > 1) multi_version_count++;
    }

    // Xattrs: the newest xattr node per xid gives the name; xrefs link inodes
    // to xids (a delete marker in `ino` retires the reference).
    std::map<std::uint32_t, std::size_t> xid_newest;
    for (std::size_t i = 0; i < xattrs.size(); ++i) {
        auto it = xid_newest.find(xattrs[i].xid);
        if (it == xid_newest.end() || xattrs[it->second].version < xattrs[i].version)
            xid_newest[xattrs[i].xid] = i;
    }
    static const char* const kPrefixes[] = {
        "",        "user.", "security.", "system.posix_acl_access", "system.posix_acl_default",
        "trusted."};
    std::map<std::uint32_t, std::set<std::string>> names;
    for (const XrefNode& x : xrefs) {
        if ((x.ino & kXrefDeleteMarker) != 0 || (x.xid & kXrefDeleteMarker) != 0) continue;
        std::string name;
        const auto it = xid_newest.find(x.xid);
        if (it == xid_newest.end()) {
            name = "#" + dec(x.xid);
        } else {
            const XattrNode& xa = xattrs[it->second];
            name = (xa.xprefix < 6 ? kPrefixes[xa.xprefix] : "?") + xa.name;
        }
        names[x.ino].insert(name);
    }
    for (auto& [ino, set] : names) xattr_names[ino].assign(set.begin(), set.end());
}

// ------------------------------------------------------------------ reconstruction

// Indices (into `inodes`) of one inode's nodes in ascending (version, offset)
// order. `all` includes obsolete and CRC-failed nodes (history); otherwise
// only nodes a mount would use.
std::vector<std::size_t> Jffs2Reader::Impl::chain_of(std::uint32_t ino, bool all) const {
    std::vector<std::size_t> out;
    const auto it = ino_range.find(ino);
    if (it == ino_range.end()) return out;
    for (std::size_t i = it->second.first; i < it->second.second; ++i)
        if (all || inodes[i].usable()) out.push_back(i);
    return out;
}

// The state after applying the first `count` nodes of `chain`: data
// fragments in version order (later overwrite earlier), a metadata-only node
// whose isize is smaller than the data extent truncates it (what the kernel
// did at setattr time), and the final isize truncates the whole.
Plan Jffs2Reader::Impl::plan_of(const std::vector<std::size_t>& chain, std::size_t count) const {
    Plan p;
    Coverage cov;
    p.count = count;
    for (std::size_t k = 0; k < count && k < chain.size(); ++k) {
        const InodeNode& n = inodes[chain[k]];
        if (n.dsize != 0) {
            cov.insert(n.offset, static_cast<std::uint64_t>(n.offset) + n.dsize, chain[k]);
        } else if (n.isize < cov.extent()) {
            cov.truncate(n.isize);
        }
        p.isize = n.isize;
        p.newest = chain[k];
        if (!n.crc_ok || !n.data_ok) p.crc_bad = true;
        if (n.obsolete) p.obsolete = true;
    }
    cov.truncate(p.isize);
    p.frags = cov.frags();
    for (const Frag& f : p.frags) p.codecs.insert(inodes[f.node].compr);
    return p;
}

// Decode the whole data payload of one inode node into w.decoded (cached by
// node index). False with `why`/`code` when it cannot be produced.
bool Jffs2Reader::Impl::decode_node(std::size_t idx, Walk& w, std::string& why, const char*& code) {
    if (w.decoded_node == idx) return true;
    w.decoded_node = static_cast<std::size_t>(-1);
    const InodeNode& n = inodes[idx];
    const Limits& L = *lim;
    if (n.dsize > L.max_file_bytes) {
        code = kCodeLimitFileBytes;
        why = "node at " + hex(n.off) + " claims dsize " + dec(n.dsize) +
              ", above max_file_bytes (" + dec(L.max_file_bytes) + ")";
        return false;
    }
    if (n.compr == kComprZero) {
        w.decoded.assign(n.dsize, 0);
        w.decoded_node = idx;
        return true;
    }
    const std::uint64_t ratio = std::max<std::uint64_t>(1, L.max_decompress_ratio);
    if (n.compr != kComprNone && n.compr != kComprCopy && n.csize != 0 &&
        static_cast<std::uint64_t>(n.dsize) / ratio > n.csize) {
        code = kCodeLimitDecompressRatio;
        why = "node at " + hex(n.off) + " claims " + dec(n.dsize) + " bytes from " + dec(n.csize) +
              " (above max_decompress_ratio " + dec(L.max_decompress_ratio) + ")";
        return false;
    }
    std::span<const std::uint8_t> in;
    {
        const auto view = span.view(n.off + kInodeSize, n.csize);
        if (view) {
            in = *view;
        } else {
            auto copy = span.bytes(n.off + kInodeSize, n.csize);
            if (!copy) {
                code = kCodeDecompressFailed;
                why =
                    "node at " + hex(n.off) + ": source refused to read " + dec(n.csize) + " bytes";
                return false;
            }
            w.raw = std::move(*copy);
            in = w.raw;
        }
    }
    Status s;
    switch (n.compr) {
        case kComprNone:
        case kComprCopy:
            if (n.csize != n.dsize) {
                code = kCodeNodeMalformed;
                why = "node at " + hex(n.off) + " stores " + dec(n.csize) +
                      " uncompressed bytes but claims dsize " + dec(n.dsize);
                return false;
            }
            w.decoded.assign(in.begin(), in.end());
            w.decoded_node = idx;
            return true;
        case kComprRtime:
            s = compress::decompress_exact(compress::Codec::Rtime, in, w.decoded, n.dsize);
            break;
        case kComprZlib:
            s = compress::decompress_exact(compress::Codec::Zlib, in, w.decoded, n.dsize);
            break;
        case kComprLzo:
            s = compress::decompress_exact(compress::Codec::Lzo1x, in, w.decoded, n.dsize);
            break;
        case kComprLzma: {
            // Headerless LZMA1 (OpenWrt): prepend the LZMA-alone header the
            // encoder omitted: props byte 0 (lc=0, lp=0, pb=0), dictionary
            // size, and the exact uncompressed size.
            std::vector<std::uint8_t> framed;
            framed.reserve(13 + in.size());
            framed.push_back(0);
            for (int i = 0; i < 4; ++i)
                framed.push_back(static_cast<std::uint8_t>((kLzmaDictSize >> (8 * i)) & 0xFF));
            for (int i = 0; i < 8; ++i)
                framed.push_back(static_cast<std::uint8_t>(
                    (static_cast<std::uint64_t>(n.dsize) >> (8 * i)) & 0xFF));
            framed.insert(framed.end(), in.begin(), in.end());
            s = compress::decompress_exact(compress::Codec::Lzma, framed, w.decoded, n.dsize);
            break;
        }
        default:
            code = kCodeUnsupportedCompression;
            why = "node at " + hex(n.off) + " uses compression " + compr_name(n.compr) + " (id " +
                  dec(n.compr) + "), which this reader cannot decode";
            w.unsupported_nodes++;
            w.unsupported_codecs.insert(n.compr);
            return false;
    }
    if (!s) {
        code = kCodeDecompressFailed;
        why = "node at " + hex(n.off) + " (" + compr_name(n.compr) + ", " + dec(n.csize) + " -> " +
              dec(n.dsize) + " bytes): " + s.error;
        return false;
    }
    w.decoded_node = idx;
    return true;
}

bool Jffs2Reader::Impl::write_zeros(
    Walk& w, std::uint64_t n, const std::function<Status(std::span<const std::uint8_t>)>& write) {
    if (w.zeros.empty()) w.zeros.assign(kChunk, 0);
    while (n > 0) {
        const std::size_t k = static_cast<std::size_t>(std::min<std::uint64_t>(n, w.zeros.size()));
        if (!write(std::span<const std::uint8_t>(w.zeros.data(), k))) return false;
        n -= k;
    }
    return true;
}

// Stream the bytes of `p` through `write` in file order: holes as zeros, each
// fragment from its node decoded once (consecutive fragments of the same node
// share the decode). Returns false when `write` refused (sink limit); sets
// `truncated` when data could not be produced and was zero-filled or cut.
bool Jffs2Reader::Impl::stream_plan(
    const Plan& p, const std::string& path, Walk& w,
    const std::function<Status(std::span<const std::uint8_t>)>& write,
    std::vector<Diagnostic>& diags, bool& truncated) {
    const Limits& L = *lim;
    std::uint64_t total = p.isize;
    if (total > L.max_file_bytes) {
        diags.push_back({Severity::Warning, kCodeLimitFileBytes,
                         "'" + path + "': isize " + dec(p.isize) + " exceeds max_file_bytes (" +
                             dec(L.max_file_bytes) + "); data cut there"});
        total = L.max_file_bytes;
        truncated = true;
    }
    std::uint64_t pos = 0;
    std::uint64_t covered_end = 0;
    for (const Frag& f : p.frags) {
        if (f.start >= total) break;
        const std::uint64_t end = std::min(f.end, total);
        covered_end = std::max(covered_end, f.end);
        if (f.start > pos) {
            if (!write_zeros(w, f.start - pos, write)) return false;
            pos = f.start;
        }
        if (inodes[f.node].compr == kComprZero) {  // a hole node: nothing to decode
            if (!write_zeros(w, end - pos, write)) return false;
            pos = end;
            continue;
        }
        std::string why;
        const char* code = kCodeDecompressFailed;
        if (decode_node(f.node, w, why, code)) {
            const InodeNode& n = inodes[f.node];
            const std::uint64_t skip = f.start - n.offset;  // f lies inside the node's range
            if (skip + (end - f.start) <= w.decoded.size()) {
                if (!write(std::span<const std::uint8_t>(w.decoded.data() + skip,
                                                         static_cast<std::size_t>(end - f.start))))
                    return false;
                pos = end;
                continue;
            }
            why = "decoded " + dec(w.decoded.size()) + " bytes, fragment needs " +
                  dec(skip + (end - f.start));
            code = kCodeDecompressFailed;
        }
        diags.push_back({Severity::Warning, code, "'" + path + "': " + why + "; zero-filled"});
        truncated = true;
        if (!write_zeros(w, end - pos, write)) return false;
        pos = end;
    }
    if (pos < total) {
        if (!write_zeros(w, total - pos, write)) return false;
        pos = total;
    }
    if (p.isize > covered_end && p.count > 0) {
        diags.push_back({Severity::Info, kCodeIsizeExceedsData,
                         "'" + path + "': isize " + dec(p.isize) + " exceeds the " +
                             dec(covered_end) +
                             " bytes covered by data nodes; the rest is zero-filled (sparse "
                             "tail or lost nodes)"});
    }
    return true;
}

// Whole content in memory for symlink targets and device numbers. Bounded by
// max_file_bytes through stream_plan.
std::vector<std::uint8_t> Jffs2Reader::Impl::small_content(const Plan& p, Walk& w,
                                                           std::vector<Diagnostic>& diags,
                                                           bool& truncated) {
    std::vector<std::uint8_t> out;
    (void)stream_plan(
        p, "inode " + dec(inodes[p.newest].ino), w,
        [&](std::span<const std::uint8_t> d) {
            out.insert(out.end(), d.begin(), d.end());
            return Status::success();
        },
        diags, truncated);
    return out;
}

// ------------------------------------------------------------------ emission

FileMeta Jffs2Reader::Impl::make_meta(const std::string& path, const InodeNode& n, const Plan& p,
                                      std::uint32_t nlink) const {
    FileMeta m;
    m.path = path;
    m.kind = kind_from_mode(n.mode);
    m.mode = n.mode & 07777;
    m.uid = n.uid;
    m.gid = n.gid;
    m.size = m.kind == EntryKind::Directory ? 0 : n.isize;
    m.atime = static_cast<std::int64_t>(n.atime);
    m.mtime = static_cast<std::int64_t>(n.mtime);
    m.ctime = static_cast<std::int64_t>(n.ctime);
    m.inode = n.ino;
    m.nlink = nlink;
    m.version = n.version;
    std::string codecs;
    for (const std::uint8_t c : p.codecs)
        codecs += (codecs.empty() ? "" : ",") + std::string(compr_name(c));
    if (!codecs.empty()) m.extra["compression"] = codecs;
    m.extra["nodes"] = dec(p.count);
    if (p.crc_bad) m.extra["crc"] = "bad";
    if (p.obsolete) m.extra["obsolete"] = "true";
    if (n.flags != 0) m.extra["flags"] = hex(n.flags);
    const auto xa = xattr_names.find(n.ino);
    if (xa != xattr_names.end()) {
        std::string names;
        for (const std::string& s : xa->second) names += (names.empty() ? "" : ",") + s;
        m.extra["xattrs"] = names;
    }
    return m;
}

// Symlink target and device numbers live in the inode data.
void Jffs2Reader::Impl::set_kind_data(FileMeta& m, const Plan& p, Walk& w,
                                      std::vector<Diagnostic>& diags, bool& truncated) {
    if (m.kind == EntryKind::Symlink) {
        const std::vector<std::uint8_t> t = small_content(p, w, diags, truncated);
        m.link_target.assign(t.begin(), t.end());
        m.size = t.size();
    } else if (m.kind == EntryKind::CharDevice || m.kind == EntryKind::BlockDevice) {
        const std::vector<std::uint8_t> d = small_content(p, w, diags, truncated);
        if (d.size() == 2) {
            const std::uint16_t v = load_int<std::uint16_t>(d.data(), endian);  // old_decode_dev
            m.rdev_major = static_cast<std::uint32_t>((v >> 8) & 0xff);
            m.rdev_minor = static_cast<std::uint32_t>(v & 0xff);
        } else if (d.size() == 4) {
            const std::uint32_t v = load_int<std::uint32_t>(d.data(), endian);  // new_decode_dev
            m.rdev_major = (v & 0xfff00u) >> 8;
            m.rdev_minor = (v & 0xffu) | ((v >> 12) & 0xfff00u);
        }
        m.size = 0;
    }
}

void Jffs2Reader::Impl::count_entry(WalkResult& out, const FileMeta& m) {
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

bool Jffs2Reader::Impl::check_limits(const std::string& path, Walk& w) {
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

void Jffs2Reader::Impl::emit_regular(const FileMeta& meta, const Plan& p, Walk& w) {
    Status s = w.sink->begin_file(meta);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return;
    }
    std::vector<Diagnostic> diags;
    bool truncated = false;
    bool sink_ok = true;
    if (w.opts->extract_data) {
        sink_ok = stream_plan(
            p, meta.path, w, [&](std::span<const std::uint8_t> d) { return w.sink->write(d); },
            diags, truncated);
    }
    EntryResult r;
    s = w.sink->end_file(r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        if (r.meta.path.empty()) return;
    }
    if (!sink_ok || truncated) r.truncated = true;
    // The walk has to admit it: a coverage row saying "supported" over a
    // cut entry reads as a clean extraction.
    if (r.truncated) w.out->truncated = true;
    for (Diagnostic& d : diags) r.diagnostics.push_back(std::move(d));
    w.out->bytes += r.digests.bytes;
    count_entry(*w.out, r.meta);
    w.out->entries_out.push_back(std::move(r));
}

bool Jffs2Reader::Impl::emit_other(const FileMeta& meta, Walk& w, std::vector<Diagnostic> diags) {
    EntryResult r;
    const Status s = w.sink->entry(meta, r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return false;
    }
    for (Diagnostic& d : diags) r.diagnostics.push_back(std::move(d));
    count_entry(*w.out, r.meta);
    w.out->entries_out.push_back(std::move(r));
    return true;
}

// Emit the state `pt` (the first `pt.count` nodes of `chain`) at `path`.
void Jffs2Reader::Impl::emit_state(const std::string& path, const std::vector<std::size_t>& chain,
                                   const VersionPoint& pt, bool deleted, bool superseded,
                                   std::uint32_t nlink, Walk& w,
                                   std::map<std::string, std::string> extra) {
    if (!check_limits(path, w)) return;
    const Plan p = plan_of(chain, pt.count);
    FileMeta m = make_meta(path, inodes[p.newest], p, nlink);
    m.deleted = deleted;
    m.superseded = superseded;
    m.extra["jffs2_version"] = dec(m.version);
    m.version = pt.version;
    for (auto& [k, v] : extra) m.extra[k] = v;
    if (m.kind == EntryKind::Regular) {
        emit_regular(m, p, w);
        return;
    }
    std::vector<Diagnostic> diags;
    bool truncated = false;
    set_kind_data(m, p, w, diags, truncated);
    (void)emit_other(m, w, std::move(diags));
}

// ------------------------------------------------------------------ live walk

void Jffs2Reader::Impl::walk_live(Walk& w) {
    struct Frame {
        std::uint32_t ino;
        std::string path;
        std::size_t next = 0;
    };
    std::vector<Frame> stack;
    stack.push_back({kRootIno, "", 0});
    w.walked_dirs.insert(kRootIno);

    while (!stack.empty() && !w.stop) {
        Frame& top = stack.back();
        const auto children = live_children.find(top.ino);
        if (children == live_children.end() || top.next >= children->second.size()) {
            stack.pop_back();
            continue;
        }
        const std::size_t dirent_idx = children->second[top.next++];
        const DirentNode& d = dirents[dirent_idx];
        const std::string parent_path = top.path;
        const std::uint32_t parent_ino = top.ino;
        // `top` may dangle after a push_back below; do not use it past here.

        if (d.name.empty() || d.name == "." || d.name == ".." ||
            d.name.find('/') != std::string::npos || d.name.find('\0') != std::string::npos) {
            diag(*w.out, Severity::Warning, kCodeBadEntryName,
                 "directory '" + parent_path + "' (inode " + dec(parent_ino) +
                     ") has an entry named '" + d.name + "' (skipped)");
            continue;
        }
        const std::string path = parent_path.empty() ? d.name : parent_path + "/" + d.name;
        if (!w.dry && !check_limits(path, w)) break;

        const std::vector<std::size_t> chain = chain_of(d.ino, false);
        const std::uint32_t nlink = live_nlink.count(d.ino) ? live_nlink.at(d.ino) : 0;
        if (w.dry) {
            // Path resolution only: the same traversal decisions as below
            // (ancestor loops and repeated directories are not descended),
            // minus the Sink, so live_path is known before anything is emitted.
            if (!w.live_path.count(d.ino)) {
                w.live_path[d.ino] = path;
                w.live_dirent[d.ino] = dirent_idx;
            }
            const EntryKind kind =
                chain.empty() ? kind_from_dtype(d.type) : kind_from_mode(inodes[chain.back()].mode);
            if (kind != EntryKind::Directory) continue;
            bool loop = false;
            for (const Frame& f : stack)
                if (f.ino == d.ino) loop = true;
            if (!loop && w.walked_dirs.insert(d.ino).second) stack.push_back({d.ino, path, 0});
            continue;
        }
        if (chain.empty()) {
            // Named, but no usable inode node: a mount lists the name and
            // fails to stat it. Keep the name with what the dirent knows.
            const bool any_nodes = ino_range.count(d.ino) != 0;
            diag(*w.out, Severity::Warning, kCodeMissingInode,
                 "'" + path + "': dirent names inode " + dec(d.ino) +
                     (any_nodes ? " but every inode node for it is obsolete or failed its CRC"
                                : " but no inode node exists for it") +
                     "; emitted from the dirent alone");
            FileMeta m;
            m.path = path;
            m.kind = kind_from_dtype(d.type);
            m.inode = d.ino;
            m.nlink = nlink;
            m.mtime = static_cast<std::int64_t>(d.mctime);
            m.extra["nodes"] = "0";
            m.extra["dirent_version"] = dec(d.version);
            if (!w.live_path.count(d.ino)) w.live_path[d.ino] = path;
            if (m.kind == EntryKind::Regular) {
                emit_regular(m, Plan{}, w);
            } else if (emit_other(m, w, {}) && m.kind == EntryKind::Directory &&
                       w.walked_dirs.insert(d.ino).second) {
                stack.push_back({d.ino, path, 0});  // its children may still be named
            }
            continue;
        }
        const Plan p = plan_of(chain, chain.size());
        FileMeta m = make_meta(path, inodes[p.newest], p, nlink);
        if (!w.live_path.count(d.ino)) w.live_path[d.ino] = path;
        // Path-scoped version (build_version_space); the raw node version stays visible.
        m.extra["jffs2_version"] = dec(m.version);
        if (const auto lv = w.live_version.find(d.ino); lv != w.live_version.end())
            m.version = lv->second;
        if (std::string h = holders_text(path, w); !h.empty()) m.extra["inode_history"] = h;

        if (m.kind == EntryKind::Regular) {
            emit_regular(m, p, w);
            continue;
        }
        if (m.kind == EntryKind::Directory) {
            bool loop = false;
            for (const Frame& f : stack)
                if (f.ino == d.ino) loop = true;
            if (loop) {
                diag(*w.out, Severity::Warning, kCodeDirLoop,
                     "'" + path + "' refers to ancestor directory inode " + dec(d.ino) +
                         "; not descended");
                continue;
            }
            const bool seen = w.walked_dirs.count(d.ino) != 0;
            std::vector<Diagnostic> diags;
            if (seen)
                diags.push_back({Severity::Warning, kCodeDirLoop,
                                 "'" + path + "' is a second name for directory inode " +
                                     dec(d.ino) + "; listed once, not descended again"});
            if (!emit_other(m, w, std::move(diags))) continue;
            if (seen) continue;
            w.walked_dirs.insert(d.ino);
            stack.push_back({d.ino, path, 0});
            continue;
        }
        std::vector<Diagnostic> diags;
        bool truncated = false;
        set_kind_data(m, p, w, diags, truncated);
        (void)emit_other(m, w, std::move(diags));
    }
}

// ------------------------------------------------------------------ history

// Path of directory inode `ino` for a historical entry: its live path when it
// is live, else the name its newest dirent gave it under its parent's path
// resolved the same way; "lost+found/#<ino>" when no dirent ever named it.
// Every directory met on the way up is memoized in `w.hist_dir_path`, so a
// chain of n nested deleted directories costs O(n), not O(n^2).
std::string Jffs2Reader::Impl::hist_path_of_dir(std::uint32_t ino, Walk& w) const {
    std::vector<std::pair<std::uint32_t, std::string>> chain;  // (dir inode, its name)
    std::string prefix;
    std::set<std::uint32_t> visited;
    std::uint32_t cur = ino;
    for (;;) {
        if (cur == kRootIno) break;
        const auto memo = w.hist_dir_path.find(cur);
        if (memo != w.hist_dir_path.end()) {
            prefix = memo->second;
            break;
        }
        const auto lp = w.live_path.find(cur);
        if (lp != w.live_path.end()) {
            prefix = lp->second;
            break;
        }
        if (!visited.insert(cur).second) {
            prefix = "lost+found/#" + dec(cur);  // dirent cycle
            break;
        }
        const auto it = last_dirent_of.find(cur);
        if (it == last_dirent_of.end()) {
            prefix = "lost+found/#" + dec(cur);
            break;
        }
        chain.emplace_back(cur, dirents[it->second].name);
        cur = dirents[it->second].pino;
    }
    std::string path = prefix;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        path = path.empty() ? it->second : path + "/" + it->second;
        w.hist_dir_path[it->first] = path;
    }
    return path;
}

std::string Jffs2Reader::Impl::hist_path_of(std::uint32_t ino, Walk& w, bool& orphan) const {
    orphan = false;
    const auto it = last_dirent_of.find(ino);
    if (it == last_dirent_of.end()) {
        orphan = true;
        return "lost+found/#" + dec(ino);
    }
    const DirentNode& d = dirents[it->second];
    const std::string parent = hist_path_of_dir(d.pino, w);
    return parent.empty() ? d.name : parent + "/" + d.name;
}

// Version points of one inode: counts of nodes after which a state is worth
// an entry. Consecutive data nodes that form one write (each starts where the
// previous one ended, carries the same mtime and ctime, and does not shrink
// isize) are one version: the kernel and mkfs.jffs2 split a single write into
// page-sized nodes. Every other node (an overwrite, a truncation, a
// metadata-only node, a later append) starts a new version.
std::vector<std::size_t> Jffs2Reader::Impl::version_points(
    const std::vector<std::size_t>& chain) const {
    std::vector<std::size_t> points;
    std::uint64_t extent = 0;
    const InodeNode* prev = nullptr;
    for (std::size_t k = 0; k < chain.size(); ++k) {
        const InodeNode& n = inodes[chain[k]];
        const bool same_write = prev != nullptr && n.dsize != 0 && prev->dsize != 0 &&
                                n.offset == extent && n.mtime == prev->mtime &&
                                n.ctime == prev->ctime && n.isize >= prev->isize;
        if (same_write && !points.empty()) points.pop_back();
        points.push_back(k + 1);
        if (n.dsize != 0)
            extent = std::max(extent, static_cast<std::uint64_t>(n.offset) + n.dsize);
        else if (n.isize < extent)
            extent = n.isize;
        prev = &n;
    }
    return points;
}

// The version sequence of one path. Holders are ordered by the dirent that
// bound each of them to the name when those dirents share a parent (the
// parent's dirent counter is the clock of that name: an older inode renamed
// over a younger one at this path comes last), else by inode number (JFFS2
// allocates inode numbers monotonically, so the earlier holder has the lower
// number). Then each holder's states in node order with the live state
// included, and an unlink record right after the states of the inode it
// unlinked (after every holder when that inode is unknown or held another
// path). Each point keeps its raw JFFS2 version unless an earlier point of
// the path already used that number or a higher one, in which case it takes
// the next free number: a path held by one inode keeps the numbers
// jffs2dump shows, and a second holder's versions continue after the first.
std::vector<Jffs2Reader::Impl::VersionPoint> Jffs2Reader::Impl::number_path(const PathSpace& space,
                                                                            const Walk& w) const {
    std::vector<std::uint32_t> holders = space.holders;
    {
        std::vector<std::size_t> bound;  // binding dirent per holder
        bool same_parent = !holders.empty();
        for (const std::uint32_t ino : holders) {
            std::size_t idx = static_cast<std::size_t>(-1);
            if (const auto ld = w.live_dirent.find(ino); ld != w.live_dirent.end())
                idx = ld->second;
            else if (const auto hd = last_dirent_of.find(ino); hd != last_dirent_of.end())
                idx = hd->second;
            if (idx == static_cast<std::size_t>(-1) ||
                (!bound.empty() && dirents[idx].pino != dirents[bound.front()].pino))
                same_parent = false;
            bound.push_back(idx);
        }
        if (same_parent && holders.size() > 1) {
            std::vector<std::size_t> order(holders.size());
            std::iota(order.begin(), order.end(), 0);
            std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
                const DirentNode& da = dirents[bound[a]];
                const DirentNode& db = dirents[bound[b]];
                if (da.version != db.version) return da.version < db.version;
                return da.off < db.off;
            });
            std::vector<std::uint32_t> sorted;
            for (const std::size_t i : order) sorted.push_back(holders[i]);
            holders.swap(sorted);
        }
    }
    std::map<std::uint32_t, std::uint32_t> rank;  // holder -> position in the sequence
    for (std::size_t i = 0; i < holders.size(); ++i)
        rank[holders[i]] = static_cast<std::uint32_t>(i);

    std::vector<VersionPoint> pts;
    for (const std::uint32_t ino : holders) {
        const std::vector<std::size_t> chain = chain_of(ino, true);
        if (chain.empty()) continue;
        std::vector<std::size_t> points = version_points(chain);
        std::size_t live_count = 0;
        if (w.live_path.count(ino)) {
            for (std::size_t k = 0; k < chain.size(); ++k)
                if (inodes[chain[k]].usable()) live_count = k + 1;
            // The live state is a point of its own even when it sits inside a
            // write run whose later nodes failed their CRC.
            if (live_count != 0 &&
                std::find(points.begin(), points.end(), live_count) == points.end()) {
                points.insert(std::lower_bound(points.begin(), points.end(), live_count),
                              live_count);
            }
        }
        for (const std::size_t count : points) {
            VersionPoint pt;
            pt.group = rank.at(ino);
            pt.ino = ino;
            pt.count = count;
            pt.live = count == live_count;
            pt.final = count == chain.size();
            pt.raw = inodes[chain[count - 1]].version;
            pts.push_back(pt);
        }
    }
    for (const auto& [idx, prior] : space.unlinks) {
        VersionPoint pt;
        const auto held_here = prior != 0 ? rank.find(prior) : rank.end();
        pt.group = held_here != rank.end() ? held_here->second : 0xFFFFFFFFu;
        pt.unlink = true;
        pt.dirent = idx;
        pt.raw = dirents[idx].version;
        pts.push_back(pt);
    }
    std::stable_sort(pts.begin(), pts.end(), [](const VersionPoint& a, const VersionPoint& b) {
        if (a.group != b.group) return a.group < b.group;
        if (a.unlink != b.unlink) return !a.unlink;  // an inode's states, then its unlink
        if (a.unlink) return a.raw != b.raw ? a.raw < b.raw : a.dirent < b.dirent;
        return a.count < b.count;
    });
    std::uint64_t prev = 0;
    for (VersionPoint& pt : pts) {
        pt.version = std::max<std::uint64_t>(pt.raw, prev + 1);
        prev = pt.version;
    }
    return pts;
}

// Resolve the path of every inode with nodes (live: from the dry traversal;
// otherwise from dirent history) and every explicit unlink record, group
// them by path, and fix the version each live state will carry.
void Jffs2Reader::Impl::build_version_space(Walk& w) const {
    w.spaces.clear();
    w.deleted_path.clear();
    w.live_version.clear();
    w.orphan_inos.clear();
    for (const auto& [ino, range] : ino_range) {
        (void)range;
        if (ino == kRootIno) continue;
        if (chain_of(ino, true).empty()) continue;
        const bool live = w.live_path.count(ino) != 0;
        bool orphan = false;
        const std::string path = live ? w.live_path.at(ino) : hist_path_of(ino, w, orphan);
        if (orphan) w.orphan_inos.insert(ino);
        w.spaces[path].holders.push_back(ino);  // ino_range is ascending
        if (!live) w.deleted_path[ino] = path;
    }
    // Explicit unlink records (dirent with ino 0): kept unless the inode the
    // name pointed at is emitted as deleted under this very path, so a
    // deleted file appears once, with content.
    for (const auto& [key, hist] : dirent_history) {
        (void)key;
        for (std::size_t i = 0; i < hist.size(); ++i) {
            const DirentNode& d = dirents[hist[i]];
            if (d.ino != 0) continue;
            std::uint32_t prior_ino = 0;
            for (std::size_t j = i; j-- > 0;) {
                if (dirents[hist[j]].ino != 0) {
                    prior_ino = dirents[hist[j]].ino;
                    break;
                }
            }
            const std::string parent = hist_path_of_dir(d.pino, w);
            const std::string path = parent.empty() ? d.name : parent + "/" + d.name;
            if (prior_ino != 0) {
                const auto dp = w.deleted_path.find(prior_ino);
                if (dp != w.deleted_path.end() && dp->second == path) continue;
            }
            w.spaces[path].unlinks.emplace_back(hist[i], prior_ino);
        }
    }
    for (const auto& [path, space] : w.spaces) {
        (void)path;
        for (const VersionPoint& pt : number_path(space, w))
            if (pt.live) w.live_version[pt.ino] = pt.version;
    }
}

// "429,549" when more than one inode ever held `path`, in sequence order;
// empty otherwise.
std::string Jffs2Reader::Impl::holders_text(const std::string& path, const Walk& w) const {
    const auto it = w.spaces.find(path);
    if (it == w.spaces.end() || it->second.holders.size() < 2) return {};
    std::string out;
    std::uint32_t last = 0;
    bool any = false;
    for (const VersionPoint& pt : number_path(it->second, w)) {
        if (pt.unlink || (any && pt.ino == last)) continue;
        out += (any ? "," : "") + dec(pt.ino);
        last = pt.ino;
        any = true;
    }
    return out;
}

void Jffs2Reader::Impl::walk_history(Walk& w) {
    const Limits& L = w.opts->limits;
    const std::uint64_t max_versions = std::max<std::uint64_t>(1, L.max_versions_per_entry);

    for (const auto& [path, space] : w.spaces) {
        if (w.stop) break;
        std::vector<VersionPoint> points = number_path(space, w);
        points.erase(std::remove_if(points.begin(), points.end(),
                                    [](const VersionPoint& pt) { return pt.live; }),
                     points.end());
        std::map<std::string, std::string> capnote;
        if (points.size() > max_versions) {
            const std::uint64_t dropped = points.size() - max_versions;
            points.erase(points.begin(), points.begin() + static_cast<std::ptrdiff_t>(dropped));
            w.versions_capped_paths++;
            capnote["versions_dropped"] = dec(dropped);
            // History-only cap: the live tree and the newest versions are
            // complete, so the walk is not truncated. The Warning and the
            // entry's versions_dropped say what was left out.
        }
        const std::string holders = holders_text(path, w);
        std::map<std::uint32_t, std::vector<std::size_t>> chains;
        for (std::size_t i = 0; i < points.size() && !w.stop; ++i) {
            const VersionPoint& pt = points[i];
            std::map<std::string, std::string> extra;
            if (i == points.size() - 1) extra = capnote;
            if (!holders.empty()) extra["inode_history"] = holders;
            if (pt.unlink) {
                if (!check_limits(path, w)) break;
                const DirentNode& d = dirents[pt.dirent];
                FileMeta m;
                m.path = path;
                m.kind = kind_from_dtype(d.type);
                if (m.kind == EntryKind::Unknown) m.kind = EntryKind::Regular;
                m.deleted = true;
                m.version = pt.version;
                m.mtime = static_cast<std::int64_t>(d.mctime);
                m.extra["record"] = "unlink";
                m.extra["parent_inode"] = dec(d.pino);
                m.extra["jffs2_version"] = dec(d.version);
                if (d.obsolete) m.extra["obsolete"] = "true";
                for (auto& [k, v] : extra) m.extra[k] = v;
                if (m.kind == EntryKind::Regular) {
                    emit_regular(m, Plan{}, w);
                } else {
                    (void)emit_other(m, w, {});
                }
                continue;
            }
            auto ch = chains.find(pt.ino);
            if (ch == chains.end()) ch = chains.emplace(pt.ino, chain_of(pt.ino, true)).first;
            const bool live = w.live_path.count(pt.ino) != 0;
            if (w.orphan_inos.count(pt.ino)) extra["orphan"] = "true";
            if (!live) {
                emit_state(path, ch->second, pt, /*deleted=*/true, /*superseded=*/!pt.final, 0, w,
                           extra);
            } else {
                const std::uint64_t live_v =
                    w.live_version.count(pt.ino) ? w.live_version.at(pt.ino) : 0;
                if (pt.version > live_v) extra["newer_than_live"] = "true";
                emit_state(path, ch->second, pt, /*deleted=*/false, /*superseded=*/true,
                           live_nlink.count(pt.ino) ? live_nlink.at(pt.ino) : 0, w, extra);
            }
        }
    }
    for (const std::uint32_t ino : w.orphan_inos) {
        (void)ino;
        w.orphans++;
    }

    if (w.versions_capped_paths != 0)
        diag(*w.out, Severity::Warning, kCodeLimitVersions,
             dec(w.versions_capped_paths) + " path(s) had older versions dropped (cap " +
                 dec(max_versions) + " per path, Limits::max_versions_per_entry); the newest " +
                 "were kept");
    if (w.orphans != 0)
        diag(*w.out, Severity::Info, kCodeOrphanInode,
             dec(w.orphans) +
                 " inode(s) with data but no directory entry ever naming them; "
                 "emitted under lost+found/#<inode>");
}

// ------------------------------------------------------------------ public API

Jffs2Reader::Jffs2Reader() : impl_(std::make_unique<Impl>()) {}
Jffs2Reader::~Jffs2Reader() = default;

std::string Jffs2Reader::format() const {
    return "jffs2";
}

Status Jffs2Reader::open(const Span& span) {
    Impl& im = *impl_;
    im = Impl{};
    im.span = span;
    if (span.size() < kHdrSize) return Status::fail("jffs2-no-nodes: fewer than 12 bytes");
    const Limits defaults;
    if (Status s = im.scan(defaults.max_nodes_per_fs); !s) return s;
    im.opened = true;
    return Status::success();
}

FilesystemInfo Jffs2Reader::info() const {
    const Impl& im = *impl_;
    FilesystemInfo fi;
    fi.format = "jffs2";
    if (!im.opened) return fi;
    fi.endian = im.endian;
    fi.size = im.last_node_end;
    if (im.erase_size != 0 && fi.size != 0)
        fi.size = ((fi.size + im.erase_size - 1) / im.erase_size) * im.erase_size;
    fi.block_size = static_cast<std::uint32_t>(std::min<std::uint64_t>(im.erase_size, 0xFFFFFFFFu));
    std::string codecs;
    for (const std::uint8_t c : im.compressors)
        if (c != kComprNone) codecs += (codecs.empty() ? "" : ",") + std::string(compr_name(c));
    fi.compression = codecs;
    const Counts& c = im.counts;
    fi.attrs["endian"] = endian_name(im.endian);
    fi.attrs["first_node"] = hex(im.first_node);
    fi.attrs["nodes"] = dec(c.nodes);
    fi.attrs["inode_nodes"] = dec(c.inode_nodes);
    fi.attrs["dirent_nodes"] = dec(c.dirent_nodes);
    fi.attrs["cleanmarkers"] = dec(c.cleanmarkers);
    fi.attrs["padding_nodes"] = dec(c.padding);
    fi.attrs["summary_nodes"] = dec(c.summary);
    fi.attrs["xattr_nodes"] = dec(c.xattr);
    fi.attrs["xref_nodes"] = dec(c.xref);
    fi.attrs["unknown_nodes"] = dec(c.unknown);
    fi.attrs["obsolete_nodes"] = dec(c.obsolete);
    fi.attrs["crc_failures"] = dec(c.node_crc_bad + c.data_crc_bad + c.name_crc_bad);
    fi.attrs["unlink_dirents"] = dec(c.unlinks);
    fi.attrs["erase_size"] = im.erase_size != 0 ? dec(im.erase_size) : "unknown";
    std::string all;
    for (const std::uint8_t k : im.compressors)
        all += (all.empty() ? "" : ",") + std::string(compr_name(k));
    fi.attrs["compressors"] = all;
    fi.attrs["xattr_count"] = dec(im.xrefs.size());
    fi.attrs["inodes_live"] = dec(im.live_inode_count);
    fi.attrs["inodes_deleted"] = dec(im.deleted_inode_count);
    fi.attrs["inodes_multi_version"] = dec(im.multi_version_count);
    if (im.scan_capped) fi.attrs["scan_capped"] = "true";
    return fi;
}

Status Jffs2Reader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& im = *impl_;
    if (!im.opened) return Status::fail("jffs2: walk before a successful open");
    out = WalkResult{};
    // open() scanned with the default cap; honour the caller's when it differs.
    if (opts.limits.max_nodes_per_fs != im.scan_cap) {
        if (Status s = im.scan(opts.limits.max_nodes_per_fs); !s) return s;
    }
    for (const Diagnostic& d : im.open_diags) out.diagnostics.push_back(d);
    if (im.scan_capped) out.truncated = true;
    im.lim = &opts.limits;

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;

    // Resolve every live path without emitting, number every path's states,
    // then emit. The live tree is byte-identical with and without history.
    w.dry = true;
    im.walk_live(w);
    w.dry = false;
    w.walked_dirs.clear();
    im.build_version_space(w);

    im.walk_live(w);
    if (opts.history && !w.stop) im.walk_history(w);

    if (w.unsupported_nodes != 0) {
        std::string names;
        for (const std::uint8_t c : w.unsupported_codecs)
            names += (names.empty() ? "" : ",") + std::string(compr_name(c));
        im.diag(out, Severity::Warning, kCodeUnsupportedCompression,
                dec(w.unsupported_nodes) +
                    " data node(s) use compression this reader cannot decode (" + names +
                    "); their ranges were zero-filled and the entries marked truncated");
    }
    im.lim = nullptr;  // `opts` does not outlive this call
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("jffs2", Jffs2Reader);

}  // namespace omnitrace::fs
