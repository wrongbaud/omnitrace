// UbifsReader.cpp — UBIFS reader. See UbifsReader.h and docs/formats/ubifs.md.
//
// Format knowledge: Linux fs/ubifs (ubifs-media.h, tnc.c, replay.c, journal.c)
// and the UBIFS design document, both read for understanding; nothing is
// copied. Every structure used here was checked byte for byte against the
// mkfs.ubifs fixture before this file was written.
//
// Layout. A UBIFS volume is a sequence of logical erase blocks:
//
//   LEB 0        the superblock node
//   LEB 1, 2     two copies of the master node
//   LEB 3..      the log, then the LEB properties tree, the orphan area, and
//                the main area holding index and data nodes
//
// Every node starts with a 24-byte common header: magic 0x06101831, a crc32
// over bytes 8..len (init 0xFFFFFFFF, no final xor), a global sequence number,
// the node length and its type.
//
// Pipeline:
//   open()  superblock at LEB 0, then the newest master node that verifies;
//           walk the on-flash index (a B-tree of `idx` nodes) down to its
//           leaves, which are (key -> node) references; then replay the
//           journal, whose buds hold everything written since that commit and
//           which a mount would apply before showing anything. Later writes
//           win by sqnum, which is what makes the result the tree a mount
//           would show rather than the tree the last commit froze.
//   walk()  from inode 1, directory entries in key order, file data streamed
//           block by block (holes are zeros, each block decompressed on its
//           own), symlink targets and device numbers out of the inode's
//           inline data, xattrs summarised from the xattr entries.
//
// The LEBs have to be contiguous for any of this: `lnum` maps to
// `lnum * leb_size`. A reassembled UBI volume is contiguous
// (src/containers/ubi/UbiReader.cpp); raw flash is not.
#include "UbifsReader.h"

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../../discovery/crc32.h"
#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_ubifs() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants
// Format constants (fs/ubifs/ubifs-media.h); not tunable limits.
constexpr std::uint32_t kNodeMagic = 0x06101831u;
constexpr std::uint64_t kChSize = 24;  // common header
constexpr std::uint64_t kSbNodeSize = 4096;
constexpr std::uint64_t kMstNodeSize = 512;
constexpr std::uint64_t kInoNodeSize = 160;
constexpr std::uint64_t kDentNodeSize = 56;
constexpr std::uint64_t kDataNodeSize = 48;
constexpr std::uint64_t kBranchSize = 12;  // plus the key
constexpr std::uint64_t kKeyLen = 8;       // UBIFS_SK_LEN, the simple key format
constexpr std::uint64_t kBlockSize = 4096;
constexpr std::uint32_t kRootIno = 1;
constexpr std::uint32_t kMstLnum = 1, kLogLnum = 3;
constexpr std::uint64_t kMaxNameLen = 255;  // UBIFS_MAX_NLEN

// Node types.
constexpr std::uint8_t kIno = 0, kDataNode = 1, kDent = 2, kXent = 3, kPad = 5, kSb = 6, kMst = 7,
                       kRef = 8, kIdx = 9, kCs = 10;
// Key types, the top three bits of the key's second word.
constexpr std::uint32_t kKeyIno = 0, kKeyData = 1, kKeyDent = 2, kKeyXent = 3;
constexpr unsigned kKeyTypeShift = 29;  // UBIFS_S_KEY_BLOCK_BITS
constexpr std::uint32_t kKeyBlockMask = (1u << kKeyTypeShift) - 1;
// Directory entry types (UBIFS_ITYPE_*).
constexpr std::uint8_t kItReg = 0, kItDir = 1, kItLnk = 2, kItBlk = 3, kItChr = 4, kItFifo = 5,
                       kItSock = 6;
// Compression types (UBIFS_COMPR_*).
constexpr std::uint16_t kComprNone = 0, kComprLzo = 1, kComprZlib = 2, kComprZstd = 3;

// Bounds. The index is attacker-controlled data: a crafted tree can point a
// branch back at its own parent, and the visited set below stops the cycle,
// but a merely enormous tree still has to terminate.
constexpr std::uint64_t kMaxIndexNodes = 1u << 22;
// The history sweep reads every erase block looking for nodes, so both the
// node count and the read size need a bound.
constexpr std::uint64_t kMaxHistoryNodes = 1u << 22;
constexpr std::uint64_t kSweepChunk = 1u << 20;
constexpr std::uint64_t kMaxDepth = 512;
constexpr std::uint64_t kMaxSymlinkTarget = 4096;
// The largest LEB any real producer makes is well under this; it bounds the
// per-node read.
constexpr std::uint64_t kMaxLebSize = 1u << 26;

// Diagnostic codes; literal so scripts/gen_docs.py can catalogue them.
constexpr const char* kCodeBadIndex = "ubifs-bad-index";
constexpr const char* kCodeBadNode = "ubifs-bad-node";
constexpr const char* kCodeDecompress = "ubifs-decompress-failed";
constexpr const char* kCodeNoInode = "ubifs-missing-inode";
constexpr const char* kCodeJournal = "ubifs-journal-unreplayed";
constexpr const char* kCodeLimitNodes = "ubifs-limit-nodes";
constexpr const char* kCodeLoop = "ubifs-directory-loop";
constexpr const char* kCodeSinkError = "ubifs-sink-error";
constexpr const char* kCodeShortFile = "ubifs-missing-block";
constexpr const char* kCodeLimitHistory = "ubifs-limit-history-nodes";
constexpr const char* kCodeHistoryScan = "ubifs-history-scan";
constexpr const char* kCodeUnresolvedDelete = "ubifs-deleted-unresolved";

// `cutoff` for a live read: no node is newer than this.
constexpr std::uint64_t kLive = UINT64_MAX;

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

// A reference to a node on the medium. Leaf bodies are read when they are
// needed, not held: a volume can hold hundreds of thousands of data nodes.
struct Ref {
    std::uint32_t lnum = 0, offs = 0, len = 0;
    std::uint64_t sqnum = 0;
};

// One directory entry, as its `dent` node records it.
struct Dent {
    std::string name;
    std::uint64_t inum = 0;  // 0 in the deletion record UBIFS writes on unlink
    std::uint8_t type = 0;
    std::uint64_t sqnum = 0;
    std::uint32_t lnum = 0, offs = 0;  // where the node is, for the history pass
};

// A node read off the medium, header decoded.
struct Node {
    std::uint64_t sqnum = 0;
    std::uint32_t len = 0;
    std::uint8_t type = 0;
    bool crc_ok = false;
    std::vector<std::uint8_t> raw;  // the whole node, header included

    std::uint32_t u32(std::size_t at) const {
        return at + 4 <= raw.size() ? load_int<std::uint32_t>(raw.data() + at, Endian::Little) : 0;
    }
    std::uint16_t u16(std::size_t at) const {
        return at + 2 <= raw.size() ? load_int<std::uint16_t>(raw.data() + at, Endian::Little) : 0;
    }
    std::uint64_t u64(std::size_t at) const {
        return at + 8 <= raw.size() ? load_int<std::uint64_t>(raw.data() + at, Endian::Little) : 0;
    }
    std::uint8_t u8(std::size_t at) const { return at < raw.size() ? raw[at] : 0; }
};

// The two words of a key: which inode, and what about it.
struct Key {
    std::uint32_t inum = 0;
    std::uint32_t type = 0;
    std::uint32_t block = 0;  // block number for data, name hash for entries
};

Key key_at(const Node& n, std::size_t at) {
    Key k;
    k.inum = n.u32(at);
    const std::uint32_t w = n.u32(at + 4);
    k.type = w >> kKeyTypeShift;
    k.block = w & kKeyBlockMask;
    return k;
}

// The format fixes a minimum length per node type, and a node shorter than
// its own structure cannot be read. mkfs.ubifs leaves a 64-byte node of type
// 0 after the superblock in LEB 0, which is 96 bytes short of an inode node;
// without this screen the history sweep takes it for inode 0.
bool node_is_whole(const Node& n) {
    switch (n.type) {
        case kIno:
            return n.len >= kInoNodeSize;
        case kDent:
        case kXent:
            return n.len > kDentNodeSize;  // plus at least one byte of name
        case kDataNode:
            return n.len >= kDataNodeSize;
        default:
            return true;
    }
}

std::uint64_t align8(std::uint64_t v) {
    return v > UINT64_MAX - 7 ? v : (v + 7) & ~std::uint64_t{7};
}

// How far past a padding node the next one starts. The node is 28 bytes and
// `pad_len` more zero bytes follow it, and the whole run is what gets skipped:
// the padding fills out a minimum-I/O unit, so rounding the node's own length
// up first would land 8 bytes past the boundary and miss the node there.
std::uint64_t pad_advance(const Node& n) {
    return align8(static_cast<std::uint64_t>(n.len) + n.u32(kChSize));
}

const char* compr_name(std::uint16_t v) {
    switch (v) {
        case kComprNone:
            return "none";
        case kComprLzo:
            return "lzo";
        case kComprZlib:
            return "zlib";
        case kComprZstd:
            return "zstd";
        default:
            return "unknown";
    }
}

EntryKind kind_of(std::uint8_t itype) {
    switch (itype) {
        case kItDir:
            return EntryKind::Directory;
        case kItLnk:
            return EntryKind::Symlink;
        case kItBlk:
            return EntryKind::BlockDevice;
        case kItChr:
            return EntryKind::CharDevice;
        case kItFifo:
            return EntryKind::Fifo;
        case kItSock:
            return EntryKind::Socket;
        case kItReg:
        default:
            return EntryKind::Regular;
    }
}

}  // namespace

// ------------------------------------------------------------------ Impl

struct UbifsReader::Impl {
    Span span;
    bool opened = false;

    // Superblock.
    std::uint32_t min_io = 0, leb_size = 0, leb_cnt = 0, max_leb_cnt = 0, log_lebs = 0,
                  lpt_lebs = 0, orph_lebs = 0, jhead_cnt = 0, fanout = 0, fmt_version = 0,
                  ro_compat = 0;
    std::uint16_t default_compr = 0;
    std::string uuid;
    // Master node.
    std::uint64_t cmt_no = 0, highest_inum = 0, index_size = 0;
    std::uint32_t root_lnum = 0, root_offs = 0, root_len = 0, log_lnum = 0;

    // What the index and the journal add up to.
    std::map<std::uint32_t, Ref> inodes;
    std::map<std::pair<std::uint32_t, std::string>, Dent> dents;  // (parent, name)
    std::map<std::pair<std::uint32_t, std::uint32_t>, Ref> blocks;  // (inum, block)
    std::map<std::uint32_t, std::vector<Dent>> xattrs;              // inum -> entries
    std::uint64_t index_nodes = 0, leaf_count = 0, replayed_nodes = 0, bud_lebs = 0;
    std::uint64_t bad_nodes = 0, unlinked_dents = 0;
    std::string index_problem, journal_problem;

    // History. UBIFS never overwrites in place: a node stays where it was
    // written until garbage collection reclaims its erase block, so the older
    // states of a file, and the inodes and blocks of a deleted one, are still
    // on the medium. These are filled by a sweep of every erase block under
    // WalkOptions::history and hold *every* version, the live one included.
    std::map<std::uint32_t, std::vector<Ref>> ino_versions;
    std::map<std::pair<std::uint32_t, std::uint32_t>, std::vector<Ref>> block_versions;
    std::map<std::pair<std::uint32_t, std::string>, std::vector<Dent>> dent_versions;
    std::uint64_t swept_nodes = 0, unresolved_deletes = 0;
    bool sweep_hit_limit = false;

    // Per-walk state.
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        std::vector<std::uint8_t> block, decoded, zeros;
        std::set<std::uint32_t> on_path;   // directory loop guard
        std::set<std::uint32_t> seen_ino;  // for the hard-link count
        // Where the live tree put each inode, so the history pass can name a
        // superseded version and put a deleted name under its parent.
        std::map<std::uint32_t, std::string> live_path;
        bool stop = false;
    };

    std::uint64_t leb_at(std::uint32_t lnum) const {
        return static_cast<std::uint64_t>(lnum) * leb_size;
    }
    bool read_node(std::uint32_t lnum, std::uint32_t offs, Node& out,
                   std::uint32_t want_len = 0) const;
    bool walk_index(std::uint32_t root_ln, std::uint32_t root_off,
                    std::uint32_t root_length);
    void note_leaf(const Key& k, const Ref& r, const Node& n);
    void replay_journal();
    void replay_bud(std::uint32_t lnum, std::uint32_t offs);

    void emit_tree(std::uint32_t inum, const std::string& prefix, unsigned depth, Walk& w);
    void emit_entry(const std::string& path, const Dent& d, Walk& w);
    bool stream_file(const std::string& path, std::uint32_t inum, std::uint64_t size,
                     std::uint64_t cutoff, Walk& w, bool& truncated,
                     std::vector<Diagnostic>& diags);

    // History.
    void sweep_for_nodes();
    void note_version(const Key& k, const Ref& r, const Node& n);
    const Ref* block_at(std::uint32_t inum, std::uint32_t block, std::uint64_t cutoff) const;
    void emit_history(Walk& w);
    void emit_state(const std::string& path, std::uint32_t inum, const Ref& ino_ref,
                    std::uint64_t cutoff, bool deleted, bool superseded, std::uint64_t version,
                    Walk& w, std::map<std::string, std::string> extra);
    std::vector<std::uint8_t> inline_data(const Node& ino) const;
    std::string xattr_summary(std::uint32_t inum) const;
    bool block_data(const Ref& r, std::vector<std::uint8_t>& out, std::string& why,
                    const char*& code) const;

    void count_entry(WalkResult& out, const FileMeta& m) const {
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
    }
    void diag(WalkResult& out, Severity s, const char* code, std::string msg) const {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }
};

// ------------------------------------------------------------------ nodes

// Read the node at (lnum, offs). Rejects anything whose header is not a node
// or whose length does not fit inside its own erase block, so a corrupt
// branch cannot make the reader read across a LEB boundary.
bool UbifsReader::Impl::read_node(std::uint32_t lnum, std::uint32_t offs, Node& out,
                                  std::uint32_t want_len) const {
    out.raw.clear();
    out.crc_ok = false;
    if (lnum >= leb_cnt || offs + kChSize > leb_size) return false;
    const std::uint64_t at = leb_at(lnum) + offs;
    std::array<std::uint8_t, kChSize> ch{};
    if (span.read(at, std::span<std::uint8_t>(ch.data(), ch.size())) != ch.size()) return false;
    if (load_int<std::uint32_t>(ch.data(), Endian::Little) != kNodeMagic) return false;
    const std::uint32_t crc = load_int<std::uint32_t>(ch.data() + 4, Endian::Little);
    out.sqnum = load_int<std::uint64_t>(ch.data() + 8, Endian::Little);
    out.len = load_int<std::uint32_t>(ch.data() + 16, Endian::Little);
    out.type = ch[20];
    if (out.len < kChSize || out.len > leb_size - offs) return false;
    if (want_len != 0 && out.len != want_len) return false;
    const auto body = span.bytes(at, out.len);
    if (!body) return false;
    out.raw = *body;
    out.crc_ok = discovery::crc32_ubi(std::span<const std::uint8_t>(out.raw.data() + 8,
                                                                    out.len - 8)) == crc;
    return true;
}

// ------------------------------------------------------------------ index

void UbifsReader::Impl::note_leaf(const Key& k, const Ref& r, const Node& n) {
    switch (k.type) {
        case kKeyIno: {
            const auto it = inodes.find(k.inum);
            if (it == inodes.end() || r.sqnum > it->second.sqnum) inodes[k.inum] = r;
            break;
        }
        case kKeyData: {
            const auto key = std::make_pair(k.inum, k.block);
            const auto it = blocks.find(key);
            if (it == blocks.end() || r.sqnum > it->second.sqnum) blocks[key] = r;
            break;
        }
        case kKeyDent:
        case kKeyXent: {
            const std::uint64_t nlen = n.u16(50);
            if (nlen == 0 || nlen > kMaxNameLen || kDentNodeSize + nlen > n.raw.size()) {
                ++bad_nodes;
                return;
            }
            Dent d;
            d.name.assign(reinterpret_cast<const char*>(n.raw.data()) + kDentNodeSize,
                          static_cast<std::size_t>(nlen));
            d.inum = n.u64(40);
            d.type = n.u8(49);
            d.sqnum = r.sqnum;
            if (k.type == kKeyXent) {
                std::vector<Dent>& list = xattrs[k.inum];
                for (Dent& x : list) {
                    if (x.name != d.name) continue;
                    if (d.sqnum > x.sqnum) x = std::move(d);
                    return;
                }
                if (d.inum != 0) list.push_back(std::move(d));
                return;
            }
            const auto key = std::make_pair(k.inum, d.name);
            const auto it = dents.find(key);
            if (it != dents.end() && d.sqnum <= it->second.sqnum) return;
            if (d.inum == 0) {
                // UBIFS unlinks by writing an entry that points at inode 0.
                // It is a deletion record, not a name.
                ++unlinked_dents;
                dents.erase(key);
                return;
            }
            dents[key] = std::move(d);
            break;
        }
        default:
            ++bad_nodes;
            break;
    }
}

// Depth-first walk of the on-flash index, collecting the leaves. `visited`
// stops a branch that points back into the tree from looping; the node budget
// stops one that is merely vast.
bool UbifsReader::Impl::walk_index(std::uint32_t root_ln, std::uint32_t root_off,
                                   std::uint32_t root_length) {
    struct Frame {
        std::uint32_t lnum, offs, len;
        unsigned depth;
    };
    std::vector<Frame> stack{{root_ln, root_off, root_length, 0}};
    std::set<std::pair<std::uint32_t, std::uint32_t>> visited;
    Node idx, leaf;
    while (!stack.empty()) {
        const Frame f = stack.back();
        stack.pop_back();
        if (f.depth > kMaxDepth) {
            index_problem = "the index is deeper than " + dec(kMaxDepth) + " levels";
            return false;
        }
        if (!visited.insert({f.lnum, f.offs}).second) continue;
        if (++index_nodes > kMaxIndexNodes) {
            index_problem = "the index has more than " + dec(kMaxIndexNodes) + " nodes";
            return false;
        }
        if (!read_node(f.lnum, f.offs, idx, f.len) || idx.type != kIdx) {
            if (index_problem.empty())
                index_problem = "no index node at LEB " + dec(f.lnum) + " offset " + dec(f.offs);
            ++bad_nodes;
            continue;
        }
        if (!idx.crc_ok) ++bad_nodes;
        const std::uint32_t child_cnt = idx.u16(24);
        const std::uint32_t level = idx.u16(26);
        const std::uint64_t branch = kBranchSize + kKeyLen;
        if (kChSize + 4 + child_cnt * branch > idx.raw.size()) {
            ++bad_nodes;
            continue;
        }
        for (std::uint32_t i = 0; i < child_cnt; ++i) {
            const std::size_t b = static_cast<std::size_t>(kChSize + 4 + i * branch);
            Ref r;
            r.lnum = idx.u32(b);
            r.offs = idx.u32(b + 4);
            r.len = idx.u32(b + 8);
            if (level > 0) {
                stack.push_back({r.lnum, r.offs, r.len, f.depth + 1});
                continue;
            }
            if (!read_node(r.lnum, r.offs, leaf, r.len)) {
                ++bad_nodes;
                continue;
            }
            if (!node_is_whole(leaf)) {
                ++bad_nodes;
                continue;
            }
            r.sqnum = leaf.sqnum;
            ++leaf_count;
            note_leaf(key_at(leaf, kChSize), r, leaf);
        }
    }
    return true;
}

// ------------------------------------------------------------------ journal

// Everything written since the last commit is in the buds, not the index. A
// mount replays them before showing anything, so a reader that skips this
// shows the filesystem as it was at the last commit, not as it is.
void UbifsReader::Impl::replay_journal() {
    if (log_lebs == 0 || log_lnum < kLogLnum || log_lnum >= kLogLnum + log_lebs) {
        journal_problem = "the master node's log head (LEB " + dec(log_lnum) +
                          ") is outside the log area";
        return;
    }
    Node n;
    // The log head holds a commit-start node for this commit; the reference
    // nodes after it name the buds.
    if (!read_node(log_lnum, 0, n) || n.type != kCs) {
        journal_problem = "LEB " + dec(log_lnum) + " does not start with a commit-start node";
        return;
    }
    if (n.u64(kChSize) != cmt_no) {
        journal_problem = "the commit-start node in LEB " + dec(log_lnum) + " is for commit " +
                          dec(n.u64(kChSize)) + ", not the master node's " + dec(cmt_no);
        return;
    }
    std::uint32_t lnum = log_lnum;
    std::uint64_t offs = align8(n.len);
    for (std::uint64_t leb = 0; leb < log_lebs; ++leb) {
        while (offs + kChSize <= leb_size) {
            if (!read_node(lnum, static_cast<std::uint32_t>(offs), n)) break;
            if (n.type == kPad) {
                offs += pad_advance(n);
                continue;
            }
            if (n.type != kRef) break;  // a second commit-start ends this one's log
            if (n.crc_ok) replay_bud(n.u32(kChSize), n.u32(kChSize + 4));
            offs += align8(n.len);
        }
        lnum = kLogLnum + static_cast<std::uint32_t>((lnum - kLogLnum + 1) % log_lebs);
        offs = 0;
        if (lnum == log_lnum) break;
    }
}

// Scan one bud from where its reference node says it starts. The nodes are
// written back to back and end where the erase block's data ends, so the scan
// stops at the first thing that is not a node.
void UbifsReader::Impl::replay_bud(std::uint32_t lnum, std::uint32_t offs) {
    if (lnum >= leb_cnt) return;
    ++bud_lebs;
    Node n;
    std::uint64_t at = offs;
    while (at + kChSize <= leb_size) {
        if (!read_node(lnum, static_cast<std::uint32_t>(at), n)) break;
        if (n.type == kPad) {
            at += pad_advance(n);
            continue;
        }
        if (!n.crc_ok) {
            // A torn write at the head of a bud: everything after it was
            // never completed either.
            ++bad_nodes;
            break;
        }
        if ((n.type == kIno || n.type == kDataNode || n.type == kDent || n.type == kXent) &&
            node_is_whole(n)) {
            Ref r;
            r.lnum = lnum;
            r.offs = static_cast<std::uint32_t>(at);
            r.len = n.len;
            r.sqnum = n.sqnum;
            ++replayed_nodes;
            note_leaf(key_at(n, kChSize), r, n);
        }
        at += align8(n.len);
    }
}

// ------------------------------------------------------------------ history

void UbifsReader::Impl::note_version(const Key& k, const Ref& r, const Node& n) {
    switch (k.type) {
        case kKeyIno:
            ino_versions[k.inum].push_back(r);
            break;
        case kKeyData:
            block_versions[{k.inum, k.block}].push_back(r);
            break;
        case kKeyDent: {
            const std::uint64_t nlen = n.u16(50);
            if (nlen == 0 || nlen > kMaxNameLen || kDentNodeSize + nlen > n.raw.size()) return;
            Dent d;
            d.name.assign(reinterpret_cast<const char*>(n.raw.data()) + kDentNodeSize,
                          static_cast<std::size_t>(nlen));
            d.inum = n.u64(40);
            d.type = n.u8(49);
            d.sqnum = r.sqnum;
            d.lnum = r.lnum;
            d.offs = r.offs;
            dent_versions[{k.inum, d.name}].push_back(std::move(d));
            break;
        }
        default:
            break;  // xattr entries are summarised from the live tree only
    }
}

// Every node still on the medium, not just the ones the index and the journal
// point at. A sequential scan would miss what sits in the tail of an erase
// block that was partly reused, so this sweeps for the node magic at every
// 8-byte boundary and lets the CRC decide -- the same argument the JFFS2
// reader makes, and the reason a deleted file is recoverable at all.
void UbifsReader::Impl::sweep_for_nodes() {
    // walk() may be called more than once on the same reader, and these hold
    // every node on the medium: appending to them twice would emit every
    // historical state twice.
    ino_versions.clear();
    block_versions.clear();
    dent_versions.clear();
    swept_nodes = 0;
    unresolved_deletes = 0;
    sweep_hit_limit = false;

    std::vector<std::uint8_t> buf;
    Node n;
    for (std::uint32_t lnum = 0; lnum < leb_cnt && !sweep_hit_limit; ++lnum) {
        const std::uint64_t base = leb_at(lnum);
        for (std::uint64_t off = 0; off + kChSize <= leb_size;) {
            const std::size_t want = static_cast<std::size_t>(
                std::min<std::uint64_t>(kSweepChunk, leb_size - off));
            const std::uint8_t* p = nullptr;
            if (const auto v = span.view(base + off, want)) {
                p = v->data();
            } else {
                buf.resize(want);
                if (span.read(base + off, std::span<std::uint8_t>(buf.data(), want)) != want) break;
                p = buf.data();
            }
            // Only an 8-aligned offset can start a node: UBIFS pads every one
            // to 8, so this is a scan of the candidates, not of every byte.
            for (std::size_t i = 0; i + 4 <= want; i += 8) {
                if (load_int<std::uint32_t>(p + i, Endian::Little) != kNodeMagic) continue;
                const std::uint64_t at = off + i;
                if (!read_node(lnum, static_cast<std::uint32_t>(at), n) || !n.crc_ok) continue;
                if (n.type != kIno && n.type != kDataNode && n.type != kDent) continue;
                if (!node_is_whole(n)) continue;
                if (++swept_nodes > kMaxHistoryNodes) {
                    sweep_hit_limit = true;
                    return;
                }
                Ref r;
                r.lnum = lnum;
                r.offs = static_cast<std::uint32_t>(at);
                r.len = n.len;
                r.sqnum = n.sqnum;
                note_version(key_at(n, kChSize), r, n);
            }
            if (want < kSweepChunk) break;
            off += want;
        }
    }
}

// One state of one inode: the metadata that inode node recorded, and the
// content its blocks held at that point.
void UbifsReader::Impl::emit_state(const std::string& path, std::uint32_t inum,
                                   const Ref& ino_ref, std::uint64_t cutoff, bool deleted,
                                   bool superseded, std::uint64_t version, Walk& w,
                                   std::map<std::string, std::string> extra) {
    Node n;
    if (!read_node(ino_ref.lnum, ino_ref.offs, n, ino_ref.len) || n.type != kIno) return;

    FileMeta m;
    m.path = path;
    m.inode = inum;
    m.deleted = deleted;
    m.superseded = superseded;
    m.version = version;
    const std::uint32_t mode = n.u32(104);
    m.mode = mode & 0xFFFFu;
    m.kind = EntryKind::Regular;
    switch (mode & 0170000u) {
        case 0040000u:
            m.kind = EntryKind::Directory;
            break;
        case 0120000u:
            m.kind = EntryKind::Symlink;
            break;
        case 0060000u:
            m.kind = EntryKind::BlockDevice;
            break;
        case 0020000u:
            m.kind = EntryKind::CharDevice;
            break;
        case 0010000u:
            m.kind = EntryKind::Fifo;
            break;
        case 0140000u:
            m.kind = EntryKind::Socket;
            break;
        default:
            break;
    }
    const std::uint64_t size = n.u64(48);
    m.size = size;
    m.uid = n.u32(96);
    m.gid = n.u32(100);
    m.nlink = n.u32(92);
    m.atime = static_cast<std::int64_t>(n.u64(56));
    m.ctime = static_cast<std::int64_t>(n.u64(64));
    m.mtime = static_cast<std::int64_t>(n.u64(72));
    m.atime_nsec = n.u32(80);
    m.ctime_nsec = n.u32(84);
    m.mtime_nsec = n.u32(88);
    for (auto& [k, v] : extra) m.extra[k] = std::move(v);
    m.extra["sqnum"] = dec(ino_ref.sqnum);
    m.extra["node_offset"] = dec(leb_at(ino_ref.lnum) + ino_ref.offs);
    if (m.kind == EntryKind::Symlink) {
        std::vector<std::uint8_t> t = inline_data(n);
        if (t.size() > kMaxSymlinkTarget) t.resize(static_cast<std::size_t>(kMaxSymlinkTarget));
        m.link_target.assign(t.begin(), t.end());
        m.size = t.size();
    }

    std::vector<Diagnostic> diags;
    bool truncated = false;
    if (m.kind == EntryKind::Regular) {
        if (const Status st = w.sink->begin_file(m); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            return;
        }
        bool sink_ok = true;
        if (w.opts->extract_data)
            sink_ok = stream_file(path, inum, size, cutoff, w, truncated, diags);
        EntryResult r;
        if (const Status st = w.sink->end_file(r); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            if (r.meta.path.empty()) return;
        }
        if (!sink_ok || truncated) r.truncated = true;
        for (Diagnostic& dg : diags) r.diagnostics.push_back(std::move(dg));
        w.out->bytes += r.digests.bytes;
        count_entry(*w.out, r.meta);
        if (deleted) ++w.out->deleted;
        if (superseded) ++w.out->superseded;
        w.out->entries_out.push_back(std::move(r));
        return;
    }
    EntryResult r;
    if (const Status st = w.sink->entry(m, r); !st) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
        return;
    }
    count_entry(*w.out, r.meta);
    if (deleted) ++w.out->deleted;
    if (superseded) ++w.out->superseded;
    w.out->entries_out.push_back(std::move(r));
}

namespace {

// One historical entry, before its version number is known.
struct Historical {
    std::string path;
    std::uint32_t inum = 0;
    Ref ino_ref;
    bool deleted = false;
    bool superseded = false;
    std::map<std::string, std::string> extra;
};

}  // namespace

void UbifsReader::Impl::emit_history(Walk& w) {
    sweep_for_nodes();
    auto by_sqnum = [](const Ref& a, const Ref& b) { return a.sqnum < b.sqnum; };
    for (auto& [inum, v] : ino_versions) std::sort(v.begin(), v.end(), by_sqnum);
    for (auto& [k, v] : block_versions) std::sort(v.begin(), v.end(), by_sqnum);
    for (auto& [k, v] : dent_versions) {
        std::sort(v.begin(), v.end(),
                  [](const Dent& a, const Dent& b) { return a.sqnum < b.sqnum; });
    }

    std::vector<Historical> work;
    std::set<std::uint32_t> recovered;

    // Every state of `inum` up to `cutoff`, newest last. The newest of them
    // is the state the file was in at that moment; the rest are its past.
    auto states_up_to = [&](std::uint32_t inum, std::uint64_t cutoff) {
        std::vector<Ref> out;
        const auto it = ino_versions.find(inum);
        if (it == ino_versions.end()) return out;
        for (const Ref& r : it->second) {
            if (r.sqnum > cutoff) break;
            out.push_back(r);
        }
        return out;
    };

    // Deleted names. UBIFS unlinks by writing an entry that points at inode
    // 0, so a name whose newest entry does that is gone -- and the inode and
    // the blocks the entry before it named are still where they were written.
    for (const auto& [key, versions] : dent_versions) {
        if (versions.empty() || versions.back().inum != 0) continue;
        const Dent& unlink = versions.back();
        const Dent* named = nullptr;
        for (auto it = versions.rbegin(); it != versions.rend(); ++it) {
            if (it->inum != 0 && it->sqnum < unlink.sqnum) {
                named = &*it;
                break;
            }
        }
        const auto parent = w.live_path.find(key.first);
        const auto inum = named == nullptr ? 0u : static_cast<std::uint32_t>(named->inum);
        const std::vector<Ref> states = states_up_to(inum, unlink.sqnum);
        if (named == nullptr || parent == w.live_path.end() || states.empty()) {
            // Either the entry it removed is no longer on the medium, or the
            // directory that held it is itself gone. The name is still
            // evidence, so say so rather than dropping it in silence.
            ++unresolved_deletes;
            diag(*w.out, Severity::Info, kCodeUnresolvedDelete,
                 "an unlink record for '" + sanitize_utf8(key.second) + "' in inode " +
                     dec(key.first) + " could not be resolved to " +
                     (named == nullptr ? "the entry it removed"
                                       : (states.empty() ? "an inode still on the medium"
                                                         : "a path")));
            continue;
        }
        recovered.insert(inum);
        const std::string path =
            parent->second.empty() ? named->name : parent->second + "/" + named->name;
        for (std::size_t i = 0; i < states.size(); ++i) {
            Historical h;
            h.path = path;
            h.inum = inum;
            h.ino_ref = states[i];
            h.deleted = true;
            h.superseded = i + 1 < states.size();
            h.extra["unlink_sqnum"] = dec(unlink.sqnum);
            h.extra["unlink_node_offset"] = dec(leb_at(unlink.lnum) + unlink.offs);
            work.push_back(std::move(h));
        }
    }

    // Earlier states of what is still there.
    for (const auto& [inum, path] : w.live_path) {
        const auto it = ino_versions.find(inum);
        if (it == ino_versions.end() || it->second.size() < 2) continue;
        const auto live = inodes.find(inum);
        for (const Ref& r : it->second) {
            if (live != inodes.end() && r.lnum == live->second.lnum &&
                r.offs == live->second.offs)
                continue;  // the state the live tree already shows
            Historical h;
            h.path = path;
            h.inum = inum;
            h.ino_ref = r;
            h.superseded = true;
            if (live != inodes.end() && r.sqnum > live->second.sqnum) {
                // Written after the state the index and the journal agree on,
                // so it was never committed: an interrupted write, not a past.
                h.extra["newer_than_live"] = "true";
            }
            work.push_back(std::move(h));
        }
    }

    // Inodes with nodes but no name anywhere: an unlink whose directory entry
    // has already been reclaimed, or a file unlinked while still open. The
    // content is recoverable even though the name is not, and lost+found is
    // where a reader puts what it could not name.
    for (const auto& [inum, versions] : ino_versions) {
        if (versions.empty() || inum == kRootIno || inum == 0) continue;
        if (w.live_path.count(inum) != 0 || recovered.count(inum) != 0) continue;
        for (std::size_t i = 0; i < versions.size(); ++i) {
            Historical h;
            h.path = "lost+found/#" + dec(inum);
            h.inum = inum;
            h.ino_ref = versions[i];
            h.deleted = true;
            h.superseded = i + 1 < versions.size();
            h.extra["name_lost"] = "true";
            work.push_back(std::move(h));
        }
    }

    // Version numbers are path-scoped and start at 1, oldest first, so
    // (path, version) is unique and DiskSink's .omnitrace-versions/<path>/v<n>
    // never collides. The live entry keeps 0, which is what makes the live
    // tree byte-identical with and without --history.
    std::sort(work.begin(), work.end(), [](const Historical& a, const Historical& b) {
        return a.path != b.path ? a.path < b.path : a.ino_ref.sqnum < b.ino_ref.sqnum;
    });
    std::map<std::string, std::uint64_t> version;
    for (Historical& h : work) {
        if (w.stop) break;
        if (w.out->entries >= w.opts->limits.max_nodes_per_fs) {
            diag(*w.out, Severity::Warning, kCodeLimitNodes,
                 "the entry limit (" + dec(w.opts->limits.max_nodes_per_fs) +
                     ") stopped the history pass");
            w.out->truncated = true;
            w.stop = true;
            break;
        }
        emit_state(h.path, h.inum, h.ino_ref, h.ino_ref.sqnum, h.deleted, h.superseded,
                   ++version[h.path], w, std::move(h.extra));
    }

    // analyze() reads info() before the walk, so what the sweep found cannot
    // go in the node's attrs; it goes on the record here instead.
    diag(*w.out, Severity::Info, kCodeHistoryScan,
         dec(swept_nodes) + " node(s) still on the medium; " + dec(w.out->superseded) +
             " superseded and " + dec(w.out->deleted) + " deleted entr(ies) recovered");
    if (sweep_hit_limit) {
        diag(*w.out, Severity::Warning, kCodeLimitHistory,
             "the history sweep stopped after " + dec(kMaxHistoryNodes) +
                 " nodes; older states beyond that point were not recovered");
        w.out->truncated = true;
    }
}

// ------------------------------------------------------------------ open

UbifsReader::UbifsReader() : impl_(std::make_unique<Impl>()) {}
UbifsReader::~UbifsReader() = default;

std::string UbifsReader::format() const {
    return "ubifs";
}

Status UbifsReader::open(const Span& span) {
    Impl& m = *impl_;
    m = Impl{};
    m.span = span;

    // Superblock: the first node of LEB 0.
    std::array<std::uint8_t, kSbNodeSize> sb{};
    if (span.read(0, std::span<std::uint8_t>(sb.data(), sb.size())) != sb.size())
        return Status::fail("ubifs-truncated: fewer than 4096 bytes for the superblock node");
    auto u32 = [&](std::size_t o) { return load_int<std::uint32_t>(sb.data() + o, Endian::Little); };
    if (u32(0) != kNodeMagic)
        return Status::fail("ubifs-bad-magic: no UBIFS node magic at offset 0");
    if (sb[20] != kSb || u32(16) != kSbNodeSize)
        return Status::fail("ubifs-bad-magic: the first node of LEB 0 is not a superblock node");
    if (discovery::crc32_ubi(std::span<const std::uint8_t>(sb.data() + 8, kSbNodeSize - 8)) !=
        u32(4))
        return Status::fail("ubifs-bad-superblock: the superblock node's CRC does not match");

    m.min_io = u32(32);
    m.leb_size = u32(36);
    m.leb_cnt = u32(40);
    m.max_leb_cnt = u32(44);
    m.log_lebs = u32(56);
    m.lpt_lebs = u32(60);
    m.orph_lebs = u32(64);
    m.jhead_cnt = u32(68);
    m.fanout = u32(72);
    m.fmt_version = u32(80);
    m.default_compr = load_int<std::uint16_t>(sb.data() + 84, Endian::Little);
    m.ro_compat = u32(124);
    {
        static const char* kHex = "0123456789abcdef";
        for (std::size_t i = 0; i < 16; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) m.uuid.push_back('-');
            m.uuid.push_back(kHex[sb[108 + i] >> 4]);
            m.uuid.push_back(kHex[sb[108 + i] & 0xF]);
        }
    }
    if (m.leb_size < kSbNodeSize || m.leb_size > kMaxLebSize || m.min_io == 0 ||
        (m.leb_size % m.min_io) != 0)
        return Status::fail("ubifs-bad-superblock: the erase-block or I/O size is not usable");
    if (m.leb_cnt < 4 || m.leb_cnt > m.max_leb_cnt)
        return Status::fail("ubifs-bad-superblock: the erase-block count is out of range");
    // The LEBs have to be where lnum says they are. On raw flash they are not:
    // that is a UBI image, and the UBI reader hands over a volume where they
    // are (docs/formats/ubi.md).
    if (span.size() < static_cast<std::uint64_t>(m.leb_cnt) * m.leb_size)
        return Status::fail("ubifs-truncated: the volume is shorter than the " + dec(m.leb_cnt) +
                            " erase blocks the superblock claims");

    // Master node: two copies, in LEB 1 and LEB 2. Take the newest that
    // verifies -- a torn commit leaves the older one intact, which is exactly
    // why there are two.
    Node best;
    bool have = false;
    for (std::uint32_t lnum : {kMstLnum, kMstLnum + 1}) {
        for (std::uint64_t offs = 0; offs + kMstNodeSize <= m.leb_size; offs += m.min_io) {
            Node n;
            if (!m.read_node(lnum, static_cast<std::uint32_t>(offs), n) || n.type != kMst) break;
            if (!n.crc_ok) continue;
            if (!have || n.u64(32) > best.u64(32)) {
                best = n;
                have = true;
            }
        }
    }
    if (!have)
        return Status::fail("ubifs-bad-master: neither master node copy has a matching CRC");
    m.highest_inum = best.u64(kChSize);
    m.cmt_no = best.u64(32);
    m.log_lnum = best.u32(44);
    m.root_lnum = best.u32(48);
    m.root_offs = best.u32(52);
    m.root_len = best.u32(56);
    m.index_size = best.u64(72);

    if (!m.walk_index(m.root_lnum, m.root_offs, m.root_len) && m.inodes.empty())
        return Status::fail("ubifs-bad-index: " + (m.index_problem.empty()
                                                       ? std::string("the index did not parse")
                                                       : m.index_problem));
    m.replay_journal();
    m.opened = true;
    return Status::success();
}

FilesystemInfo UbifsReader::info() const {
    const Impl& m = *impl_;
    FilesystemInfo i;
    i.format = "ubifs";
    i.size = static_cast<std::uint64_t>(m.leb_cnt) * m.leb_size;
    i.block_size = static_cast<std::uint32_t>(kBlockSize);
    i.compression = compr_name(m.default_compr);
    i.endian = Endian::Little;
    i.attrs["fmt_version"] = dec(m.fmt_version);
    i.attrs["ro_compat_version"] = dec(m.ro_compat);
    i.attrs["uuid"] = m.uuid;
    i.attrs["min_io_size"] = dec(m.min_io);
    i.attrs["leb_size"] = dec(m.leb_size);
    i.attrs["leb_cnt"] = dec(m.leb_cnt);
    i.attrs["max_leb_cnt"] = dec(m.max_leb_cnt);
    i.attrs["log_lebs"] = dec(m.log_lebs);
    i.attrs["fanout"] = dec(m.fanout);
    i.attrs["commit_no"] = dec(m.cmt_no);
    i.attrs["index_size"] = dec(m.index_size);
    i.attrs["index_nodes"] = dec(m.index_nodes);
    i.attrs["index_leaves"] = dec(m.leaf_count);
    i.attrs["inodes"] = dec(m.inodes.size());
    i.attrs["dentries"] = dec(m.dents.size());
    i.attrs["data_nodes"] = dec(m.blocks.size());
    i.attrs["bud_lebs"] = dec(m.bud_lebs);
    i.attrs["journal_nodes"] = dec(m.replayed_nodes);
    if (m.unlinked_dents != 0) i.attrs["unlink_records"] = dec(m.unlinked_dents);
    if (m.bad_nodes != 0) i.attrs["bad_nodes"] = dec(m.bad_nodes);
    return i;
}

// ------------------------------------------------------------------ content

// A data node's payload, decompressed. `size` in the node is the length the
// block had before compression; UBIFS stores one block per node, never more.
bool UbifsReader::Impl::block_data(const Ref& r, std::vector<std::uint8_t>& out,
                                   std::string& why, const char*& code) const {
    code = kCodeShortFile;
    Node n;
    if (!read_node(r.lnum, r.offs, n, r.len) || n.type != kDataNode) {
        why = "the data node at LEB " + dec(r.lnum) + " offset " + dec(r.offs) + " is not readable";
        return false;
    }
    if (!n.crc_ok) {
        why = "the data node at LEB " + dec(r.lnum) + " offset " + dec(r.offs) + " fails its CRC";
        return false;
    }
    const std::uint64_t want = n.u32(40);
    const std::uint16_t compr = n.u16(44);
    if (want == 0 || want > kBlockSize) {
        why = "a data node claims " + dec(want) + " bytes, which is not a block";
        return false;
    }
    if (n.len <= kDataNodeSize) {
        why = "a data node carries no payload";
        return false;
    }
    const std::span<const std::uint8_t> in(n.raw.data() + kDataNodeSize,
                                           n.len - static_cast<std::size_t>(kDataNodeSize));
    compress::Codec codec = compress::Codec::None;
    switch (compr) {
        case kComprNone:
            codec = compress::Codec::None;
            break;
        case kComprLzo:
            codec = compress::Codec::Lzo1x;
            break;
        case kComprZlib:
            // UBIFS deflates without a zlib wrapper.
            codec = compress::Codec::Deflate;
            break;
        case kComprZstd:
            codec = compress::Codec::Zstd;
            break;
        default:
            why = "a data node uses compression type " + dec(compr) + ", which is not defined";
            return false;
    }
    if (const Status st = compress::decompress_exact(codec, in, out, static_cast<std::size_t>(want));
        !st) {
        code = kCodeDecompress;
        why = std::string(compr_name(compr)) + " block did not decode (" + st.error + ")";
        return false;
    }
    return true;
}

// Stream one file's blocks in order. A block the index does not have is a
// hole, which UBIFS makes by simply not writing it, so it reads as zeros.
// The data node holding `block` as of `cutoff`: the newest whose sqnum does
// not exceed it. kLive means the live map, which the index and the journal
// already agreed on.
const Ref* UbifsReader::Impl::block_at(std::uint32_t inum, std::uint32_t block,
                                       std::uint64_t cutoff) const {
    if (cutoff == kLive) {
        const auto it = blocks.find({inum, block});
        return it == blocks.end() ? nullptr : &it->second;
    }
    const auto it = block_versions.find({inum, block});
    if (it == block_versions.end()) return nullptr;
    const Ref* best = nullptr;
    for (const Ref& r : it->second) {  // sorted by sqnum
        if (r.sqnum > cutoff) break;
        best = &r;
    }
    return best;
}

bool UbifsReader::Impl::stream_file(const std::string& path, std::uint32_t inum,
                                    std::uint64_t size, std::uint64_t cutoff, Walk& w,
                                    bool& truncated, std::vector<Diagnostic>& diags) {
    if (w.zeros.size() != kBlockSize) w.zeros.assign(static_cast<std::size_t>(kBlockSize), 0);
    const std::uint64_t cap = std::min<std::uint64_t>(size, w.opts->limits.max_file_bytes);
    if (cap < size) truncated = true;
    bool missing_reported = false;
    for (std::uint64_t pos = 0; pos < cap;) {
        const std::uint32_t bno = static_cast<std::uint32_t>(pos / kBlockSize);
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(kBlockSize, cap - pos));
        const std::uint8_t* src = w.zeros.data();
        std::size_t have = want;
        const Ref* ref = block_at(inum, bno, cutoff);
        if (ref != nullptr) {
            std::string why;
            const char* code = kCodeShortFile;
            if (block_data(*ref, w.decoded, why, code)) {
                src = w.decoded.data();
                have = std::min(want, w.decoded.size());
                if (have < want) {
                    // The last block of a file is shorter than 4 KiB; a short
                    // block anywhere else means the rest of it is not there.
                    if (pos + kBlockSize < cap) truncated = true;
                }
            } else {
                truncated = true;
                if (!missing_reported) {
                    diags.push_back({Severity::Warning, code,
                                     "'" + path + "': block " + dec(bno) + ": " + why +
                                         "; zero-filled"});
                    missing_reported = true;
                }
            }
        }
        if (Status st = w.sink->write(std::span<const std::uint8_t>(src, have)); !st) return false;
        if (have < want) {
            if (Status st = w.sink->write(std::span<const std::uint8_t>(w.zeros.data(),
                                                                        want - have));
                !st)
                return false;
        }
        pos += want;
    }
    return true;
}

// An inode node's inline data: a symlink's target, or a device's numbers.
std::vector<std::uint8_t> UbifsReader::Impl::inline_data(const Node& ino) const {
    const std::uint64_t len = ino.u32(112);
    if (len == 0 || kInoNodeSize + len > ino.raw.size()) return {};
    return std::vector<std::uint8_t>(ino.raw.begin() + static_cast<std::ptrdiff_t>(kInoNodeSize),
                                     ino.raw.begin() +
                                         static_cast<std::ptrdiff_t>(kInoNodeSize + len));
}

// "name=size;name=size", the same shape the ext reader uses. The value of a
// UBIFS xattr lives in an inode of its own, so the size comes from there.
std::string UbifsReader::Impl::xattr_summary(std::uint32_t inum) const {
    const auto it = xattrs.find(inum);
    if (it == xattrs.end()) return {};
    std::vector<std::string> parts;
    for (const Dent& x : it->second) {
        std::uint64_t vsize = 0;
        const auto vi = inodes.find(static_cast<std::uint32_t>(x.inum));
        if (vi != inodes.end()) {
            Node n;
            if (read_node(vi->second.lnum, vi->second.offs, n, vi->second.len) &&
                n.type == kIno)
                vsize = n.u32(112);
        }
        parts.push_back(sanitize_utf8(x.name) + "=" + dec(vsize));
    }
    std::sort(parts.begin(), parts.end());
    std::string out;
    for (const std::string& p : parts) {
        if (!out.empty()) out.push_back(';');
        out += p;
    }
    return out;
}

// ------------------------------------------------------------------ walk

void UbifsReader::Impl::emit_entry(const std::string& path, const Dent& d, Walk& w) {
    const auto inum = static_cast<std::uint32_t>(d.inum);
    const auto ref = inodes.find(inum);
    FileMeta m;
    m.path = path;
    m.kind = kind_of(d.type);
    m.inode = inum;
    if (ref == inodes.end()) {
        // A name whose inode never made it to the index or a bud. The name is
        // evidence on its own, so the entry is still listed, empty.
        diag(*w.out, Severity::Warning, kCodeNoInode,
             "'" + path + "' names inode " + dec(inum) + ", which has no inode node");
        EntryResult r;
        if (const Status st = w.sink->entry(m, r); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            return;
        }
        r.truncated = true;
        count_entry(*w.out, r.meta);
        w.out->entries_out.push_back(std::move(r));
        return;
    }
    Node n;
    if (!read_node(ref->second.lnum, ref->second.offs, n, ref->second.len) || n.type != kIno) {
        diag(*w.out, Severity::Warning, kCodeBadNode,
             "'" + path + "': the inode node for " + dec(inum) + " is not readable");
        return;
    }
    if (!n.crc_ok) {
        ++bad_nodes;
        diag(*w.out, Severity::Warning, kCodeBadNode,
             "'" + path + "': the inode node for " + dec(inum) + " fails its CRC; its metadata is "
             "reported as stored");
    }

    const std::uint64_t size = n.u64(48);
    m.mode = n.u32(104) & 0xFFFFu;
    m.uid = n.u32(96);
    m.gid = n.u32(100);
    m.nlink = n.u32(92);
    m.size = size;
    m.atime = static_cast<std::int64_t>(n.u64(56));
    m.ctime = static_cast<std::int64_t>(n.u64(64));
    m.mtime = static_cast<std::int64_t>(n.u64(72));
    m.atime_nsec = n.u32(80);
    m.ctime_nsec = n.u32(84);
    m.mtime_nsec = n.u32(88);
    const std::uint16_t compr = n.u16(132);
    if (m.kind == EntryKind::Regular && compr != default_compr)
        m.extra["compression"] = compr_name(compr);
    if (const std::string x = xattr_summary(inum); !x.empty()) m.extra["xattrs"] = x;
    // A second name for an inode already emitted is a hard link.
    if (m.nlink > 1 && !w.seen_ino.insert(inum).second) m.extra["hardlink"] = "true";

    if (m.kind == EntryKind::Symlink) {
        std::vector<std::uint8_t> t = inline_data(n);
        if (t.size() > kMaxSymlinkTarget) t.resize(static_cast<std::size_t>(kMaxSymlinkTarget));
        m.link_target.assign(t.begin(), t.end());
        m.size = t.size();
    } else if (m.kind == EntryKind::BlockDevice || m.kind == EntryKind::CharDevice) {
        const std::vector<std::uint8_t> dev = inline_data(n);
        if (dev.size() == 4) {
            // new_encode_dev: minor's low byte, then major, then minor's high bits.
            const std::uint32_t v = load_int<std::uint32_t>(dev.data(), Endian::Little);
            m.rdev_major = (v >> 8) & 0xFFFu;
            m.rdev_minor = (v & 0xFFu) | ((v >> 12) & 0xFFF00u);
        } else if (dev.size() == 8) {
            // huge_encode_dev: major in the high word, minor in the low one.
            const std::uint64_t v = load_int<std::uint64_t>(dev.data(), Endian::Little);
            m.rdev_major = static_cast<std::uint32_t>(v >> 32);
            m.rdev_minor = static_cast<std::uint32_t>(v & 0xFFFFFFFFu);
        }
        m.size = 0;
    }

    std::vector<Diagnostic> diags;
    bool truncated = false;
    if (m.kind == EntryKind::Regular) {
        if (const Status st = w.sink->begin_file(m); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            return;
        }
        bool sink_ok = true;
        if (w.opts->extract_data)
            sink_ok = stream_file(path, inum, size, kLive, w, truncated, diags);
        EntryResult r;
        if (const Status st = w.sink->end_file(r); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            if (r.meta.path.empty()) return;
        }
        if (!sink_ok || truncated) r.truncated = true;
        for (Diagnostic& dg : diags) r.diagnostics.push_back(std::move(dg));
        w.out->bytes += r.digests.bytes;
        count_entry(*w.out, r.meta);
        w.out->entries_out.push_back(std::move(r));
        return;
    }
    EntryResult r;
    if (const Status st = w.sink->entry(m, r); !st) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
        return;
    }
    count_entry(*w.out, r.meta);
    w.out->entries_out.push_back(std::move(r));
}

void UbifsReader::Impl::emit_tree(std::uint32_t inum, const std::string& prefix, unsigned depth,
                                  Walk& w) {
    if (w.stop || depth > kMaxDepth) return;
    if (!w.on_path.insert(inum).second) {
        diag(*w.out, Severity::Warning, kCodeLoop,
             "directory inode " + dec(inum) + " is its own ancestor at '" + prefix +
                 "'; the branch stops there");
        return;
    }
    // The map is keyed by (parent, name), so this range is exactly this
    // directory's entries, already in name order.
    std::vector<Dent> here;
    for (auto it = dents.lower_bound({inum, std::string{}});
         it != dents.end() && it->first.first == inum; ++it) {
        here.push_back(it->second);
    }
    for (const Dent& d : here) {
        if (w.out->entries >= w.opts->limits.max_nodes_per_fs) {
            if (!w.stop) {
                diag(*w.out, Severity::Warning, kCodeLimitNodes,
                     "the entry limit (" + dec(w.opts->limits.max_nodes_per_fs) +
                         ") stopped the walk");
                w.out->truncated = true;
            }
            w.stop = true;
            break;
        }
        const std::string path = prefix.empty() ? d.name : prefix + "/" + d.name;
        const auto child = static_cast<std::uint32_t>(d.inum);
        emit_entry(path, d, w);
        // The first name an inode is reached by is the one history uses for
        // it; a hard link's second name would name the same content twice.
        w.live_path.emplace(child, path);
        if (d.type == kItDir) emit_tree(child, path, depth + 1, w);
    }
    w.on_path.erase(inum);
}

Status UbifsReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& m = *impl_;
    if (!m.opened) return Status::fail("ubifs-not-open: walk before a successful open");

    if (!m.index_problem.empty()) {
        m.diag(out, Severity::Warning, kCodeBadIndex,
               m.index_problem + "; only the part of the index that parsed was used");
        out.truncated = true;
    }
    if (!m.journal_problem.empty()) {
        // The index alone is the filesystem as the last commit froze it.
        // Anything written after that commit is in the buds this could not
        // reach, so recent changes are missing.
        m.diag(out, Severity::Warning, kCodeJournal,
               m.journal_problem + "; the tree is as of commit " + dec(m.cmt_no) +
                   " and anything written after it is not shown");
        out.truncated = true;
    }

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;
    w.live_path[kRootIno] = "";  // a name deleted from the root lands here
    m.emit_tree(kRootIno, "", 0, w);
    if (out.entries == 0 && m.dents.empty()) {
        m.diag(out, Severity::Warning, kCodeBadIndex,
               "the index holds no directory entry, so there is no tree to walk");
    }
    if (opts.history && !w.stop) m.emit_history(w);
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("ubifs", UbifsReader);

}  // namespace omnitrace::fs
