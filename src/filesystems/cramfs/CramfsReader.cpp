// CramfsReader.cpp — cramfs extraction.
//
// Layout (linux/cramfs_fs.h):
//
//     [ 76-byte superblock, root inode at offset 64 ]
//     [ directory inodes, file block-pointer tables, compressed blocks ... ]
//
// A directory's data is `size` bytes of back-to-back inodes, each 12 bytes
// followed by its name padded to a multiple of four. A regular file's data is
// a table of u32 block pointers followed by the compressed blocks: pointer `i`
// is the offset one past the end of block `i`, so block 0 runs from the end of
// the table to `ptr[0]`, and block `i` from `ptr[i-1]` to `ptr[i]`. Every
// block decompresses to 4096 bytes except the last.
//
// The one real trap is the inode. It is three u32 words of C bitfields:
//
//     __u32 mode:16, uid:16;  __u32 size:24, gid:8;  __u32 namelen:6, offset:26;
//
// GCC packs bitfields from the least significant end on a little-endian
// target and from the most significant end on a big-endian one, so a
// big-endian image is not a byte swap of a little-endian one -- the fields sit
// at different bit positions. Both layouts are spelled out in `read_inode`,
// and both are covered by a fixture built with `mkfs.cramfs -N big|little`.
//
// `namelen` counts 4-byte units, and `offset` is in 4-byte units too, which is
// what keeps a 26-bit field able to address a 256 MiB image.
#include "CramfsReader.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_cramfs() {}
}  // namespace detail

namespace {

constexpr const char* kCodeBadInode = "cramfs-bad-inode";
constexpr const char* kCodeBadBlock = "cramfs-bad-block";
constexpr const char* kCodeDecompressFailed = "cramfs-decompress-failed";
constexpr const char* kCodeCycle = "cramfs-cycle";
constexpr const char* kCodeLimitNodes = "cramfs-limit-nodes";
constexpr const char* kCodeLimitDepth = "cramfs-limit-depth";
constexpr const char* kCodeSinkError = "cramfs-sink-error";
constexpr const char* kCodeUnsupportedFlags = "cramfs-unsupported-flags";

constexpr std::uint64_t kSuperblockBytes = 76;
constexpr std::uint64_t kInodeBytes = 12;
constexpr std::uint64_t kRootInodeAt = 64;
// The block size is not stored: cramfs uses the kernel's page size and every
// tool that writes one uses 4096. mkfs.cramfs -b accepts nothing else.
constexpr std::uint64_t kBlockSize = 4096;
constexpr std::size_t kMaxDepth = 64;

// Superblock flags (linux/cramfs_fs.h).
constexpr std::uint32_t kFlagFsidV2 = 0x001;
constexpr std::uint32_t kFlagSortedDirs = 0x002;
constexpr std::uint32_t kFlagHoles = 0x100;
constexpr std::uint32_t kFlagWrongSignature = 0x200;
constexpr std::uint32_t kFlagShiftedRootOffset = 0x400;
constexpr std::uint32_t kFlagExtBlockPointers = 0x800;

struct Inode {
    std::uint32_t mode = 0;
    std::uint32_t uid = 0, gid = 0;
    std::uint64_t size = 0;
    std::uint64_t offset = 0;  // already multiplied out to bytes
    std::string name;
    std::uint64_t record = 0;  // bytes this inode plus its name occupy
};

EntryKind kind_of(std::uint32_t mode) {
    switch (mode & 0170000U) {
        case 0040000U:
            return EntryKind::Directory;
        case 0120000U:
            return EntryKind::Symlink;
        case 0100000U:
            return EntryKind::Regular;
        case 0020000U:
            return EntryKind::CharDevice;
        case 0060000U:
            return EntryKind::BlockDevice;
        case 0010000U:
            return EntryKind::Fifo;
        case 0140000U:
            return EntryKind::Socket;
        default:
            return EntryKind::Unknown;
    }
}

std::string flag_names(std::uint32_t f) {
    std::string out;
    const auto add = [&out](const char* n) {
        if (!out.empty()) out += ",";
        out += n;
    };
    if ((f & kFlagFsidV2) != 0) add("fsid_v2");
    if ((f & kFlagSortedDirs) != 0) add("sorted_dirs");
    if ((f & kFlagHoles) != 0) add("holes");
    if ((f & kFlagWrongSignature) != 0) add("wrong_signature");
    if ((f & kFlagShiftedRootOffset) != 0) add("shifted_root_offset");
    if ((f & kFlagExtBlockPointers) != 0) add("ext_block_pointers");
    return out;
}

}  // namespace

struct CramfsReader::Impl {
    Span span;
    bool opened = false;
    Endian endian = Endian::Little;
    std::uint64_t image_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t edition = 0, blocks = 0, files = 0;
    std::string name;
    Inode root;

    // The bitfield unpack. Little- and big-endian images put the same fields
    // at different bit offsets, because GCC allocates bitfields from opposite
    // ends; this is not a byte swap.
    std::optional<Inode> read_inode(std::uint64_t at) const {
        if (at + kInodeBytes > span.size()) return std::nullopt;
        const auto w0 = span.at<std::uint32_t>(at + 0, endian);
        const auto w1 = span.at<std::uint32_t>(at + 4, endian);
        const auto w2 = span.at<std::uint32_t>(at + 8, endian);
        if (!w0 || !w1 || !w2) return std::nullopt;

        Inode n;
        std::uint32_t namelen = 0;
        if (endian == Endian::Little) {
            n.mode = *w0 & 0xFFFFU;
            n.uid = *w0 >> 16;
            n.size = *w1 & 0xFFFFFFU;
            n.gid = *w1 >> 24;
            namelen = *w2 & 0x3FU;
            n.offset = static_cast<std::uint64_t>(*w2 >> 6) * 4;
        } else {
            n.mode = *w0 >> 16;
            n.uid = *w0 & 0xFFFFU;
            n.size = *w1 >> 8;
            n.gid = *w1 & 0xFFU;
            namelen = *w2 >> 26;
            n.offset = static_cast<std::uint64_t>(*w2 & 0x03FFFFFFU) * 4;
        }

        const std::uint64_t name_bytes = static_cast<std::uint64_t>(namelen) * 4;
        if (at + kInodeBytes + name_bytes > span.size()) return std::nullopt;
        if (name_bytes != 0) {
            auto b = span.bytes(at + kInodeBytes, static_cast<std::size_t>(name_bytes));
            if (!b) return std::nullopt;
            // NUL-padded to the 4-byte unit, so the name ends at the first NUL.
            const auto nul = std::find(b->begin(), b->end(), 0);
            n.name.assign(b->begin(), nul);
        }
        n.record = kInodeBytes + name_bytes;
        return n;
    }
};

CramfsReader::CramfsReader() : impl_(std::make_unique<Impl>()) {}
CramfsReader::~CramfsReader() = default;

std::string CramfsReader::format() const {
    return "cramfs";
}

Status CramfsReader::open(const Span& span) {
    if (span.size() < kSuperblockBytes)
        return Status::fail("cramfs-truncated: fewer than 76 bytes of superblock");

    // The magic tells the byte order: 0x28cd3d45 read little-endian, or the
    // same value read big-endian on an image built for a big-endian host.
    const auto le = span.at<std::uint32_t>(0, Endian::Little);
    const auto be = span.at<std::uint32_t>(0, Endian::Big);
    if (!le || !be) return Status::fail("cramfs-truncated: the magic is not readable");
    Impl& d = *impl_;
    if (*le == 0x28cd3d45U) {
        d.endian = Endian::Little;
    } else if (*be == 0x28cd3d45U) {
        d.endian = Endian::Big;
    } else {
        return Status::fail("cramfs-bad-magic: no cramfs magic at offset 0");
    }

    // Before anything calls read_inode, which reads through this.
    d.span = span;

    auto sig = span.bytes(16, 16);
    if (!sig) return Status::fail("cramfs-truncated: the signature is not readable");
    static const char kSig[] = "Compressed ROMFS";
    if (!std::equal(sig->begin(), sig->end(), kSig, kSig + 16))
        return Status::fail("cramfs-bad-signature: \"Compressed ROMFS\" is not at offset 16");

    const auto size = span.at<std::uint32_t>(4, d.endian);
    const auto flags = span.at<std::uint32_t>(8, d.endian);
    const auto edition = span.at<std::uint32_t>(36, d.endian);
    const auto blocks = span.at<std::uint32_t>(40, d.endian);
    const auto files = span.at<std::uint32_t>(44, d.endian);
    if (!size || !flags || !edition || !blocks || !files)
        return Status::fail("cramfs-truncated: the superblock is not readable");
    d.image_size = *size;
    d.flags = *flags;
    d.edition = *edition;
    d.blocks = *blocks;
    d.files = *files;

    if (auto nm = span.bytes(48, 16); nm) {
        const auto nul = std::find(nm->begin(), nm->end(), 0);
        d.name.assign(nm->begin(), nul);
    }

    const auto root = d.read_inode(kRootInodeAt);
    if (!root) return Status::fail("cramfs-bad-root: the root inode is not readable");
    if (kind_of(root->mode) != EntryKind::Directory)
        return Status::fail("cramfs-bad-root: the root inode is not a directory");
    d.root = *root;
    d.opened = true;
    return Status::success();
}

FilesystemInfo CramfsReader::info() const {
    const Impl& d = *impl_;
    FilesystemInfo i;
    i.format = "cramfs";
    i.label = sanitize_utf8(d.name);
    i.size = d.image_size;
    i.block_size = static_cast<std::uint32_t>(kBlockSize);
    i.compression = "zlib";
    i.endian = d.endian;
    i.attrs["version"] = (d.flags & kFlagFsidV2) != 0 ? "2" : "1";
    i.attrs["flags"] = flag_names(d.flags);
    i.attrs["edition"] = std::to_string(d.edition);
    i.attrs["blocks"] = std::to_string(d.blocks);
    i.attrs["files"] = std::to_string(d.files);
    return i;
}

Status CramfsReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& d = *impl_;
    if (!d.opened) return Status::fail("cramfs-not-open: walk before a successful open");

    if ((d.flags & kFlagExtBlockPointers) != 0)
        out.diagnostics.push_back(
            {Severity::Warning, kCodeUnsupportedFlags,
             "EXT_BLOCK_POINTERS is set: block pointers carry uncompressed and direct-block bits "
             "this reader does not decode, so file contents may be wrong"});

    std::set<std::uint64_t> seen_dirs;
    std::uint64_t nodes = 0;
    bool stop = false;

    const auto count = [&out](const FileMeta& m) {
        ++out.entries;
        switch (m.kind) {
            case EntryKind::Directory:
                ++out.dirs;
                break;
            case EntryKind::Symlink:
                ++out.symlinks;
                break;
            case EntryKind::Regular:
                ++out.files;
                break;
            default:
                ++out.others;
                break;
        }
    };

    // Inflate a file's blocks. The pointer table sits at the inode's offset and
    // the blocks follow it; a pointer equal to the previous one is a hole when
    // the image declares them, and a run of zeros otherwise.
    const auto read_file = [&](const Inode& n, const std::string& path,
                               std::vector<std::uint8_t>& out_bytes) {
        out_bytes.clear();
        if (n.size == 0) return true;
        const std::uint64_t nblocks = (n.size + kBlockSize - 1) / kBlockSize;
        const std::uint64_t table = n.offset;
        const std::uint64_t table_end = table + nblocks * 4;
        if (table == 0 || table_end > d.span.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadBlock,
                                       "'" + path + "': the block table at " +
                                           std::to_string(table) + " is outside the image"});
            return false;
        }
        out_bytes.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(n.size, 1u << 24)));
        std::uint64_t start = table_end;
        for (std::uint64_t b = 0; b < nblocks; ++b) {
            const auto ptr = d.span.at<std::uint32_t>(table + b * 4, d.endian);
            if (!ptr) return false;
            const std::uint64_t end = *ptr;
            // How much of the file this block accounts for.
            const std::uint64_t want = std::min<std::uint64_t>(kBlockSize, n.size - b * kBlockSize);
            if (end == start) {
                // A hole: no compressed bytes, so the block is zeros.
                out_bytes.insert(out_bytes.end(), static_cast<std::size_t>(want), 0);
                continue;
            }
            if (end < start || end > d.span.size()) {
                out.diagnostics.push_back({Severity::Warning, kCodeBadBlock,
                                           "'" + path + "': block " + std::to_string(b) +
                                               " ends at " + std::to_string(end) +
                                               ", which is before its start or past the image"});
                return false;
            }
            auto comp = d.span.bytes(start, static_cast<std::size_t>(end - start));
            if (!comp) return false;
            std::vector<std::uint8_t> plain;
            const Status st = compress::decompress_exact(
                compress::Codec::Zlib, std::span<const std::uint8_t>(comp->data(), comp->size()),
                plain, static_cast<std::size_t>(want));
            if (!st) {
                out.diagnostics.push_back({Severity::Warning, kCodeDecompressFailed,
                                           "'" + path + "': block " + std::to_string(b) +
                                               " did not inflate (" + st.error +
                                               "); the file is cut there"});
                return false;
            }
            out_bytes.insert(out_bytes.end(), plain.begin(), plain.end());
            start = end;
        }
        return true;
    };

    const std::function<void(const Inode&, const std::string&, std::size_t)> walk_dir =
        [&](const Inode& dir, const std::string& prefix, std::size_t depth) {
            if (stop) return;
            if (depth > kMaxDepth) {
                out.diagnostics.push_back({Severity::Warning, kCodeLimitDepth,
                                           "directory nesting deeper than " +
                                               std::to_string(kMaxDepth) + " at '" + prefix +
                                               "'; not descended"});
                out.truncated = true;
                return;
            }
            if (dir.size == 0) return;
            if (!seen_dirs.insert(dir.offset).second) {
                out.diagnostics.push_back({Severity::Warning, kCodeCycle,
                                           "the directory data at " + std::to_string(dir.offset) +
                                               " ('" + prefix +
                                               "') was already walked; the image loops"});
                out.truncated = true;
                return;
            }
            const std::uint64_t end = dir.offset + dir.size;
            if (dir.offset < kSuperblockBytes || end > d.span.size()) {
                out.diagnostics.push_back({Severity::Warning, kCodeBadInode,
                                           "'" + prefix + "' claims directory data at " +
                                               std::to_string(dir.offset) + ".." +
                                               std::to_string(end) + ", outside the image"});
                out.truncated = true;
                return;
            }

            std::vector<Inode> children;
            for (std::uint64_t at = dir.offset; at < end && !stop;) {
                const auto n = d.read_inode(at);
                if (!n) {
                    out.diagnostics.push_back({Severity::Warning, kCodeBadInode,
                                               "the inode at " + std::to_string(at) + " under '" +
                                                   prefix +
                                                   "' is unreadable; the rest of this "
                                                   "directory was not walked"});
                    out.truncated = true;
                    break;
                }
                if (at + n->record > end) {
                    out.diagnostics.push_back({Severity::Warning, kCodeBadInode,
                                               "the inode at " + std::to_string(at) + " under '" +
                                                   prefix + "' runs past the directory's data"});
                    out.truncated = true;
                    break;
                }
                at += n->record;
                if (n->name.empty() || n->name == "." || n->name == "..") continue;
                children.push_back(*n);
            }

            for (const Inode& n : children) {
                if (stop) return;
                if (nodes >= opts.limits.max_nodes_per_fs) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeLimitNodes,
                         "max_nodes_per_fs (" + std::to_string(opts.limits.max_nodes_per_fs) +
                             ") reached; the rest of the image was not walked"});
                    out.truncated = true;
                    stop = true;
                    return;
                }
                ++nodes;

                const std::string path = prefix.empty() ? n.name : prefix + "/" + n.name;
                const EntryKind kind = kind_of(n.mode);

                FileMeta m;
                m.path = path;
                m.kind = kind;
                m.mode = n.mode & 07777U;
                m.uid = n.uid;
                m.gid = n.gid;
                m.size = n.size;
                m.inode = n.offset;  // cramfs has no inode numbers; the offset is the identity
                // cramfs stores no timestamps at all, and gid is truncated to
                // eight bits by mkfs.cramfs. Say so rather than let an examiner
                // read the absence as "epoch".
                m.extra["no_timestamps"] = "cramfs stores none";

                EntryResult r;
                Status emitted = Status::success();
                if (kind == EntryKind::Symlink) {
                    std::vector<std::uint8_t> target;
                    if (read_file(n, path, target))
                        m.link_target = sanitize_utf8(std::string(target.begin(), target.end()));
                    m.size = 0;
                    emitted = sink.entry(m, r);
                } else if (kind == EntryKind::Regular) {
                    if (opts.extract_data) {
                        std::vector<std::uint8_t> data;
                        const bool whole = read_file(n, path, data);
                        emitted = sink.file(
                            m, std::span<const std::uint8_t>(data.data(), data.size()), r);
                        out.bytes += data.size();
                        if (!whole) {
                            r.truncated = true;
                            out.truncated = true;
                        }
                    } else {
                        emitted = sink.begin_file(m);
                        if (emitted) emitted = sink.end_file(r);
                    }
                } else {
                    // Directories, devices, fifos and sockets: metadata only.
                    // cramfs keeps no rdev, so a device node has no numbers.
                    m.size = 0;
                    emitted = sink.entry(m, r);
                }

                if (!emitted) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeSinkError, "'" + path + "': " + emitted.error});
                } else {
                    if (r.truncated) out.truncated = true;
                    count(r.meta.path.empty() ? m : r.meta);
                    out.entries_out.push_back(std::move(r));
                }

                if (kind == EntryKind::Directory) walk_dir(n, path, depth + 1);
            }
        };

    walk_dir(d.root, "", 0);
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("cramfs", CramfsReader);

}  // namespace omnitrace::fs
