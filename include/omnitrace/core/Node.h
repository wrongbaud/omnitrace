// Node.h — the evidence graph.
//
// Everything OmniTrace finds is a Node: the image, a partition, a container, a
// filesystem, a file (including deleted/superseded versions), an unidentified
// region, an artifact. Each Node has a Span-derived location {source_id,
// offset, length} so any finding traces back to bytes in the original evidence.
#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Hash.h"

namespace omnitrace {

enum class NodeKind : std::uint8_t {
    Image,       // top-level evidence file
    Partition,   // MBR/GPT/vendor table entry, UBI volume, eMMC boot area
    Container,   // tar/zip/cpio/gzip/uImage/FIT/sparse/boot image
    Filesystem,  // SquashFS/JFFS2/UBIFS/ext/...
    File,        // regular file, dir, symlink, device... see FileMeta.kind
    Region,      // unidentified or unallocated byte range
    Artifact,    // a rule/extractor hit (Phase 2)
};
const char* node_kind_name(NodeKind k);
std::optional<NodeKind> node_kind_from_name(const std::string& s);

struct Location {
    std::string source_id;  // Source::id() this offset is relative to
    std::uint64_t offset = 0;
    std::uint64_t length = 0;  // 0 = unknown
};

enum class EntryKind : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown
};
const char* entry_kind_name(EntryKind k);

// Per-file metadata captured by filesystem readers. Every field a forensic
// listing needs, independent of what lands on the host filesystem.
struct FileMeta {
    std::string path;  // POSIX-style, relative to the filesystem root, no leading '/'
    EntryKind kind = EntryKind::Regular;
    std::uint32_t mode = 0;  // permission bits (and type bits if the FS has them)
    std::uint32_t uid = 0, gid = 0;
    std::uint64_t size = 0;
    std::optional<std::int64_t> mtime, ctime, atime, crtime;  // unix seconds
    std::optional<std::uint32_t> mtime_nsec, ctime_nsec, atime_nsec;
    std::uint64_t inode = 0;
    std::uint32_t nlink = 0;
    std::string link_target;  // for symlinks
    std::uint32_t rdev_major = 0, rdev_minor = 0;
    // Forensic state. `deleted`: no live directory entry points at it.
    // `superseded`: an older version of a file that still has a live entry.
    // `version`: monotonically increasing per inode as recorded by the FS
    // (JFFS2 version, UBIFS sqnum order, YAFFS2 sequence); 0 = only/current.
    bool deleted = false;
    bool superseded = false;
    std::uint64_t version = 0;
    std::map<std::string, std::string> extra;  // FS-specific (compression, xattrs summary, ...)
};

struct Node {
    std::string id;         // "n" + zero-padded counter, assigned by the graph
    std::string parent_id;  // empty for the root
    NodeKind kind = NodeKind::Region;
    std::string name;    // human label: partition name, file name, format label
    std::string format;  // "squashfs", "jffs2", "mbr", "gzip", ... empty for File/Region
    Location location;
    std::uint8_t confidence = 0;  // 0-100
    std::string evidence;         // why the confidence
    Endian endian = Endian::Little;
    std::optional<FileMeta> file;              // present when kind == File
    Digests digests;                           // filled for File (regular) and for extracted blobs
    std::map<std::string, std::string> attrs;  // format-specific: version, compression, arch, label
    std::vector<Diagnostic> diagnostics;
    std::vector<std::string> child_ids;
};

// One row per capability the run could or could not exercise.
struct Coverage {
    std::string format;  // "ubifs", "qnx6", "nand-oob", ...
    std::string status;  // "supported" | "partial" | "unsupported" | "tool-missing"
    std::string detail;
};

struct ToolRecord {
    std::string name, version;
    std::vector<std::string> argv;
    int exit_code = 0;
    double seconds = 0;
};

}  // namespace omnitrace
