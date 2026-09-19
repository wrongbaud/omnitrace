// Node.h — the evidence graph.
//
// Everything OmniTrace finds is a Node: the image, a partition, a container, a
// filesystem, a file (including deleted/superseded versions), an unidentified
// region, an artifact. Each Node has a Span-derived location {source_id,
// offset, length} so any finding traces back to bytes in the original evidence.
/// @file Node.h
/// @brief The evidence graph's vocabulary: `Node`, `NodeKind`, `Location`,
/// `FileMeta`, `EntryKind`, `Coverage`, `ToolRecord`.
///
/// These are plain data. `Manifest` owns the Nodes and assigns ids;
/// `output::manifest_to_yaml` serializes them with the exact key names the
/// `*_name()` functions return, so those strings are frozen once published.
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

/// What a Node is. Serialized as the lowercase name (`node_kind_name`).
enum class NodeKind : std::uint8_t {
    Image,      ///< Top-level evidence file.
    Partition,  ///< MBR/GPT/vendor table (attrs role=table) or one of its entries, a UBI volume, an
                ///< eMMC boot area.
    Container,  ///< tar/zip/cpio/gzip/uImage/FIT/sparse/boot image.
    Filesystem,  ///< SquashFS/JFFS2/UBIFS/ext/...
    File,        ///< Regular file, dir, symlink, device...; see `FileMeta::kind`.
    Region,      ///< Unidentified or unallocated byte range, or an identified non-container find
                 ///< (kernel, DTB) with `format` set.
    Artifact,    ///< A rule/extractor hit (Phase 2; not produced yet).
};
/// "image", "partition", "container", "filesystem", "file", "region",
/// "artifact"; "unknown" for an out-of-range value.
const char* node_kind_name(NodeKind k);
/// Inverse of `node_kind_name`; `nullopt` for any other string.
std::optional<NodeKind> node_kind_from_name(const std::string& s);

/// Where a Node's bytes are, relative to a `Source::id()`.
struct Location {
    std::string source_id;     ///< `Source::id()` this offset is relative to (the evidence path, or
                               ///< "<path>|swap32" under a word swap).
    std::uint64_t offset = 0;  ///< First byte.
    std::uint64_t length = 0;  ///< Byte count; 0 = unknown extent.
};

/// Type of a filesystem entry. Serialized via `entry_kind_name`.
enum class EntryKind : std::uint8_t {
    Regular,      ///< "regular"
    Directory,    ///< "directory"
    Symlink,      ///< "symlink"
    CharDevice,   ///< "char-device"
    BlockDevice,  ///< "block-device"
    Fifo,         ///< "fifo"
    Socket,       ///< "socket"
    Unknown       ///< "unknown"
};
/// Stable lowercase name of an EntryKind (see the enumerator docs).
const char* entry_kind_name(EntryKind k);

// Per-file metadata captured by filesystem readers. Every field a forensic
// listing needs, independent of what lands on the host filesystem.
/// Everything a filesystem records about one entry (docs/ARCHITECTURE.md
/// rule 6). Readers fill it; Sinks normalize `path` and hand it back inside
/// an `EntryResult`; `output::listing_to_yaml` writes it. Fields a format
/// cannot represent stay at their defaults (`nullopt` timestamps, mode 0).
struct FileMeta {
    std::string path;  ///< POSIX-style, relative to the filesystem root, no leading '/'.
    EntryKind kind = EntryKind::Regular;  ///< Entry type.
    std::uint32_t mode = 0;               ///< Permission bits (and type bits if the FS has them).
    std::uint32_t uid = 0, gid = 0;       ///< Owner ids as stored.
    std::uint64_t size = 0;  ///< Size the filesystem claims; the Sink reports what it actually
                             ///< received in `Digests::bytes`.
    std::optional<std::int64_t> mtime, ctime, atime,
        crtime;  ///< Unix seconds; `nullopt` when the FS has no such field.
    std::optional<std::uint32_t> mtime_nsec, ctime_nsec,
        atime_nsec;                                ///< Sub-second parts when the FS keeps them.
    std::uint64_t inode = 0;                       ///< Inode / object id inside the filesystem.
    std::uint32_t nlink = 0;                       ///< Hard-link count.
    std::string link_target;                       ///< Symlink target, verbatim and never resolved.
    std::uint32_t rdev_major = 0, rdev_minor = 0;  ///< Device numbers for char/block devices.
    // Forensic state. `deleted`: no live directory entry points at it.
    // `superseded`: an older version of a file that still has a live entry.
    // `version`: monotonically increasing per inode as recorded by the FS
    // (JFFS2 version, UBIFS sqnum order, YAFFS2 sequence); 0 = only/current.
    bool deleted = false;       ///< No live directory entry points at it.
    bool superseded = false;    ///< An older version of a file that still has a live entry.
    std::uint64_t version = 0;  ///< Per-inode version as the FS records it (JFFS2 version, UBIFS
                                ///< sqnum order, YAFFS2 sequence); 0 = only/current.
    std::map<std::string, std::string> extra;  ///< FS-specific: compression, xattrs summary, ...
                                               ///< (`std::map` so output order is fixed).
};

/// One vertex of the evidence graph. Ids and `child_ids` are managed by
/// `Manifest::add_node`; everything else is set by whoever found it.
struct Node {
    std::string id;         ///< "n" + six-digit counter, assigned by `Manifest::add_node`.
    std::string parent_id;  ///< Empty for the root (the Image).
    NodeKind kind = NodeKind::Region;  ///< What this is.
    std::string name;                  ///< Human label: partition name, file name, format label.
    std::string format;           ///< "squashfs", "jffs2", "mbr", "gzip", ...; empty for File and
                                  ///< unidentified Region.
    Location location;            ///< Byte range in the evidence.
    std::uint8_t confidence = 0;  ///< 0-100, the `Confidence` score of the finding.
    std::string evidence;         ///< Why that confidence (magic position, CRC results, ...).
    Endian endian = Endian::Little;  ///< Byte order of the structure.
    std::optional<FileMeta> file;    ///< Present when `kind == File`.
    Digests digests;  ///< Filled for regular Files and for carved blobs; empty otherwise.
    std::map<std::string, std::string>
        attrs;  ///< Format-specific: version, compression, arch, label, carved_path, ...
                ///< (docs/CASE_LAYOUT.md lists the partition ones).
    std::vector<Diagnostic> diagnostics;  ///< Caveats about this node.
    std::vector<std::string> child_ids;   ///< Filled by `Manifest::add_node` as children arrive.
};

// One row per capability the run could or could not exercise.
/// One row per format or capability met during the run, so that nothing is
/// skipped silently (docs/ARCHITECTURE.md rule 7). docs/CLI.md "Coverage"
/// defines the status values.
struct Coverage {
    std::string format;  ///< "ubifs", "qnx6", "nand-oob", "carve", "word-swap", ...
    std::string status;  ///< "supported" | "partial" | "unsupported" | "tool-missing".
    std::string detail;  ///< What was left behind and where; empty for "supported".
};

/// Record of an external tool invocation. Reserved for later phases; nothing
/// populates it today.
struct ToolRecord {
    std::string name, version;      ///< Tool identity.
    std::vector<std::string> argv;  ///< Exact command line.
    int exit_code = 0;              ///< Process exit status.
    double seconds = 0;             ///< Wall time.
};

}  // namespace omnitrace
