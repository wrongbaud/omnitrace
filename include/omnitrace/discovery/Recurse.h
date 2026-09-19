// Recurse.h — the analysis driver: image -> findings -> evidence graph -> case
// directory.
//
// analyze() hashes the image, scans it with the builtin signatures, and builds
// the evidence graph partition-first:
//
//   1. Every partition-table finding becomes one Partition node for the table
//      (attrs role=table) plus one Partition node per entry, named from the
//      GPT label (sanitized) or "pN". A GPT backup header that describes the
//      same disk as a primary is folded into the primary (attrs backup_lba);
//      a backup with no primary is used on its own and its
//      gpt-primary-missing diagnostic is copied onto the Image node.
//   2. Every other finding is parented under the innermost Partition (or
//      Filesystem / Container) whose range contains its first byte; a finding
//      that starts after the partition's first byte keeps its own offset and
//      is a "nested find".
//   3. A Partition with no finding at its first byte is re-scanned on its own
//      Span, so a filesystem that starts exactly at the partition start is
//      found even when the whole-image scan missed it. Unclaimed space inside
//      a partition, and between top-level claims, becomes Region nodes.
//   4. Every Filesystem node, wherever it is nested, is walked with the reader
//      the caller supplies into <out_dir>/filesystems/<node-id>/files; one
//      File node per emitted entry. Containers without a reader are a Coverage
//      row ("unsupported") and a Diagnostic, never silent.
//   5. With carve != Carve::None and a non-empty out_dir, every partition entry
//      (and, with Carve::All, every nested find) is streamed to
//      <out_dir>/partitions/<name>.bin, hashed as it is written; the node gets
//      digests and attrs carved_path. <out_dir>/partitions/mount.sh is then
//      generated (see mount_script_text). A file larger than max_carve_bytes
//      is skipped with a Coverage row {"carve","partial",...} and a Diagnostic.
//
// Phase 0 handles one level: the image itself. Nested recursion (re-scanning a
// Container payload or an extracted file) is Phase 1a; the per-span worker
// analyze_span() is the unit a later pass will call recursively.
//
// Layering: this file lives in discovery and therefore cannot link against the
// filesystems library. Readers are supplied by the caller through
// AnalyzeOptions::open_reader; the CLI passes FilesystemRegistry::create.
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/core/Limits.h"
#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Status.h"
#include "omnitrace/discovery/Signature.h"
#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::discovery {

// Returns a reader for `format`, or nullptr when none is available.
using ReaderLookup =
    std::function<std::unique_ptr<fs::FilesystemReader>(const std::string& format)>;

// Scanner used for the whole image and for every partition re-scan. Tests
// substitute hand-made findings; the default is scan(span, builtin, opts.scan).
using Scanner = std::function<std::vector<Finding>(const Span& span)>;

// EXTENSION POINT (word swap; not implemented here). Called once, before the
// whole-image scan, with the evidence Source and the Image node already in the
// graph. Returns the Source the scan should run on: the same one, or a derived
// view such as core/Swap.h SwappedSource chosen by detect_word_swap(). The hook
// records what it decided on `image_node` (attrs, diagnostics such as
// "image-word-swapped"). Empty (the default): the image is analysed as is.
using ImageViewHook = std::function<std::shared_ptr<const Source>(
    const std::shared_ptr<const Source>& image, Node& image_node)>;

// What to carve into <out_dir>/partitions/.
enum class Carve : std::uint8_t {
    None,   // nothing; no partitions/ directory is created
    Table,  // every partition-table entry
    All,    // table entries plus every nested find (filesystem, container, kernel, ...)
};
const char* carve_name(Carve c);

struct AnalyzeOptions {
    std::string
        out_dir;  // case directory; extracted trees land under <out_dir>/filesystems/<id>/files
    bool extract = true;   // false: ListingSink, metadata only, nothing written
    bool history = false;  // emit superseded/deleted versions when the reader can
    Limits limits;         // run-wide: max_files / max_bytes are shared by every walk
    ScanOptions scan;
    // Gaps between claimed ranges shorter than this are not reported as Regions.
    std::uint64_t min_region_bytes = 4096;
    // Reader factory. Empty: every filesystem is "unsupported" (Coverage row).
    ReaderLookup open_reader;
    // Scanner override (tests). Empty: the builtin signatures with `scan`.
    Scanner scanner;
    // Word-swap extension point; see ImageViewHook.
    ImageViewHook image_view;
    // Carving into <out_dir>/partitions/. Ignored when out_dir is empty.
    Carve carve = Carve::All;
    std::uint64_t max_carve_bytes = 4ull << 30;  // per carved file
};

// One (filesystem node id, entries) pair per walked filesystem, in node order.
using Listings = std::vector<std::pair<std::string, std::vector<EntryResult>>>;

// Analyze `image` (the examiner's evidence, read as `evidence_path`) into `out`.
// Appends one Evidence row and an Image node plus everything found beneath it;
// `out.run` is left to the caller. Fails only on caller errors (null image,
// extraction requested without out_dir); hostile images produce nodes,
// diagnostics and coverage rows, never a failure.
Status analyze(const std::shared_ptr<const Source>& image, const std::string& evidence_path,
               const AnalyzeOptions& opts, Manifest& out, Listings& listings);

// The mount script for <out_dir>/partitions/: the examiner's template with
// PARTITION_NAMES / PARTITION_TYPES filled from every carved file that holds a
// loop-mountable filesystem (a partition whose first byte is a filesystem, or
// a nested filesystem carved on its own) and the Linux `mount -t` type for it.
// jffs2 / ubifs / yaffs2 carves are listed in a comment with the mtdram /
// nandsim instructions instead. Deterministic: rendered from `m` only.
std::string mount_script_text(const Manifest& m);

// Linux `mount -t` type for a filesystem format ("ext4" for ext2/3/4, "vfat"
// for fat, ...); empty when the format is not loop-mountable this way.
std::string mount_type_for(const std::string& format);

}  // namespace omnitrace::discovery
