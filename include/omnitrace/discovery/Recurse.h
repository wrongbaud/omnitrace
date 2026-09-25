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
//      the caller supplies into <out_dir>/filesystems/<node-id>/files, and
//      every Container node with the container reader the caller supplies into
//      <out_dir>/containers/<node-id>/files; one File node per emitted entry.
//      A gzip or xz container holds one entry, "payload"; the reader also
//      reports where the stream ended, so the node gets the extent the
//      validator could not know. A container with no registered reader is a
//      Coverage row ("unsupported") and a Diagnostic, never silent.
//   5. Every file that walk wrote to the host is re-scanned. When it holds a
//      filesystem or a partition table at Structural or better and at least
//      min_region_bytes long, the whole pass
//      runs again over its bytes with the File node as the parent and depth+1, so a
//      filesystem stored as a file inside another one (the QNX6 "storage"
//      partition keeps its SquashFS update images that way) becomes a real
//      Filesystem node with its own tree. Offsets under it are relative to
//      the extracted file and Location::source_id names it. A file whose scan
//      yields only Region finds, only Container finds (no reader can open the
//      payload yet) or only magic-tier hits keeps no children.
//   6. With carve != Carve::None and a non-empty out_dir, every partition entry
//      (and, with Carve::All, every nested find) is streamed to
//      <out_dir>/partitions/<name>.bin, hashed as it is written; the node gets
//      digests and attrs carved_path. <out_dir>/partitions/mount.sh is then
//      generated (see mount_script_text). A file larger than max_carve_bytes
//      is skipped with a Coverage row {"carve","partial",...} and a Diagnostic.
//
// analyze_span() is the per-span worker and is called recursively for every
// file a filesystem or container walk wrote to the host, so a payload that is
// itself an image is analysed like any other extracted file.
//
// Layering: this file lives in discovery and therefore cannot link against the
// filesystems library. Readers are supplied by the caller through
// AnalyzeOptions::open_reader; the CLI passes FilesystemRegistry::create.
/// @file Recurse.h
/// @brief `analyze()`, the driver that turns one image into a `Manifest` and
/// a case directory, with its options and the mount-script helpers.
///
/// What it does today versus the plan: the image, the partitions inside it,
/// every file extracted from a filesystem or a container payload, re-scanned
/// and analysed again when it is itself an image (`Limits::max_depth` bounds
/// the nesting). Word-swap detection *is* implemented (see `ImageViewHook`).
/// docs/CASE_LAYOUT.md documents the resulting nodes, attrs and files.
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Limits.h"
#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Status.h"
#include "omnitrace/discovery/Signature.h"
#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::discovery {

// Returns a reader for `format`, or nullptr when none is available.
/// Reader factory: a fresh `fs::FilesystemReader` for `format`, or `nullptr`
/// when none exists (the node then gets an "unsupported" Coverage row). The
/// CLI passes a lambda around `fs::FilesystemRegistry::instance().create`.
using ReaderLookup =
    std::function<std::unique_ptr<fs::FilesystemReader>(const std::string& format)>;

// Returns a container reader for `format`, or nullptr when none is available.
/// Container reader factory, the `container::ContainerReader` twin of
/// `ReaderLookup`. Supplied by the caller for the same layering reason: this
/// header lives in discovery and cannot link the containers library. The CLI
/// passes a lambda around `container::ContainerRegistry::instance().create`.
/// Empty: every container is "unsupported", as before any reader existed.
using ContainerLookup =
    std::function<std::unique_ptr<container::ContainerReader>(const std::string& format)>;

// Scanner used for the whole image and for every partition re-scan. Tests
// substitute hand-made findings; the default is scan(span, builtin, opts.scan).
/// Scanner used for the whole image and for every partition re-scan. Tests
/// substitute hand-made findings; the default is
/// `scan(span, SignatureSet::builtin(), opts.scan)`.
using Scanner = std::function<std::vector<Finding>(const Span& span)>;

// EXTENSION POINT (word swap; not implemented here). Called once, before the
// whole-image scan, with the evidence Source and the Image node already in the
// graph. Returns the Source the scan should run on: the same one, or a derived
// view such as core/Swap.h SwappedSource chosen by detect_word_swap(). The hook
// records what it decided on `image_node` (attrs, diagnostics such as
// "image-word-swapped"). Empty (the default): the image is analysed as is.
/// Chooses the Source the analysis runs on. Called once, before the
/// whole-image scan, with the evidence Source and the Image node already in
/// the graph. Return the same Source, or a derived view such as a
/// `SwappedSource`, and record the decision on `image_node` (attrs,
/// diagnostics); returning `nullptr` keeps the image as is.
///
/// When the hook is empty (the default), `analyze()` runs `detect_word_swap`
/// itself: a detected swap sets attrs `word_swap` / `word_swap_confidence`,
/// the "image-word-swapped" warning (plus "image-word-swap-tail" for a
/// partial last word), a "word-swap" Coverage row, and every node found
/// beneath carries "<evidence-id>|swap16|32" in `Location::source_id`.
using ImageViewHook = std::function<std::shared_ptr<const Source>(
    const std::shared_ptr<const Source>& image, Node& image_node)>;

// What to carve into <out_dir>/partitions/.
/// What to carve into `<out_dir>/partitions/` (CLI `--carve`).
enum class Carve : std::uint8_t {
    None,   ///< Nothing; no partitions/ directory is created.
    Table,  ///< Every partition-table entry.
    All,    ///< Table entries plus every nested find directly under the image or a partition
            ///< (filesystem, container, kernel, ...).
};
/// "none", "table", "all".
const char* carve_name(Carve c);

/// Everything `analyze()` needs beyond the image.
struct AnalyzeOptions {
    std::string out_dir;  ///< Case directory; extracted trees land under
                          ///< `<out_dir>/filesystems/<id>/files`.
    bool extract =
        true;  ///< false: a `ListingSink` per filesystem, metadata only, nothing written.
    bool history =
        false;  ///< Ask readers for superseded/deleted versions (`fs::WalkOptions::history`).
    /// Write a tar of every extracted tree beside its `files/` directory, for
    /// handing the case to someone else.
    ///
    /// An extracted tree carries symlinks, permission bits that deny their own
    /// owner read, device nodes and names that are not valid UTF-8. Copy it
    /// onto exFAT, a Windows share or cloud storage and every one of those is
    /// dropped without a word. The archive is written from the same entries as
    /// the tree, in one pass, so it is faithful even where the host filesystem
    /// is not. It roughly doubles what a case takes on disk, which is why it
    /// is asked for rather than assumed.
    bool tar_filesystems = false;
    Limits limits;     ///< Run-wide: `max_files` / `max_bytes` are shared by every walk.
    ScanOptions scan;  ///< Passed to the default Scanner.
    std::uint64_t min_region_bytes =
        4096;                  ///< Gaps shorter than this are not reported as Region nodes.
    ReaderLookup open_reader;  ///< Reader factory. Empty: every filesystem is "unsupported".
    ContainerLookup
        open_container;  ///< Container reader factory. Empty: every container is "unsupported".
    Scanner scanner;     ///< Scanner override (tests). Empty: the builtin signatures with `scan`.
    ImageViewHook image_view;  ///< See `ImageViewHook`. Empty: automatic word-swap detection.
    Carve carve =
        Carve::All;  ///< Carving into `<out_dir>/partitions/`; ignored when `out_dir` is empty.
    /// Per carved file; a larger one gets `carve_skipped` and a
    /// "carve"/"partial" Coverage row.
    ///
    /// 32 GiB because a partition can be that big and an examiner wants it.
    /// The 4 GiB this replaced skipped the 15.2 GB `storage` partition of a
    /// QNX vehicle unit -- the one holding everything -- and a UFS dump's
    /// partitions are larger still. The guard against filling a disk is not
    /// this: the extraction budget is cut to free space up front
    /// (`analyze-limit-disk`) and every carve is checked as it is written
    /// (`carve-limit-disk`), because this is per file and nothing else bounds
    /// carving in aggregate.
    std::uint64_t max_carve_bytes = 32ull << 30;
    /// Write the view the analysis actually ran on to
    /// `<out_dir>/flash/<stem>-<transform>.bin` whenever that view is not the
    /// evidence itself -- today, a word-swapped image. Without it the case
    /// directory records that the bytes were corrected but holds no file an
    /// examiner or another tool can work from, and every offset in the
    /// manifest refers to bytes that exist nowhere on disk. Bounded by
    /// `max_carve_bytes`; ignored when `out_dir` is empty or the view is the
    /// evidence.
    bool write_corrected_view = false;
};

/// The extraction budget `analyze()` applies, from the run's `Limits` and the
/// image size: `max(max_bytes, image_size * max_bytes_ratio)`, saturating, and
/// exactly `max_bytes` when the ratio is 0. Exposed because it is policy, not
/// arithmetic -- a caller assembling its own pipeline wants the same answer,
/// and it is the one place the "budget tracks the evidence" rule lives.
std::uint64_t extraction_budget(const Limits& lim, std::uint64_t image_size);

/// The per-entry cap `analyze()` applies, the same rule for one entry:
/// `max(max_file_bytes, image_size * max_file_bytes_ratio)`, saturating, and
/// exactly `max_file_bytes` when the ratio is 0 (`core/Limits.h` explains why
/// the multiple is 1).
std::uint64_t entry_budget(const Limits& lim, std::uint64_t image_size);

/// How many bytes a run may write to a filesystem with `available` bytes free,
/// leaving it room to keep working: `available` less 5% of itself, and never
/// less than 256 MiB of headroom. Returns 0 when there is not even that.
///
/// Pure, so the policy can be tested without a full disk. `analyze()` asks the
/// output filesystem for `available` and clamps both write paths to the
/// result: the extraction budget up front, and each carve as it comes.
std::uint64_t disk_headroom(std::uint64_t available);

// One (filesystem node id, entries) pair per walked filesystem, in node order.
/// One (filesystem node id, entries) pair per walked filesystem, in node
/// order; the input to `output::listing_to_yaml` / `listing_markdown`.
using Listings = std::vector<std::pair<std::string, std::vector<EntryResult>>>;

// Analyze `image` (the examiner's evidence, read as `evidence_path`) into `out`.
// Appends one Evidence row and an Image node plus everything found beneath it;
// `out.run` is left to the caller. Fails only on caller errors (null image,
// extraction requested without out_dir); hostile images produce nodes,
// diagnostics and coverage rows, never a failure.
/// Run the pipeline in the file comment on `image` and append the result to
/// `out`: one Evidence row (id "e<n>", path `evidence_path`, digests from
/// `hash_span`), an Image node, and everything found beneath it. `out.run` is
/// left to the caller.
///
/// Fails only on caller errors: "analyze-no-image" (null `image`) and
/// "analyze-no-out-dir" (`extract` without `out_dir`). A hostile image
/// produces nodes, diagnostics and Coverage rows, never a failure. Writes
/// to the host only under `opts.out_dir` (`filesystems/<id>/files`,
/// `partitions/`); the manifest and Markdown files are the CLI's job.
///
/// ```cpp
/// omnitrace::Manifest m;
/// omnitrace::discovery::Listings listings;
/// omnitrace::discovery::AnalyzeOptions opts;
/// opts.out_dir = "case-router";
/// opts.open_reader = [](const std::string& f) {
///     return omnitrace::fs::FilesystemRegistry::instance().create(f);
/// };
/// if (auto st = omnitrace::discovery::analyze(file, "router.bin", opts, m, listings); !st)
///     return st;
/// std::string yaml = omnitrace::output::manifest_to_yaml(m);
/// ```
Status analyze(const std::shared_ptr<const Source>& image, const std::string& evidence_path,
               const AnalyzeOptions& opts, Manifest& out, Listings& listings);

// The mount script for <out_dir>/partitions/: the examiner's template with
// PARTITION_NAMES / PARTITION_TYPES filled from every carved file that holds a
// loop-mountable filesystem (a partition whose first byte is a filesystem, or
// a nested filesystem carved on its own) and the Linux `mount -t` type for it.
// jffs2 / ubifs / yaffs2 carves are listed in a comment with the mtdram /
// nandsim instructions instead. Deterministic: rendered from `m` only.
/// Text of `<out_dir>/partitions/mount.sh`: the examiner's template with
/// `PARTITION_NAMES` / `PARTITION_TYPES` filled from every carved file whose
/// first byte is a loop-mountable filesystem, in image order. jffs2 / ubifs /
/// yaffs2 carves go in a comment block with mtdram / nandsim instructions.
/// Deterministic: rendered from `m` only.
std::string mount_script_text(const Manifest& m);

// Linux `mount -t` type for a filesystem format ("ext4" for ext2/3/4, "vfat"
// for fat, ...); empty when the format is not loop-mountable this way.
/// Linux `mount -t` type for a filesystem format ("ext4" for ext2/3/4, "vfat"
/// for fat, ...); empty when the format is not loop-mountable this way
/// (table in docs/CASE_LAYOUT.md).
std::string mount_type_for(const std::string& format);

}  // namespace omnitrace::discovery
