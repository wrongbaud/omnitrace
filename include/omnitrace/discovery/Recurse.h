// Recurse.h — the analysis driver: image -> findings -> evidence graph.
//
// analyze() hashes the image, scans it with the builtin signatures, turns every
// top-level finding into a Node (partition tables become one Partition node per
// entry), walks every filesystem for which the caller can supply a reader into
// a Sink under <out_dir>/filesystems/<node-id>/files, records one File node per
// emitted entry, and reports every unclaimed gap as a Region node. Formats that
// are recognised but have no reader become a Coverage row ("unsupported").
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

}  // namespace omnitrace::discovery
