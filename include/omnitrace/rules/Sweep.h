// Sweep.h — running a rule Engine over a finished case.
/// @file Sweep.h
/// @brief Applies the rules to everything `analyze()` produced, and collects
/// the hits into the case directory's `artifacts.yaml`.
///
/// The sweep runs **after** the evidence graph exists, not during it. That is
/// deliberate: `discovery` has no business knowing what an examiner is looking
/// for, and a hit has to be able to name the node it came from, which only
/// exists once the graph is built. It also means a case can be swept again
/// with a different pack without re-extracting anything.
///
/// Two things are searched, and they are the two the extraction actually
/// produced:
///
/// * **extracted files** — every entry a reader wrote, by path and by content;
/// * **unidentified regions** — the bytes no signature claimed, which is where
///   a string table or a stray key survives with no filesystem around it.
///
/// A region whose entropy class is `erased` or `random` is skipped: fill bytes
/// hold nothing, and uniformly random bytes hold nothing a pattern can find.
/// Saying so costs one line and saves reading gigabytes.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/discovery/Recurse.h"
#include "omnitrace/rules/Rule.h"

namespace omnitrace::rules {

/// A hit, placed in the case.
struct ArtifactHit {
    std::string node;       ///< Node the hit belongs to: a file, or a region.
    std::string path;       ///< Entry path inside its filesystem; empty for a region.
    std::string host_path;  ///< Where the file is in the case directory; empty for a region.
    Hit hit;
};

/// What a sweep did and found.
struct SweepResult {
    std::vector<ArtifactHit> hits;
    std::uint64_t files_scanned = 0;
    std::uint64_t regions_scanned = 0;
    std::uint64_t regions_skipped = 0;  ///< Erased or random: nothing a pattern could find.
    std::uint64_t bytes_scanned = 0;
    bool truncated = false;  ///< A cap stopped the sweep before it ran out of material.
    std::vector<Diagnostic> diagnostics;
};

/// Run `engine` over the case `m` describes.
///
/// `image` is the view the analysis ran on — for a word-swapped dump that is
/// the corrected one, which `analyze` wrote to `flash/`; pass an empty Span to
/// skip regions entirely. `listings` supplies the extracted files, so a sweep
/// with `--no-extract` finds only what a path rule can see.
///
/// Never fails as a whole: an unreadable file becomes a diagnostic and the
/// sweep carries on, because one bad entry is not a reason to abandon the
/// other seventy thousand.
Status sweep(const Engine& engine, const Manifest& m, const discovery::Listings& listings,
             const Span& image, const ScanLimits& limits, SweepResult& out);

/// Schema tag written as the first key of `artifacts.yaml` and checked on read.
inline constexpr const char* kArtifactsSchema = "omnitrace-artifacts/1";

/// `artifacts.yaml`: the hits, grouped by rule, with their provenance.
std::string artifacts_to_yaml(const Manifest& m, const SweepResult& r);
/// `artifacts.md`: the same for a person — a summary by severity and
/// category, then a table per rule that fired.
std::string artifacts_to_markdown(const Manifest& m, const SweepResult& r);

/// Read an `artifacts.yaml` back into a `SweepResult`. Fails (never throws)
/// with "artifacts: ..." on a YAML error, a `schema` other than
/// `omnitrace-artifacts/1`, or a missing/mistyped field; `out` is untouched on
/// failure.
///
/// The inverse of `artifacts_to_yaml`, and the last piece that lets
/// `omnitrace report <case>` rebuild every section from a case directory. A
/// sweep wants the *image* -- re-reading a 16 GiB dump to re-find hits the
/// case already records is work for no gain -- so this is how the search
/// section comes back without one.
///
/// Two fields do not survive the round trip, and neither is one a report uses:
/// `host_path`, which the writer does not record because a hit is placed by
/// `node` and `path`, and `Hit::match`/`context` for a hit whose bytes were
/// not quoted. The summary counters come from the file rather than being
/// recounted, because `files_scanned` and the region tallies cannot be derived
/// from the hits.
///
/// A `summary.hits` that disagrees with the number of `hits:` entries is a
/// **failure**, not a smaller result: the usual cause is a file cut short
/// while being written, and a report that quietly said "0 hits" over a
/// truncated sweep would be the most misleading thing this could produce.
Status artifacts_from_yaml(const std::string& text, SweepResult& out);

}  // namespace omnitrace::rules
