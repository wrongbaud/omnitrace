// Markdown.h — human/agent readable renderings of the case. Deterministic.
/// @file Markdown.h
/// @brief Markdown renderers for the case (summary.md, partitions.md,
/// listing.md) and the small table/number helpers they share.
///
/// Every renderer is a pure function of its input, so the same Manifest gives
/// byte-identical text; every evidence string is `sanitize_utf8`'d and
/// `md_escape`'d on the way out. INFO.md is assembled by the CLI from these
/// pieces (docs/CASE_LAYOUT.md).
#pragma once
#include <string>
#include <vector>

#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"

/// @namespace omnitrace::output
/// @brief Serialization: YAML manifest/listings, JSON Schema, Markdown.
namespace omnitrace::output {

// summary.md: evidence table, run info, counts by kind, coverage, top-level map.
/// summary.md: run info, evidence table, counts by kind, the structural map
/// (image / partition / container / filesystem / region nodes), coverage and
/// run-level diagnostics.
std::string summary_markdown(const Manifest& m);
// partitions.md: every Partition/Container/Filesystem/Region node as a table row
// (offset, size, kind, format, confidence, warnings), nested by depth.
/// partitions.md: every Partition / Container / Filesystem / Region node as a
/// table row (offset, size, kind, format, confidence, warnings), nested by depth.
std::string partitions_markdown(const Manifest& m);
// listing.md for one filesystem.
/// listing.md for one filesystem: one row per `EntryResult`.
std::string listing_markdown(const std::string& fs_node_id,
                             const std::vector<EntryResult>& entries);

// Helpers shared by all renderers.
/// Escape a cell for a Markdown table: `|` and `\` are backslashed, `\n`
/// `\r` `\t` become their escapes, other control bytes become `\xNN`.
std::string md_escape(const std::string& s);
/// A GitHub-style table; a short row leaves its remaining cells blank. Cells
/// are inserted as given, so pass them through `md_escape` first.
std::string md_table(const std::vector<std::string>& header,
                     const std::vector<std::vector<std::string>>& rows);
/// "512 B", "1.5 MiB", "16.0 MiB": one decimal, binary units, locale-independent.
std::string human_bytes(std::uint64_t n);
/// "0x" + lowercase hex, no padding.
std::string hex(std::uint64_t v);

}  // namespace omnitrace::output
