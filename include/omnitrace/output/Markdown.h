// Markdown.h — human/agent readable renderings of the case. Deterministic.
#pragma once
#include <string>
#include <vector>

#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"

namespace omnitrace::output {

// summary.md: evidence table, run info, counts by kind, coverage, top-level map.
std::string summary_markdown(const Manifest& m);
// partitions.md: every Partition/Container/Filesystem/Region node as a table row
// (offset, size, kind, format, confidence, warnings), nested by depth.
std::string partitions_markdown(const Manifest& m);
// listing.md for one filesystem.
std::string listing_markdown(const std::string& fs_node_id,
                             const std::vector<EntryResult>& entries);

// Helpers shared by all renderers.
std::string md_escape(const std::string& s);
std::string md_table(const std::vector<std::string>& header,
                     const std::vector<std::vector<std::string>>& rows);
std::string human_bytes(std::uint64_t n);
std::string hex(std::uint64_t v);

}  // namespace omnitrace::output
