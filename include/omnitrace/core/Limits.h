// Limits.h — guard rails for hostile input. A tripped guard stops that branch,
// records a Diagnostic, and keeps everything recovered so far.
/// @file Limits.h
/// @brief The one place every cap lives (docs/ARCHITECTURE.md rule 4).
///
/// Readers never hard-code a limit; they read the field and, when it trips,
/// stop that branch, record a `Diagnostic{Warning, "<fmt>-limit-<what>"}`,
/// set `truncated` and keep what was recovered. The CLI exposes some fields as
/// `--max-depth`, `--max-files`, `--max-bytes` (docs/CLI.md).
#pragma once
#include <cstddef>
#include <cstdint>

namespace omnitrace {

/// Per-run caps. Defaults are generous for real firmware and small enough that
/// a zip bomb or a self-referencing directory cannot exhaust the host.
struct Limits {
    std::size_t max_depth = 8;  ///< Nesting levels `discovery::analyze` descends; deeper finds get
                                ///< an "analyze-limit-depth" run diagnostic.
    std::uint64_t max_files = 500'000;  ///< Entries a Sink accepts per run ("sink-limit-files").
    std::uint64_t max_bytes = 4ull
                              << 30;  ///< Total bytes a Sink accepts per run ("sink-limit-bytes");
                                      ///< the rest of the entry is dropped and `truncated` set.
    std::uint64_t max_file_bytes =
        1ull << 30;  ///< Bytes of one entry a Sink accepts ("sink-limit-file-bytes").
    std::uint64_t max_decompress_ratio =
        1000;  ///< Intended out/in cap for one stream. No reader consults it yet; they pass an
               ///< explicit `max_out` to `compress::decompress`.
    std::uint64_t max_nodes_per_fs =
        5'000'000;  ///< Metadata records one filesystem reader parses (SquashFS directory entries
                    ///< today; JFFS2 nodes, inodes later).
};

}  // namespace omnitrace
