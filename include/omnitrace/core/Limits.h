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
    std::uint64_t max_files = 500'000;     ///< Entries a Sink accepts per run ("sink-limit-files").
    std::uint64_t max_bytes = 4ull << 30;  ///< Floor for the total bytes a Sink accepts per run
                                           ///< ("sink-limit-bytes"); the rest of the entry is
                                           ///< dropped and `truncated` set. See `max_bytes_ratio`.
    /// Extraction budget as a multiple of the image, which is what makes the
    /// budget track the evidence: `analyze` raises `max_bytes` to
    /// `image_size * max_bytes_ratio` when that is larger, so a 2 MiB SPI dump
    /// keeps the floor above and a 16 GiB eMMC image gets room to be extracted
    /// at all. A fixed byte count cannot do both, and the fixed 4 GiB this
    /// replaced silently truncated every large image.
    ///
    /// The ratio is the guard that matters: legitimate firmware expands by up
    /// to ~5x (a compressed SquashFS router image), and the floor already
    /// covers those because they are small. A decompression bomb expands by
    /// orders of magnitude more and still trips.
    ///
    /// 0 means use `max_bytes` exactly -- what the CLI sets when `--max-bytes`
    /// is given, so an explicit budget is never silently raised.
    std::uint64_t max_bytes_ratio = 4;
    std::uint64_t max_file_bytes =
        1ull << 30;  ///< Floor for the bytes of one entry a Sink accepts
                     ///< ("sink-limit-file-bytes"). See `max_file_bytes_ratio`.
    /// Per-entry cap as a multiple of the image, for the same reason
    /// `max_bytes_ratio` exists: a fixed byte count cannot suit both a 2 MiB
    /// SPI part and a 16 GiB eMMC dump.
    ///
    /// The multiple is 1 because a *stored* entry cannot be larger than the
    /// image that holds it, so the image size is the tightest cap that can
    /// never cut legitimate content -- and cutting it is not a partial
    /// recovery. A truncated data file still yields its first N bytes, but a
    /// truncated *filesystem image* yields nothing at all: SquashFS, ext and
    /// zip all keep the tables that name their contents at the end, so
    /// removing the tail removes every file inside. The fixed 1 GiB this
    /// replaced did exactly that to two 1054 MiB SquashFS images inside a
    /// 15.7 GiB QNX dump, losing ~100,000 files and the compressed streams
    /// among them (`docs/PARITY.md`).
    ///
    /// This does not loosen the bomb guard, which was never this field's job:
    /// a stored entry's size is known from metadata before a byte is written,
    /// and a *decompressed* entry -- the one whose size is not known in
    /// advance -- is bounded by `max_decompress_ratio` instead.
    ///
    /// 0 means use `max_file_bytes` exactly -- what the CLI sets when
    /// `--max-file-bytes` is given, so an explicit cap is never raised.
    std::uint64_t max_file_bytes_ratio = 1;
    /// Out/in cap for one decompressed stream, and the guard that stands in
    /// for `max_file_bytes` where a size is not known in advance: the readers
    /// that decompress pass `min(max_file_bytes, in_bytes * this)` as `max_out`
    /// (`QnxIfsReader`, `StreamReader`). Real firmware expands by up to ~32x
    /// measured across the corpus; a bomb expands by orders of magnitude more
    /// and still trips.
    std::uint64_t max_decompress_ratio = 1000;
    std::uint64_t max_nodes_per_fs =
        5'000'000;  ///< Metadata records one filesystem reader parses (SquashFS directory entries
                    ///< today; JFFS2 nodes, inodes later).
    /// History: superseded versions kept per entry path (oldest dropped first, with a
    /// `<fmt>-limit-versions` diagnostic). Applies to JFFS2/UBIFS/YAFFS2 and QNX6 snapshots.
    std::uint32_t max_versions_per_entry = 64;
};

}  // namespace omnitrace
