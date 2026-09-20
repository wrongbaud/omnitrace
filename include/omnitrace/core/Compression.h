// Compression.h — bounded decompressors. Every codec takes an explicit output
// cap and returns Status::fail("...ratio...") rather than growing unbounded.
/// @file Compression.h
/// @brief Bounded decompressors for every codec a supported format uses.
///
/// Error behaviour: `Status::error` is one of the stable codes
/// `decompress-cap`, `decompress-corrupt`, `decompress-truncated`,
/// `decompress-empty-input`, `decompress-init-failed`, `decompress-memlimit`,
/// `decompress-unsupported`, `decompress-size-mismatch`,
/// `decompress-trailing-input`; nothing throws. Thread-safety: pure functions
/// with no shared state.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Status.h"

/// @namespace omnitrace::compress
/// @brief Bounded decompression (`decompress`, `decompress_exact`).
namespace omnitrace::compress {

/// Stream or block format. `Zlib` auto-detects a zlib or gzip wrapper; `Lz4`
/// auto-detects an LZ4 frame, the legacy `02 21 4C 18` format or a raw block;
/// `Lz4Legacy` accepts the legacy format or a raw block; `Lzo1x` and `Rtime`
/// are the in-tree decoders used by SquashFS-LZO and JFFS2.
enum class Codec { None, Zlib, Deflate, Gzip, Xz, Lzma, Lz4, Lz4Legacy, Zstd, Lzo1x, Rtime };
/// "none", "zlib", "deflate", "gzip", "xz", "lzma", "lz4", "lz4-legacy",
/// "zstd", "lzo1x", "rtime"; "unknown" otherwise.
const char* codec_name(Codec c);

// Decompress `in` into `out` (cleared first). `max_out` caps the output; on cap
// hit returns fail with code "decompress-cap".
/// Decompress `in` into `out` (cleared first). `Codec::None` copies through.
/// @param max_out hard cap on the output size; a stream that would exceed it
/// fails with "decompress-cap" instead of growing.
Status decompress(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                  std::uint64_t max_out);

// Decompress the stream at the start of `in` and report how many input bytes
// it used, so the caller can size the stream inside a larger image.
/// Like `decompress`, and additionally sets `consumed` to the number of input
/// bytes the stream used: one past the last byte of the last member, so a
/// gzip or xz stream embedded in a larger image gets a real extent. Only the
/// wrapped stream codecs (`Zlib`, `Deflate`, `Gzip`, `Xz`, `Lzma`) measure it;
/// for the others the whole input is the unit and `consumed` is `in.size()`.
/// On failure `consumed` is how far the decoder got, which is still the best
/// available bound for a truncated or corrupt stream.
Status decompress_stream(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                         std::uint64_t max_out, std::uint64_t& consumed);

// How long the stream at the start of `in` is, without keeping its output.
/// Run the decoder to the end of the stream and report only its measurements:
/// `consumed` input bytes and `produced` output bytes. The payload is
/// discarded as it is produced, so measuring a multi-gigabyte stream costs one
/// 64 KiB window. This is what lets a validator give a compressed finding a
/// real extent — a deflate or xz header says nothing about where the stream
/// ends — without holding the decompressed image in memory.
///
/// Supported for the wrapped stream codecs (`Zlib`, `Deflate`, `Gzip`, `Xz`,
/// `Lzma`) and the framed ones (`Lz4` when the input starts with a frame
/// magic, `Zstd`); anything else fails with "decompress-unsupported". On any
/// failure `consumed` and `produced` still hold how far the decoder got.
Status stream_length(Codec c, std::span<const std::uint8_t> in, std::uint64_t max_out,
                     std::uint64_t& consumed, std::uint64_t& produced);

// Raw-block variants used by filesystems (SquashFS/UBIFS blocks, JFFS2 nodes):
// exact expected output size, fail if the stream produces more or less.
/// Block variant for filesystems that know the decompressed size (SquashFS
/// blocks, JFFS2 nodes): `expected` is both the cap and the required output
/// size; a stream that yields more fails with "decompress-cap", less with
/// "decompress-size-mismatch", and LZO input with unread trailing bytes with
/// "decompress-trailing-input".
Status decompress_exact(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                        std::size_t expected);

}  // namespace omnitrace::compress
