// Compression.h — bounded decompressors. Every codec takes an explicit output
// cap and returns Status::fail("...ratio...") rather than growing unbounded.
/// @file Compression.h
/// @brief Bounded decompressors for every codec a supported format uses.
///
/// Error behaviour: `Status::error` is one of the stable codes
/// `decompress-cap`, `decompress-corrupt`, `decompress-truncated`,
/// `decompress-empty-input`, `decompress-init-failed`, `decompress-memlimit`,
/// `decompress-unsupported`, `decompress-size-mismatch`,
/// `decompress-trailing-input`, `decompress-checksum-mismatch`; nothing
/// throws. Thread-safety: pure functions with no shared state.
///
/// `decompress-checksum-mismatch` is the one failure that still leaves a
/// usable result: the compressed data decoded to its natural end and then
/// disagreed with the checksum the producer recorded in the stream's own
/// header, so `out` holds the complete payload and the mismatch is itself
/// evidence of damage. Only gzip, zlib, lz4 and zstd can tell the two apart;
/// xz, lzma and bzip2 report their libraries' undifferentiated data error
/// either way, so a bad check there surfaces as `decompress-corrupt`.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "omnitrace/core/Status.h"

/// @namespace omnitrace::compress
/// @brief Bounded decompression (`decompress`, `decompress_exact`).
namespace omnitrace::compress {

/// Stream or block format. `Zlib` auto-detects a zlib or gzip wrapper; `Lz4`
/// auto-detects an LZ4 frame, the legacy `02 21 4C 18` format or a raw block;
/// `Lz4Legacy` accepts the legacy format or a raw block; `Lzo1x` and `Rtime`
/// are the in-tree decoders used by SquashFS-LZO and JFFS2.
enum class Codec { None, Zlib, Deflate, Gzip, Xz, Lzma, Bzip2, Lz4, Lz4Legacy, Zstd, Lzo1x, Rtime };
/// "none", "zlib", "deflate", "gzip", "xz", "lzma", "bzip2", "lz4",
/// "lz4-legacy", "zstd", "lzo1x", "rtime"; "unknown" otherwise.
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

/// The integrity check the stream at the start of `in` declares in its own
/// header: `crc32`, `adler32`, `crc64`, `sha256`, `xxh32` or `xxh64`; `none`
/// when the stream carries no check over its payload; and the empty string
/// when the codec is a bare block, or the header is too short or names a
/// check this build cannot. Reads the header only -- it does not decode, so
/// it is free to call before one.
///
/// This is what lets a reader say *which* guarantee a payload came with. The
/// libraries all verify their own check while decoding; the format knowledge
/// of where that check is recorded, and whether the producer wrote one at
/// all, lives here.
std::string stream_check(Codec c, std::span<const std::uint8_t> in);

// How long the stream at the start of `in` is, without keeping its output.
/// Run the decoder to the end of the stream and report only its measurements:
/// `consumed` input bytes and `produced` output bytes. The payload is
/// discarded as it is produced, so measuring a multi-gigabyte stream costs one
/// 64 KiB window. This is what lets a validator give a compressed finding a
/// real extent — a deflate or xz header says nothing about where the stream
/// ends — without holding the decompressed image in memory.
///
/// Supported for the wrapped stream codecs (`Zlib`, `Deflate`, `Gzip`, `Xz`,
/// `Lzma`, `Bzip2`) and the framed ones (`Lz4` when the input starts with a frame
/// magic, `Zstd`); anything else fails with "decompress-unsupported". On any
/// failure `consumed` and `produced` still hold how far the decoder got.
Status stream_length(Codec c, std::span<const std::uint8_t> in, std::uint64_t max_out,
                     std::uint64_t& consumed, std::uint64_t& produced);

/// Did this decode stop because the *data* ran out, rather than because the
/// stream broke?
///
/// `error` is the failing `Status::error` from `stream_length` or
/// `decompress_stream`, `consumed`/`produced` its measurements, `avail` the
/// bytes that were offered. True means every available byte decoded and the
/// decoder still wanted more: what came out is real, and nothing follows it
/// that could be something else, because it used everything.
///
/// This is the line between a stream an image cut short and a magic that
/// landed in unrelated bytes, and it decides whether either layer will claim
/// an extent or emit a payload. It is one function because the validator and
/// the reader must not answer it differently — a reader more permissive than
/// its validator turns a guess into bytes on disk.
///
/// The three conditions, each measured against the corpus rather than assumed:
///
/// * **`decompress-truncated`, not `decompress-corrupt`.** All 195 hits the
///   corpus cannot measure fail as corrupt, 181 of them accidental `1f 8b 08`
///   runs in the QNX image's speech data.
/// * **`consumed == avail`.** Tested rather than inferred, because the lzma
///   and lz4 decoders also report a stall as truncated without having
///   exhausted their input.
/// * **`produced > 0`.** A header in the last bytes of a region would
///   otherwise claim them for nothing.
///
/// How *much* came out is deliberately not a condition: a stray gzip header
/// inside compressed data happily yields megabytes of garbage (one in the router-wrt
/// image produces 3774806 bytes before it breaks), so output volume is
/// evidence of nothing.
bool stream_ran_out(std::string_view error, std::uint64_t consumed, std::uint64_t produced,
                    std::uint64_t avail);

// Raw-block variants used by filesystems (SquashFS/UBIFS blocks, JFFS2 nodes):
// exact expected output size, fail if the stream produces more or less.
/// Block variant for filesystems that know the decompressed size (SquashFS
/// blocks, JFFS2 nodes): `expected` is both the cap and the required output
/// size; a stream that yields more fails with "decompress-cap", less with
/// "decompress-size-mismatch", and LZO input with unread trailing bytes with
/// "decompress-trailing-input".
Status decompress_exact(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                        std::size_t expected);

/// One step of a raw (unframed) filter chain, as 7z records a coder and xz
/// records a filter: a liblzma filter id and the properties bytes the
/// container stored for it.
struct RawFilter {
    std::uint64_t id = 0;             ///< `LZMA_FILTER_*`.
    std::vector<std::uint8_t> props;  ///< As stored; liblzma decodes them.
};

/// Filter ids, so callers need not include `lzma.h`. These are liblzma's own
/// values, which are also the ones the .xz format uses.
inline constexpr std::uint64_t kFilterDelta = 0x03;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterX86 = 0x04;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterPowerPc = 0x05;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterIa64 = 0x06;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterArm = 0x07;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterArmThumb = 0x08;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterSparc = 0x09;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterArm64 = 0x0A;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterRiscV = 0x0B;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterLzma2 = 0x21;
/// @copydoc kFilterDelta
inline constexpr std::uint64_t kFilterLzma1 = 0x4000000000000001ull;
/// LZMA1 told how long its output is, so it can stop without an end marker.
/// 7z stores raw LZMA1 with the size in the header and usually no marker, and
/// a byte filter after it only flushes its held-back tail once the decoder
/// below says the data is over -- which plain `kFilterLzma1` never does.
/// `decompress_raw` sets the size from its `expected` argument.
inline constexpr std::uint64_t kFilterLzma1Ext = 0x4000000000000002ull;

/// Decode `in` through a raw liblzma filter chain into `out`, which must come
/// to exactly `expected` bytes.
///
/// `chain` is in **encoding order**, which is what liblzma wants: the
/// compressor last, any byte filter before it. A container that records its
/// coders in decoding order (7z walks them from the packed stream outwards)
/// has to reverse them first.
///
/// Fails with "decompress-unsupported" when a filter id is not one this build
/// has, "decompress-props" when a coder's properties do not decode, and the
/// usual "decompress-cap" / "decompress-size-mismatch" otherwise. Nothing here
/// throws.
Status decompress_raw(std::span<const RawFilter> chain, std::span<const std::uint8_t> in,
                      std::vector<std::uint8_t>& out, std::size_t expected);

}  // namespace omnitrace::compress
