// Compression.h — bounded decompressors. Every codec takes an explicit output
// cap and returns Status::fail("...ratio...") rather than growing unbounded.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Status.h"

namespace omnitrace::compress {

enum class Codec { None, Zlib, Deflate, Gzip, Xz, Lzma, Lz4, Lz4Legacy, Zstd, Lzo1x, Rtime };
const char* codec_name(Codec c);

// Decompress `in` into `out` (cleared first). `max_out` caps the output; on cap
// hit returns fail with code "decompress-cap".
Status decompress(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                  std::uint64_t max_out);

// Raw-block variants used by filesystems (SquashFS/UBIFS blocks, JFFS2 nodes):
// exact expected output size, fail if the stream produces more or less.
Status decompress_exact(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                        std::size_t expected);

}  // namespace omnitrace::compress
