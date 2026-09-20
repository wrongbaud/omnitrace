// Lzop.h — the lzop file format, shared by the validator and the reader.
/// @file Lzop.h
/// @brief Header and block parsing for `.lzo` files (the lzop tool, not the
/// bare LZO1X blocks SquashFS and JFFS2 use).
///
/// A `.lzo` file is one or more members laid end to end. Each is a header
/// (nine magic bytes, then the versions, method, flags, mode, mtime and the
/// original name, with a checksum over all of it) followed by blocks:
///
///     u32 uncompressed_len   -- 0 ends the member
///     u32 compressed_len     -- equal to the above when the block is stored
///     u32 checksum(s) of the uncompressed data, per the header's flags
///     u32 checksum(s) of the compressed data, when it is smaller
///     compressed_len bytes
///
/// Every integer is big-endian. Because the block lengths are in the stream,
/// a member's extent is found by walking the block headers alone -- no
/// decompression, which is what keeps the validator cheap on a magic hit.
///
/// It is in core because two layers read the same bytes: the `lzop` validator
/// decides what a region is and how long it is, and `container::LzopReader`
/// decodes the blocks. Everything here is pure and reads through the Span, so
/// it is safe from any thread.
///
/// Reference: lzop 1.04 (`src/lzop.c`, `src/conf.h`) and
/// <https://www.lzop.org/download/lzop-1.04.tar.gz> `doc/lzop.1`; read for
/// understanding, nothing copied.
#pragma once
#include <array>
#include <cstdint>
#include <string>

#include "omnitrace/core/Span.h"

/// @namespace omnitrace::lzop
/// @brief lzop (`.lzo`) header and block parsing.
namespace omnitrace::lzop {

/// The nine bytes every member starts with.
inline constexpr std::array<std::uint8_t, 9> kMagic{0x89, 0x4C, 0x5A, 0x4F, 0x00,
                                                    0x0D, 0x0A, 0x1A, 0x0A};

/// Header flags (`conf.h`). The low fourteen bits are the format's; the top
/// byte carries the operating system that wrote the file.
inline constexpr std::uint32_t kAdler32D = 0x00000001u;  ///< Adler-32 of each block's data.
inline constexpr std::uint32_t kAdler32C = 0x00000002u;  ///< ... of the compressed bytes.
inline constexpr std::uint32_t kHExtraField = 0x00000040u;  ///< An extra field follows the header.
inline constexpr std::uint32_t kCrc32D = 0x00000100u;    ///< CRC-32 of each block's data.
inline constexpr std::uint32_t kCrc32C = 0x00000200u;    ///< ... of the compressed bytes.
inline constexpr std::uint32_t kMultipart = 0x00000400u;
inline constexpr std::uint32_t kHFilter = 0x00000800u;   ///< A filter id follows the flags.
inline constexpr std::uint32_t kHCrc32 = 0x00001000u;    ///< The header checksum is CRC-32.
inline constexpr std::uint32_t kHPath = 0x00002000u;

/// Compression methods (`conf.h`). Only the LZO1X ones are produced.
inline constexpr std::uint8_t kMethodLzo1x1 = 1, kMethodLzo1x115 = 2, kMethodLzo1x999 = 3;
/// lzop can be built against zlib; such a file is recognised but not decoded.
inline constexpr std::uint8_t kMethodZlib = 128;

/// The largest block lzop will write (`conf.h` MAX_BLOCK_SIZE), which bounds
/// what one block may claim.
inline constexpr std::uint32_t kMaxBlockSize = 64u * 1024u * 1024u;
/// A name longer than this is not one lzop wrote.
inline constexpr std::uint8_t kMaxNameLen = 255;

/// One member's header.
struct Header {
    std::uint16_t version = 0;         ///< lzop version that wrote it (0x1040 = 1.04).
    std::uint16_t lib_version = 0;     ///< LZO library version.
    std::uint16_t version_needed = 0;  ///< Oldest lzop that can read it.
    std::uint8_t method = 0;
    std::uint8_t level = 0;
    std::uint32_t flags = 0;
    std::uint32_t filter = 0;
    std::uint32_t mode = 0;       ///< The original file's mode, or 0.
    std::uint64_t mtime = 0;      ///< Unix seconds; 0 when not recorded.
    std::string name;             ///< The original name, raw; sanitize before output.
    bool checksum_ok = false;     ///< The header matches its own checksum.
    std::uint64_t first_block = 0;  ///< Span offset of the first block header.

    /// True when the method is one this build can decode.
    bool decodable() const {
        return method == kMethodLzo1x1 || method == kMethodLzo1x115 || method == kMethodLzo1x999;
    }
};

/// One block of a member.
struct Block {
    std::uint64_t at = 0;             ///< Span offset of the (possibly compressed) bytes.
    std::uint32_t uncompressed = 0;
    std::uint32_t compressed = 0;
    std::uint32_t data_adler = 0, data_crc = 0;
    bool has_data_adler = false, has_data_crc = false;
    /// lzop stores a block verbatim when compressing it did not help.
    bool stored() const { return compressed == uncompressed; }
};

/// What `read_block` found.
enum class BlockResult : std::uint8_t {
    Ok,    ///< A block was decoded; `next` is where the following one starts.
    End,   ///< The zero length that ends a member; `next` is just past it.
    Bad,   ///< Malformed or truncated; nothing usable from here on.
};

/// "lzo1x-1", "lzo1x-1-15", "lzo1x-999", "zlib", or "unknown".
const char* method_name(std::uint8_t method);

/// Read the member header whose magic is at `at`. False when the magic is not
/// there, the header does not fit, or a field is outside what lzop writes;
/// `Header::checksum_ok` reports the checksum separately, so a damaged but
/// plausible header still comes back.
bool read_header(const Span& span, std::uint64_t at, Header& out);

/// Read the block header at `at`. `next` is where to continue, past the
/// block's data for `Ok` and past the terminator for `End`.
BlockResult read_block(const Span& span, const Header& h, std::uint64_t at, Block& out,
                       std::uint64_t& next);

/// The Adler-32 lzop puts on a block, over `data`.
std::uint32_t adler32_of(std::span<const std::uint8_t> data);
/// The CRC-32 lzop puts on a block, over `data`.
std::uint32_t crc32_of(std::span<const std::uint8_t> data);

}  // namespace omnitrace::lzop
