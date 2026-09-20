// Compression.cpp — bounded decompressors over zlib, liblzma, lz4, zstd and
// the in-tree LZO1X / rtime decoders. Every codec writes through one capped
// appender so no stream can grow the output past max_out, and every error is
// a stable kebab-case code in Status::error.
#include "omnitrace/core/Compression.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <limits>

#include <lz4.h>
#include <lz4frame.h>
#include <lzma.h>
#include <bzlib.h>
#include <zlib.h>
#include <zstd.h>
#include <zstd_errors.h>

#include "lzo1x.h"
#include "rtime.h"

namespace omnitrace::compress {

const char* codec_name(Codec c) {
    switch (c) {
        case Codec::None:
            return "none";
        case Codec::Zlib:
            return "zlib";
        case Codec::Deflate:
            return "deflate";
        case Codec::Gzip:
            return "gzip";
        case Codec::Xz:
            return "xz";
        case Codec::Lzma:
            return "lzma";
        case Codec::Bzip2:
            return "bzip2";
        case Codec::Lz4:
            return "lz4";
        case Codec::Lz4Legacy:
            return "lz4-legacy";
        case Codec::Zstd:
            return "zstd";
        case Codec::Lzo1x:
            return "lzo1x";
        case Codec::Rtime:
            return "rtime";
    }
    return "unknown";
}

namespace {

// Error codes. Tests and diagnostics key on these strings.
constexpr const char* kCap = "decompress-cap";
constexpr const char* kCorrupt = "decompress-corrupt";
// The compressed data decoded to its end and then disagreed with the check
// the stream carries over it. The payload is left in `out`: see the header.
constexpr const char* kChecksum = "decompress-checksum-mismatch";
constexpr const char* kTruncated = "decompress-truncated";
constexpr const char* kEmpty = "decompress-empty-input";
constexpr const char* kInit = "decompress-init-failed";
constexpr const char* kMemlimit = "decompress-memlimit";
constexpr const char* kUnsupported = "decompress-unsupported";
constexpr const char* kSizeMismatch = "decompress-size-mismatch";
constexpr const char* kTrailing = "decompress-trailing-input";

// Streaming decoders write into this scratch window and the result is
// appended to the output. 64 KiB is a working-buffer size, not a limit.
constexpr std::size_t kWindow = 64u * 1024u;

// liblzma allocates the LZMA dictionary declared in the stream header before
// producing a byte, so a hostile header can demand 1.5 GiB for a 4 KiB block.
// The decoder memlimit is therefore tied to the caller's output cap plus the
// largest dictionary a stock encoder emits (xz -9 uses 64 MiB). Any stream
// whose dictionary exceeds its own capped output by more than that is refused
// with "decompress-memlimit".
constexpr std::uint64_t kLzmaDictAllowance = 64ull << 20;

// Legacy lz4 frames (magic 02 21 4C 18) are a sequence of blocks each
// decoding to at most this many bytes; the format fixes it at 8 MiB.
constexpr std::size_t kLz4LegacyBlockSize = 8u << 20;

constexpr std::uint32_t kLz4FrameMagic = 0x184D2204u;
constexpr std::uint32_t kLz4LegacyMagic = 0x184C2102u;
constexpr std::uint32_t kLz4SkippableMask = 0xFFFFFFF0u;
constexpr std::uint32_t kLz4SkippableMagic = 0x184D2A50u;
constexpr std::uint32_t kZstdMagic = 0xFD2FB528u;
constexpr std::uint32_t kZstdSkippableMask = 0xFFFFFFF0u;
constexpr std::uint32_t kZstdSkippableMagic = 0x184D2A50u;

std::uint32_t le32_at(std::span<const std::uint8_t> in, std::size_t off) {
    return static_cast<std::uint32_t>(in[off]) | (static_cast<std::uint32_t>(in[off + 1]) << 8) |
           (static_cast<std::uint32_t>(in[off + 2]) << 16) |
           (static_cast<std::uint32_t>(in[off + 3]) << 24);
}

bool starts_with_le32(std::span<const std::uint8_t> in, std::size_t off, std::uint32_t magic,
                      std::uint32_t mask = 0xFFFFFFFFu) {
    return in.size() - off >= 4 && (le32_at(in, off) & mask) == magic;
}

bool is_gzip_header(std::span<const std::uint8_t> in, std::size_t off) {
    return in.size() - off >= 2 && in[off] == 0x1f && in[off + 1] == 0x8b;
}

bool is_bzip2_header(std::span<const std::uint8_t> in, std::size_t off) {
    // "BZh" then the block-size digit '1'..'9'.
    return in.size() - off >= 4 && in[off] == 'B' && in[off + 1] == 'Z' && in[off + 2] == 'h' &&
           in[off + 3] >= '1' && in[off + 3] <= '9';
}

bool is_xz_header(std::span<const std::uint8_t> in, std::size_t off) {
    static constexpr std::uint8_t kMagic[6] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
    return in.size() - off >= 6 && std::memcmp(in.data() + off, kMagic, 6) == 0;
}

// Capped output appender shared by every streaming codec.
class Appender {
   public:
    Appender(std::vector<std::uint8_t>& out, std::uint64_t max_out)
        : out_(&out), max_(max_out), buf_(kWindow) {}
    // Counting mode: the decoder runs to the end of the stream but the output
    // is discarded, so measuring a 2 GiB stream costs one 64 KiB window.
    explicit Appender(std::uint64_t max_out) : max_(max_out), buf_(kWindow) {}

    std::uint8_t* scratch() { return buf_.data(); }
    // Bytes a decoder may write into scratch() this round: at most kWindow,
    // and one more than the remaining allowance so an over-cap stream is
    // detected on the byte that crosses the line, never silently clipped.
    std::size_t window() const {
        const std::uint64_t remaining = max_ - size();
        return remaining >= kWindow ? kWindow : static_cast<std::size_t>(remaining) + 1;
    }
    // Append n bytes from scratch(); false if that would exceed the cap.
    bool commit(std::size_t n) {
        if (n > max_ - size()) return false;
        if (out_ != nullptr)
            out_->insert(out_->end(), buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(n));
        else
            counted_ += n;
        return true;
    }
    std::uint64_t remaining() const { return max_ - size(); }
    /// Bytes produced so far, whether stored or only counted.
    std::uint64_t size() const { return out_ != nullptr ? out_->size() : counted_; }

   private:
    std::vector<std::uint8_t>* out_ = nullptr;
    std::uint64_t counted_ = 0;
    std::uint64_t max_;
    std::vector<std::uint8_t> buf_;
};

// ---------------------------------------------------------------- zlib

Status inflate_zlib(std::span<const std::uint8_t> in, std::vector<std::uint8_t>* out,
                    std::uint64_t max_out, int window_bits, std::uint64_t* consumed = nullptr,
                    std::uint64_t* produced = nullptr) {
    if (in.empty()) return Status::fail(kEmpty);
    z_stream zs{};
    if (inflateInit2(&zs, window_bits) != Z_OK) return Status::fail(kInit);
    Appender ap = out != nullptr ? Appender(*out, max_out) : Appender(max_out);
    std::size_t ip = 0;
    std::size_t member_start = 0;  // where the member being decoded began
    Status result = Status::success();
    const bool allow_members = window_bits > 15;  // gzip or auto-detect modes
    for (;;) {
        const std::size_t avail_in =
            std::min<std::size_t>(in.size() - ip, std::numeric_limits<uInt>::max());
        zs.next_in = const_cast<Bytef*>(in.data() + ip);
        zs.avail_in = static_cast<uInt>(avail_in);
        const std::size_t win = ap.window();
        zs.next_out = ap.scratch();
        zs.avail_out = static_cast<uInt>(win);
        const int rc = inflate(&zs, Z_NO_FLUSH);
        ip += avail_in - zs.avail_in;
        const std::size_t produced = win - zs.avail_out;
        if (!ap.commit(produced)) {
            result = Status::fail(kCap);
            break;
        }
        if (rc == Z_STREAM_END) {
            // Concatenated gzip members are one logical stream (RFC 1952 §2.2).
            if (allow_members && is_gzip_header(in, ip) && inflateReset(&zs) == Z_OK) {
                member_start = ip;
                continue;
            }
            break;
        }
        if (rc == Z_OK) continue;
        if (rc == Z_BUF_ERROR) {
            result = Status::fail(ip >= in.size() ? kTruncated : kCorrupt);
            break;
        }
        if (rc == Z_NEED_DICT) {
            result = Status::fail(kUnsupported);
            break;
        }
        if (rc == Z_MEM_ERROR) {
            result = Status::fail(kInit);
            break;
        }
        // zlib reports a failed gzip CRC-32/ISIZE or zlib Adler-32 as a plain
        // Z_DATA_ERROR and names it only in `msg`. The distinction is worth
        // recovering: the deflate data itself decoded, so everything already
        // in `out` is the whole payload, just not the payload that was
        // compressed. A `msg` this does not recognise falls through to
        // kCorrupt, which is the safe answer.
        const char* msg = zs.msg != nullptr ? zs.msg : "";
        const bool bad_crc = std::strcmp(msg, "incorrect data check") == 0;
        const bool bad_len = std::strcmp(msg, "incorrect length check") == 0;
        if (bad_crc && is_gzip_header(in, member_start) && in.size() - ip >= 4) {
            // zlib stops on the CRC-32 and never reads the ISIZE behind it, so
            // `ip` would be four bytes short of the member's real end and the
            // caller would leave a phantom four-byte gap in the image. The
            // gzip trailer is fixed at CRC-32 then ISIZE (RFC 1952 2.3.1), so
            // those four bytes belong to the member whatever they hold.
            ip += 4;
        }
        result = Status::fail(bad_crc || bad_len ? kChecksum : kCorrupt);
        break;
    }
    inflateEnd(&zs);
    // `ip` is one past the last byte the stream (or the last concatenated
    // member) used, which is the stream's extent in the enclosing image.
    if (consumed != nullptr) *consumed = ip;
    if (produced != nullptr) *produced = ap.size();
    return result;
}

// ---------------------------------------------------------------- libbz2

// bzip2 has no streaming "skip to next member" call: BZ2_bzDecompress reports
// BZ_STREAM_END and stops. Concatenated streams (bzip2 -c a b > c, and every
// pbzip2 output) are one logical file, so the decoder is torn down and rebuilt
// at each boundary, exactly as bunzip2 does.
Status inflate_bzip2(std::span<const std::uint8_t> in, std::vector<std::uint8_t>* out,
                     std::uint64_t max_out, std::uint64_t* consumed = nullptr,
                     std::uint64_t* produced = nullptr) {
    if (in.empty()) return Status::fail(kEmpty);
    Appender ap = out != nullptr ? Appender(*out, max_out) : Appender(max_out);
    std::size_t ip = 0;
    Status result = Status::success();
    for (;;) {
        bz_stream bs{};
        if (BZ2_bzDecompressInit(&bs, 0, 0) != BZ_OK) {
            result = Status::fail(kInit);
            break;
        }
        bool member_done = false;
        for (;;) {
            const std::size_t avail_in =
                std::min<std::size_t>(in.size() - ip, std::numeric_limits<unsigned>::max());
            bs.next_in = const_cast<char*>(reinterpret_cast<const char*>(in.data() + ip));
            bs.avail_in = static_cast<unsigned>(avail_in);
            const std::size_t win = ap.window();
            bs.next_out = reinterpret_cast<char*>(ap.scratch());
            bs.avail_out = static_cast<unsigned>(win);
            const int rc = BZ2_bzDecompress(&bs);
            ip += avail_in - bs.avail_in;
            const std::size_t got = win - bs.avail_out;
            if (!ap.commit(got)) {
                result = Status::fail(kCap);
                break;
            }
            if (rc == BZ_STREAM_END) {
                member_done = true;
                break;
            }
            if (rc != BZ_OK) {
                result = Status::fail(rc == BZ_MEM_ERROR ? kInit : kCorrupt);
                break;
            }
            if (bs.avail_in == 0 && ip >= in.size() && got == 0) {
                result = Status::fail(kTruncated);
                break;
            }
        }
        BZ2_bzDecompressEnd(&bs);
        if (!result || !member_done) break;
        // Another member may follow; anything else is trailing data.
        if (is_bzip2_header(in, ip)) continue;
        break;
    }
    if (consumed != nullptr) *consumed = ip;
    if (produced != nullptr) *produced = ap.size();
    return result;
}

// ---------------------------------------------------------------- liblzma

std::uint64_t lzma_memlimit_for(std::uint64_t max_out) {
    return max_out > std::numeric_limits<std::uint64_t>::max() - kLzmaDictAllowance
               ? std::numeric_limits<std::uint64_t>::max()
               : max_out + kLzmaDictAllowance;
}

// Skip .xz stream padding (groups of four NUL bytes) and report whether
// another .xz stream begins there.
bool next_xz_stream(std::span<const std::uint8_t> in, std::size_t& ip) {
    std::size_t p = ip;
    while (in.size() - p >= 4 && in[p] == 0 && in[p + 1] == 0 && in[p + 2] == 0 && in[p + 3] == 0)
        p += 4;
    if (!is_xz_header(in, p)) return false;
    ip = p;
    return true;
}

Status inflate_lzma(std::span<const std::uint8_t> in, std::vector<std::uint8_t>* out,
                    std::uint64_t max_out, bool xz, std::uint64_t* consumed = nullptr,
                    std::uint64_t* produced = nullptr) {
    if (in.empty()) return Status::fail(kEmpty);
    const std::uint64_t memlimit = lzma_memlimit_for(max_out);
    lzma_stream s = LZMA_STREAM_INIT;
    auto init = [&]() {
        return xz ? lzma_stream_decoder(&s, memlimit, 0) : lzma_alone_decoder(&s, memlimit);
    };
    if (init() != LZMA_OK) return Status::fail(kInit);
    Appender ap = out != nullptr ? Appender(*out, max_out) : Appender(max_out);
    std::size_t ip = 0;
    Status result = Status::success();
    unsigned stalls = 0;
    for (;;) {
        s.next_in = in.data() + ip;
        s.avail_in = in.size() - ip;
        const std::size_t win = ap.window();
        s.next_out = ap.scratch();
        s.avail_out = win;
        const lzma_ret rc = lzma_code(&s, LZMA_FINISH);
        const std::size_t consumed = (in.size() - ip) - s.avail_in;
        ip += consumed;
        const std::size_t produced = win - s.avail_out;
        if (!ap.commit(produced)) {
            result = Status::fail(kCap);
            break;
        }
        if (rc == LZMA_STREAM_END) {
            if (xz && next_xz_stream(in, ip)) {
                lzma_end(&s);
                s = LZMA_STREAM_INIT;
                if (init() != LZMA_OK) {
                    result = Status::fail(kInit);
                    break;
                }
                continue;
            }
            break;
        }
        if (rc == LZMA_OK) {
            // liblzma promises LZMA_BUF_ERROR after two no-progress calls;
            // guard the loop anyway.
            stalls = (consumed == 0 && produced == 0) ? stalls + 1 : 0;
            if (stalls > 2) {
                result = Status::fail(kTruncated);
                break;
            }
            continue;
        }
        if (rc == LZMA_BUF_ERROR) {
            result = Status::fail(ip >= in.size() ? kTruncated : kCorrupt);
            break;
        }
        if (rc == LZMA_MEMLIMIT_ERROR) {
            result = Status::fail(kMemlimit);
            break;
        }
        if (rc == LZMA_MEM_ERROR) {
            result = Status::fail(kInit);
            break;
        }
        if (rc == LZMA_OPTIONS_ERROR) {
            result = Status::fail(kUnsupported);
            break;
        }
        result = Status::fail(kCorrupt);  // LZMA_FORMAT_ERROR, LZMA_DATA_ERROR, ...
        break;
    }
    lzma_end(&s);
    if (consumed != nullptr) *consumed = ip;
    if (produced != nullptr) *produced = ap.size();
    return result;
}

// ---------------------------------------------------------------- lz4

Status inflate_lz4_frame(std::span<const std::uint8_t> in, std::vector<std::uint8_t>* out,
                         std::uint64_t max_out, std::uint64_t* consumed = nullptr,
                         std::uint64_t* produced = nullptr) {
    LZ4F_dctx* dctx = nullptr;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION)) || dctx == nullptr)
        return Status::fail(kInit);
    Appender ap = out != nullptr ? Appender(*out, max_out) : Appender(max_out);
    std::size_t ip = 0;
    Status result = Status::success();
    for (;;) {
        // One frame.
        unsigned stalls = 0;
        for (;;) {
            std::size_t src_size = in.size() - ip;
            std::size_t dst_size = ap.window();
            const std::size_t hint =
                LZ4F_decompress(dctx, ap.scratch(), &dst_size, in.data() + ip, &src_size, nullptr);
            if (LZ4F_isError(hint)) {
                // LZ4F_getErrorCode is static-linking-only; the error *name*
                // is public and is the enumerator's own spelling.
                //
                // On a content-checksum failure the last block's bytes are in
                // the scratch buffer but `dst_size` was never set to their
                // count -- LZ4F returns the error before the assignment at the
                // end of LZ4F_decompress -- so they cannot be committed and
                // the payload is short by up to one window. It is already
                // reported as damaged; zstd does the same and the zlib-backed
                // codecs, which commit before they check, do not.
                const char* name = LZ4F_getErrorName(hint);
                const bool check_failed = std::strcmp(name, "ERROR_contentChecksum_invalid") == 0 ||
                                          std::strcmp(name, "ERROR_blockChecksum_invalid") == 0;
                result = Status::fail(check_failed ? kChecksum : kCorrupt);
                break;
            }
            ip += src_size;
            if (!ap.commit(dst_size)) {
                result = Status::fail(kCap);
                break;
            }
            if (hint == 0) break;  // frame fully decoded
            if (src_size == 0 && dst_size == 0) {
                if (ip >= in.size() || ++stalls > 2) {
                    result = Status::fail(kTruncated);
                    break;
                }
            } else {
                stalls = 0;
            }
        }
        if (!result) break;
        // Another frame (or skippable frame) may follow; anything else is
        // trailing data we leave alone.
        if (starts_with_le32(in, ip, kLz4FrameMagic) ||
            starts_with_le32(in, ip, kLz4SkippableMagic, kLz4SkippableMask))
            continue;
        break;
    }
    LZ4F_freeDecompressionContext(dctx);
    // `ip` is one past the last frame the decoder accepted, which is the
    // stream's extent: trailing data after the last frame is not claimed.
    if (consumed != nullptr) *consumed = ip;
    if (produced != nullptr) *produced = ap.size();
    return result;
}

// A single raw lz4 block (SquashFS data blocks, erofs, UBIFS-lz4 out of tree).
// The block format carries no size, so the output buffer is sized to the cap,
// bounded by the format's own expansion limit (a block cannot grow past
// roughly 255x its input). The strict decoder is used first because the
// partial decoder deliberately accepts input that ends mid-sequence, which
// would turn a truncated block into a silent prefix. Only when the strict
// decode fails is the partial decoder run, to tell "over the cap" apart from
// "corrupt".
Status inflate_lz4_block(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                         std::uint64_t max_out) {
    if (in.empty()) return Status::fail(kEmpty);
    constexpr std::uint64_t kIntMax = static_cast<std::uint64_t>(std::numeric_limits<int>::max());
    if (in.size() > kIntMax) return Status::fail(kUnsupported);
    const std::uint64_t bound = static_cast<std::uint64_t>(in.size()) * 255u + 64u;
    const std::uint64_t capacity = std::min<std::uint64_t>(max_out, bound);
    if (capacity > kIntMax) return Status::fail(kUnsupported);
    const char* src = reinterpret_cast<const char*>(in.data());
    out.assign(static_cast<std::size_t>(capacity), 0);
    const int n = LZ4_decompress_safe(src, reinterpret_cast<char*>(out.data()),
                                      static_cast<int>(in.size()), static_cast<int>(capacity));
    if (n >= 0) {
        out.resize(static_cast<std::size_t>(n));
        return Status::success();
    }
    // Strict decode failed. If the cap was the binding limit, the block may
    // simply be larger than allowed: decode one byte past the cap to find out.
    if (max_out < bound) {
        const std::uint64_t target = max_out + 1;  // <= bound <= kIntMax
        out.assign(static_cast<std::size_t>(target), 0);
        const int m = LZ4_decompress_safe_partial(
            src, reinterpret_cast<char*>(out.data()), static_cast<int>(in.size()),
            static_cast<int>(target), static_cast<int>(target));
        if (m >= 0 && static_cast<std::uint64_t>(m) > max_out) {
            out.resize(static_cast<std::size_t>(max_out));
            return Status::fail(kCap);
        }
    }
    out.clear();
    return Status::fail(kCorrupt);
}

// Legacy frame: magic, then [u32 LE compressed size][block]... until input
// ends or a non-block magic appears (that is how the lz4 CLI ends them). A
// dangling partial size field means the input was cut short.
Status inflate_lz4_legacy(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                          std::uint64_t max_out) {
    if (in.size() < 4) return Status::fail(kTruncated);
    std::size_t ip = 4;
    std::vector<std::uint8_t> block;
    while (in.size() - ip >= 4) {
        // Block sizes are u32 LE; a magic value here starts the next frame.
        const std::uint32_t csize = le32_at(in, ip);
        if (csize == kLz4LegacyMagic || csize == kLz4FrameMagic ||
            (csize & kLz4SkippableMask) == kLz4SkippableMagic)
            return Status::success();
        ip += 4;
        if (csize == 0 || csize > static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
            return Status::fail(kCorrupt);
        if (csize > in.size() - ip) return Status::fail(kTruncated);
        block.resize(kLz4LegacyBlockSize);
        const int n = LZ4_decompress_safe(
            reinterpret_cast<const char*>(in.data() + ip), reinterpret_cast<char*>(block.data()),
            static_cast<int>(csize), static_cast<int>(kLz4LegacyBlockSize));
        if (n < 0) return Status::fail(kCorrupt);
        if (static_cast<std::uint64_t>(n) > max_out - out.size()) return Status::fail(kCap);
        out.insert(out.end(), block.begin(), block.begin() + n);
        ip += csize;
    }
    if (ip != in.size()) return Status::fail(kTruncated);  // 1..3 bytes of a size field
    // A magic with no blocks behind it is how the lz4 CLI writes an empty file.
    return Status::success();
}

// ---------------------------------------------------------------- zstd

Status inflate_zstd(std::span<const std::uint8_t> in, std::vector<std::uint8_t>* out,
                    std::uint64_t max_out, std::uint64_t* consumed = nullptr,
                    std::uint64_t* produced = nullptr) {
    if (in.empty()) return Status::fail(kEmpty);
    ZSTD_DStream* ds = ZSTD_createDStream();
    if (ds == nullptr) return Status::fail(kInit);
    if (ZSTD_isError(ZSTD_initDStream(ds))) {
        ZSTD_freeDStream(ds);
        return Status::fail(kInit);
    }
    Appender ap = out != nullptr ? Appender(*out, max_out) : Appender(max_out);
    ZSTD_inBuffer zin{in.data(), in.size(), 0};
    Status result = Status::success();
    for (;;) {
        ZSTD_outBuffer zout{ap.scratch(), ap.window(), 0};
        const std::size_t rc = ZSTD_decompressStream(ds, &zout, &zin);
        if (ZSTD_isError(rc)) {
            // As in the lz4 path: a failed content checksum leaves the last
            // flush's bytes in the scratch buffer with `zout.pos` still 0, so
            // the payload is short by up to one window.
            const ZSTD_ErrorCode ec = ZSTD_getErrorCode(rc);
            const char* code =
                ec == ZSTD_error_frameParameter_windowTooLarge || ec == ZSTD_error_memory_allocation
                    ? kMemlimit
                : ec == ZSTD_error_checksum_wrong ? kChecksum
                                                  : kCorrupt;
            result = Status::fail(code);
            break;
        }
        if (!ap.commit(zout.pos)) {
            result = Status::fail(kCap);
            break;
        }
        if (rc == 0) {
            // Frame complete. Continue only into another zstd (or skippable) frame.
            if (starts_with_le32(in, zin.pos, kZstdMagic) ||
                starts_with_le32(in, zin.pos, kZstdSkippableMagic, kZstdSkippableMask))
                continue;
            break;
        }
        if (zin.pos >= zin.size && zout.pos < zout.size) {
            result = Status::fail(kTruncated);
            break;
        }
    }
    ZSTD_freeDStream(ds);
    if (consumed != nullptr) *consumed = zin.pos;
    if (produced != nullptr) *produced = ap.size();
    return result;
}

// ---------------------------------------------------------------- in-tree codecs

Status inflate_lzo1x(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                     std::uint64_t max_out, bool exact) {
    std::size_t consumed = 0;
    const lzo::Lzo1xStatus rc = lzo::lzo1x_decompress_safe(in, out, max_out, &consumed);
    if (rc != lzo::Lzo1xStatus::Ok) return Status::fail(lzo::lzo1x_status_code(rc));
    if (exact && consumed != in.size()) return Status::fail(kTrailing);
    return Status::success();
}

Status inflate_rtime(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                     std::uint64_t max_out) {
    const rtime::RtimeStatus rc = rtime::rtime_decompress(in, out, max_out);
    if (rc != rtime::RtimeStatus::Ok) return Status::fail(rtime::rtime_status_code(rc));
    return Status::success();
}

Status copy_through(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                    std::uint64_t max_out) {
    if (in.size() > max_out) return Status::fail(kCap);
    out.assign(in.begin(), in.end());
    return Status::success();
}

// `consumed`, when given, is set to the input length the stream actually used.
// Only the wrapped stream formats can report it; for the block codecs the
// whole input is the unit, so it stays at in.size().
Status decompress_impl(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                       std::uint64_t max_out, bool exact,
                       std::uint64_t* consumed = nullptr) {
    out.clear();
    if (consumed != nullptr) *consumed = in.size();
    switch (c) {
        case Codec::None:
            return copy_through(in, out, max_out);
        case Codec::Zlib:
            return inflate_zlib(in, &out, max_out, 15 + 32, consumed);  // zlib or gzip
        case Codec::Deflate:
            return inflate_zlib(in, &out, max_out, -15, consumed);
        case Codec::Gzip:
            return inflate_zlib(in, &out, max_out, 15 + 16, consumed);
        case Codec::Bzip2:
            return inflate_bzip2(in, &out, max_out, consumed);
        case Codec::Xz:
            return inflate_lzma(in, &out, max_out, true, consumed);
        case Codec::Lzma:
            return inflate_lzma(in, &out, max_out, false, consumed);
        case Codec::Lz4:
            if (starts_with_le32(in, 0, kLz4FrameMagic) ||
                starts_with_le32(in, 0, kLz4SkippableMagic, kLz4SkippableMask))
                return inflate_lz4_frame(in, &out, max_out, consumed);
            if (starts_with_le32(in, 0, kLz4LegacyMagic))
                return inflate_lz4_legacy(in, out, max_out);
            return inflate_lz4_block(in, out, max_out);
        case Codec::Lz4Legacy:
            if (starts_with_le32(in, 0, kLz4LegacyMagic))
                return inflate_lz4_legacy(in, out, max_out);
            return inflate_lz4_block(in, out, max_out);
        case Codec::Zstd:
            return inflate_zstd(in, &out, max_out, consumed);
        case Codec::Lzo1x:
            return inflate_lzo1x(in, out, max_out, exact);
        case Codec::Rtime:
            return inflate_rtime(in, out, max_out);
    }
    return Status::fail(kUnsupported);
}

}  // namespace

Status decompress(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                  std::uint64_t max_out) {
    return decompress_impl(c, in, out, max_out, false);
}

Status stream_length(Codec c, std::span<const std::uint8_t> in, std::uint64_t max_out,
                     std::uint64_t& consumed, std::uint64_t& produced) {
    consumed = 0;
    produced = 0;
    switch (c) {
        case Codec::Zlib:
            return inflate_zlib(in, nullptr, max_out, 15 + 32, &consumed, &produced);
        case Codec::Deflate:
            return inflate_zlib(in, nullptr, max_out, -15, &consumed, &produced);
        case Codec::Gzip:
            return inflate_zlib(in, nullptr, max_out, 15 + 16, &consumed, &produced);
        case Codec::Xz:
            return inflate_lzma(in, nullptr, max_out, true, &consumed, &produced);
        case Codec::Lzma:
            return inflate_lzma(in, nullptr, max_out, false, &consumed, &produced);
        case Codec::Bzip2:
            return inflate_bzip2(in, nullptr, max_out, &consumed, &produced);
        case Codec::Lz4:
            // Only the frame format has an extent; a raw block is the whole
            // input by definition and has no header to measure.
            if (!starts_with_le32(in, 0, kLz4FrameMagic) &&
                !starts_with_le32(in, 0, kLz4SkippableMagic, kLz4SkippableMask))
                return Status::fail(kUnsupported);
            return inflate_lz4_frame(in, nullptr, max_out, &consumed, &produced);
        case Codec::Zstd:
            return inflate_zstd(in, nullptr, max_out, &consumed, &produced);
        default:
            return Status::fail(kUnsupported);
    }
}

std::string stream_check(Codec c, std::span<const std::uint8_t> in) {
    switch (c) {
        case Codec::Gzip:
            // The 8-byte trailer is a CRC-32 over the payload then its length;
            // both are mandatory (RFC 1952 section 2.3.1).
            return "crc32";
        case Codec::Zlib:
            // Auto-detecting: a gzip wrapper when its magic is there, else the
            // zlib one, whose 4-byte trailer is an Adler-32 (RFC 1950).
            return is_gzip_header(in, 0) ? "crc32" : "adler32";
        case Codec::Bzip2:
            // Every block carries a CRC-32 and the stream a combined one.
            return "crc32";
        case Codec::Xz: {
            // Stream header: six magic bytes, then two flag bytes whose low
            // nibble picks the check (xz file format 2.1.1.2).
            if (!is_xz_header(in, 0) || in.size() < 8) return "";
            switch (in[7] & 0x0Fu) {
                case 0x00:
                    return "none";  // xz --check=none
                case 0x01:
                    return "crc32";
                case 0x04:
                    return "crc64";  // the default
                case 0x0A:
                    return "sha256";
                default:
                    return "";  // a reserved id this build cannot name
            }
        }
        case Codec::Lzma:
        case Codec::Deflate:
            // Neither records anything over its payload.
            return "none";
        case Codec::Lz4:
            // Frame descriptor: FLG is the byte after the magic. Bit 2 is an
            // xxHash32 over the whole content, bit 4 one per block; either
            // means the decoder checks what it produced.
            if (!starts_with_le32(in, 0, kLz4FrameMagic) || in.size() < 5) return "";
            return (in[4] & 0x14u) != 0 ? "xxh32" : "none";
        case Codec::Lz4Legacy:
            return "none";
        case Codec::Zstd:
            // Frame header descriptor, bit 2: the low 32 bits of an XXH64
            // over the content.
            if (!starts_with_le32(in, 0, kZstdMagic) || in.size() < 5) return "";
            return (in[4] & 0x04u) != 0 ? "xxh64" : "none";
        case Codec::Lzo1x:
        case Codec::Rtime:
        case Codec::None:
            // Bare blocks: whatever checks them lives in the format that
            // stores them, not in the bytes handed here.
            break;
    }
    return "";
}

Status decompress_stream(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                         std::uint64_t max_out, std::uint64_t& consumed) {
    consumed = in.size();
    return decompress_impl(c, in, out, max_out, false, &consumed);
}

Status decompress_exact(Codec c, std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                        std::size_t expected) {
    const Status s = decompress_impl(c, in, out, expected, true);
    if (!s) return s;
    if (out.size() != expected) return Status::fail(kSizeMismatch);
    return Status::success();
}


Status decompress_raw(std::span<const RawFilter> chain, std::span<const std::uint8_t> in,
                      std::vector<std::uint8_t>& out, std::size_t expected) {
    out.clear();
    if (chain.empty()) return Status::fail("decompress-unsupported: empty filter chain");
    if (chain.size() >= LZMA_FILTERS_MAX + 1)
        return Status::fail("decompress-unsupported: more than " +
                            std::to_string(LZMA_FILTERS_MAX) + " filters in the chain");

    // liblzma owns the decoded options, so they are freed on every path out.
    std::array<lzma_filter, LZMA_FILTERS_MAX + 1> filters{};
    for (auto& f : filters) {
        f.id = LZMA_VLI_UNKNOWN;
        f.options = nullptr;
    }
    struct FilterGuard {
        std::array<lzma_filter, LZMA_FILTERS_MAX + 1>* f;
        ~FilterGuard() {
            for (auto& one : *f) {
                if (one.options != nullptr) std::free(one.options);
            }
        }
    } guard{&filters};

    for (std::size_t i = 0; i < chain.size(); ++i) {
        filters[i].id = chain[i].id;
        const lzma_ret rc = lzma_properties_decode(
            &filters[i], nullptr, chain[i].props.empty() ? nullptr : chain[i].props.data(),
            chain[i].props.size());
        if (rc == LZMA_OPTIONS_ERROR)
            return Status::fail("decompress-unsupported: filter id " +
                                std::to_string(chain[i].id) + " is not one this build has");
        if (rc != LZMA_OK)
            return Status::fail("decompress-props: filter id " + std::to_string(chain[i].id) +
                                " rejected its " + std::to_string(chain[i].props.size()) +
                                " properties byte(s)");
        // The extended LZMA1 needs to be told how long its output is; that is
        // the whole reason to use it over plain LZMA1.
        if (chain[i].id == kFilterLzma1Ext && filters[i].options != nullptr) {
            auto* o = static_cast<lzma_options_lzma*>(filters[i].options);
            o->ext_flags = LZMA_LZMA1EXT_ALLOW_EOPM;
            lzma_set_ext_size(*o, static_cast<std::uint64_t>(expected));
        }
    }

    lzma_stream s = LZMA_STREAM_INIT;
    if (const lzma_ret rc = lzma_raw_decoder(&s, filters.data()); rc != LZMA_OK) {
        return Status::fail(rc == LZMA_OPTIONS_ERROR
                                ? "decompress-unsupported: the filter chain is not one this build "
                                  "can decode"
                                : "decompress-init: raw decoder");
    }
    out.resize(expected);
    s.next_in = in.data();
    s.avail_in = in.size();
    s.next_out = out.data();
    s.avail_out = out.size();
    // One call is not always enough. A BCJ filter holds back the bytes it
    // cannot convert without lookahead, and raw LZMA1 has no end marker to
    // tell it the input is over -- it simply stops when the output is full --
    // so the tail is flushed only by calling again with nothing left to feed.
    lzma_ret rc = LZMA_OK;
    for (;;) {
        const std::size_t in_before = s.avail_in, out_before = s.avail_out;
        rc = lzma_code(&s, LZMA_FINISH);
        if (rc != LZMA_OK) break;
        if (s.avail_out == 0) break;
        if (s.avail_in == in_before && s.avail_out == out_before) break;  // no progress
    }
    const std::size_t produced = out.size() - s.avail_out;
    lzma_end(&s);
    if (rc != LZMA_OK && rc != LZMA_STREAM_END) {
        out.clear();
        return Status::fail("decompress-failed: raw chain returned " + std::to_string(rc));
    }
    if (produced != expected) {
        out.resize(produced);
        return Status::fail("decompress-size-mismatch: raw chain produced " +
                            std::to_string(produced) + " bytes, expected " +
                            std::to_string(expected));
    }
    return Status::success();
}

}  // namespace omnitrace::compress
