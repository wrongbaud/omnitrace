// Lzop.cpp — the lzop file format. See the header.
//
// Reference: lzop 1.04 (`src/lzop.c` header and block handling, `src/conf.h`
// for the flags and methods), read for understanding; nothing copied.
// Checked byte for byte against lzop 1.04 output before this was written.
#include "omnitrace/core/Lzop.h"

#include <algorithm>
#include <array>
#include <vector>

#include <zlib.h>

#include "omnitrace/core/Endian.h"

namespace omnitrace::lzop {

namespace {

// The header is variable-length, so it is read into a buffer big enough for
// the largest one lzop writes: the fixed fields plus a 255-byte name.
constexpr std::size_t kMaxHeaderSize = 64 + kMaxNameLen;
// Fields that only exist from this version on (`lzop.c`).
constexpr std::uint16_t kVersionWithNeeded = 0x0940;
// A version below this is not lzop; above 0x20ff is not one that exists.
constexpr std::uint16_t kMinVersion = 0x0100, kMaxVersion = 0x20FF;

}  // namespace

const char* method_name(std::uint8_t method) {
    switch (method) {
        case kMethodLzo1x1:
            return "lzo1x-1";
        case kMethodLzo1x115:
            return "lzo1x-1-15";
        case kMethodLzo1x999:
            return "lzo1x-999";
        case kMethodZlib:
            return "zlib";
        default:
            return "unknown";
    }
}

std::uint32_t adler32_of(std::span<const std::uint8_t> data) {
    return static_cast<std::uint32_t>(
        ::adler32(1UL, data.data(), static_cast<uInt>(data.size())));
}

std::uint32_t crc32_of(std::span<const std::uint8_t> data) {
    return static_cast<std::uint32_t>(::crc32(0UL, data.data(), static_cast<uInt>(data.size())));
}

bool read_header(const Span& span, std::uint64_t at, Header& out) {
    out = Header{};
    if (!span.matches_at(at, std::span<const std::uint8_t>(kMagic.data(), kMagic.size())))
        return false;

    // Read what is there; a short read is fine as long as every field the
    // header actually uses landed, which the bounds checks below decide.
    std::vector<std::uint8_t> buf(kMaxHeaderSize);
    const std::size_t got = span.read(at + kMagic.size(),
                                      std::span<std::uint8_t>(buf.data(), buf.size()));
    buf.resize(got);
    std::size_t p = 0;
    auto need = [&](std::size_t n) { return p + n <= buf.size(); };
    auto u8 = [&]() { return buf[p++]; };
    auto u16 = [&]() {
        const auto v = load_int<std::uint16_t>(buf.data() + p, Endian::Big);
        p += 2;
        return v;
    };
    auto u32 = [&]() {
        const auto v = load_int<std::uint32_t>(buf.data() + p, Endian::Big);
        p += 4;
        return v;
    };

    if (!need(4)) return false;
    out.version = u16();
    out.lib_version = u16();
    if (out.version < kMinVersion || out.version > kMaxVersion) return false;
    if (out.version >= kVersionWithNeeded) {
        if (!need(2)) return false;
        out.version_needed = u16();
        if (out.version_needed > out.version) return false;
    }
    if (!need(1)) return false;
    out.method = u8();
    if (out.version >= kVersionWithNeeded) {
        if (!need(1)) return false;
        out.level = u8();
    }
    if (!need(4)) return false;
    out.flags = u32();
    if ((out.flags & kHFilter) != 0) {
        if (!need(4)) return false;
        out.filter = u32();
    }
    if (!need(8)) return false;
    out.mode = u32();
    const std::uint32_t mtime_low = u32();
    std::uint32_t mtime_high = 0;
    if (out.version >= kVersionWithNeeded) {
        if (!need(4)) return false;
        mtime_high = u32();
    }
    out.mtime = (static_cast<std::uint64_t>(mtime_high) << 32) | mtime_low;
    if (!need(1)) return false;
    const std::uint8_t name_len = u8();
    if (!need(name_len)) return false;
    out.name.assign(reinterpret_cast<const char*>(buf.data()) + p, name_len);
    p += name_len;

    // The checksum covers everything from the version through the name.
    if (!need(4)) return false;
    const std::size_t body = p;
    const std::uint32_t stored = u32();
    const std::span<const std::uint8_t> covered(buf.data(), body);
    out.checksum_ok =
        ((out.flags & kHCrc32) != 0 ? crc32_of(covered) : adler32_of(covered)) == stored;

    if ((out.flags & kHExtraField) != 0) {
        // Length, the field itself, and a checksum over it.
        if (!need(4)) return false;
        const std::uint32_t extra = u32();
        if (extra > kMaxBlockSize) return false;
        p += static_cast<std::size_t>(extra) + 4;
        if (p > buf.size() && at + kMagic.size() + p > span.size()) return false;
    }
    out.first_block = at + kMagic.size() + p;
    return true;
}

BlockResult read_block(const Span& span, const Header& h, std::uint64_t at, Block& out,
                       std::uint64_t& next) {
    out = Block{};
    const auto dst = span.at<std::uint32_t>(at, Endian::Big);
    if (!dst) return BlockResult::Bad;
    if (*dst == 0) {  // the terminator
        next = at + 4;
        return BlockResult::End;
    }
    if (*dst > kMaxBlockSize) return BlockResult::Bad;
    const auto src = span.at<std::uint32_t>(at + 4, Endian::Big);
    // A block never grows: lzop stores it verbatim rather than write more
    // bytes than it was given.
    if (!src || *src == 0 || *src > *dst) return BlockResult::Bad;

    std::uint64_t p = at + 8;
    if ((h.flags & kAdler32D) != 0) {
        const auto v = span.at<std::uint32_t>(p, Endian::Big);
        if (!v) return BlockResult::Bad;
        out.data_adler = *v;
        out.has_data_adler = true;
        p += 4;
    }
    if ((h.flags & kCrc32D) != 0) {
        const auto v = span.at<std::uint32_t>(p, Endian::Big);
        if (!v) return BlockResult::Bad;
        out.data_crc = *v;
        out.has_data_crc = true;
        p += 4;
    }
    // The checksums of the compressed bytes are only written when there are
    // fewer of them than of the originals; otherwise they would be the same
    // number twice.
    if ((h.flags & kAdler32C) != 0 && *src < *dst) p += 4;
    if ((h.flags & kCrc32C) != 0 && *src < *dst) p += 4;

    out.uncompressed = *dst;
    out.compressed = *src;
    out.at = p;
    next = p + *src;
    if (next > span.size()) return BlockResult::Bad;
    return BlockResult::Ok;
}

}  // namespace omnitrace::lzop
