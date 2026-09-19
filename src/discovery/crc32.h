// crc32.h — table-driven reflected CRC-32 with the init/xor-out parameters as
// arguments, because the formats we validate disagree on them:
//
//   zlib / gzip / GPT / uImage : init 0xFFFFFFFF, xor-out 0xFFFFFFFF  (crc32_zlib)
//   JFFS2 node headers         : init 0x00000000, xor-out 0x00000000  (crc32_jffs2)
//   UBI EC/VID headers         : init 0xFFFFFFFF, xor-out 0x00000000  (crc32_ubi)
//   ext4 metadata_csum         : CRC-32C poly, init 0xFFFFFFFF, no xor-out (crc32c_ext4)
//
// The table is built at compile time; the polynomial is a template parameter
// so CRC-32C shares the implementation.
#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "omnitrace/core/Span.h"

namespace omnitrace::discovery {

constexpr std::uint32_t kCrc32Poly = 0xEDB88320u;   // IEEE 802.3, reflected
constexpr std::uint32_t kCrc32cPoly = 0x82F63B78u;  // Castagnoli, reflected

template <std::uint32_t Poly>
struct Crc32Table {
    std::array<std::uint32_t, 256> t{};
    constexpr Crc32Table() {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1u) ? (c >> 1) ^ Poly : (c >> 1);
            t[i] = c;
        }
    }
};

// Feed bytes into a running register (no final xor applied).
template <std::uint32_t Poly = kCrc32Poly>
constexpr std::uint32_t crc32_update(std::uint32_t crc, std::span<const std::uint8_t> data) {
    constexpr Crc32Table<Poly> tbl{};
    for (const std::uint8_t b : data) crc = tbl.t[(crc ^ b) & 0xFFu] ^ (crc >> 8);
    return crc;
}

template <std::uint32_t Poly = kCrc32Poly>
constexpr std::uint32_t crc32(std::span<const std::uint8_t> data, std::uint32_t init,
                              std::uint32_t xorout) {
    return crc32_update<Poly>(init, data) ^ xorout;
}

inline std::uint32_t crc32_zlib(std::span<const std::uint8_t> d) {
    return crc32(d, 0xFFFFFFFFu, 0xFFFFFFFFu);
}
inline std::uint32_t crc32_jffs2(std::span<const std::uint8_t> d) {
    return crc32(d, 0u, 0u);
}
inline std::uint32_t crc32_ubi(std::span<const std::uint8_t> d) {
    return crc32(d, 0xFFFFFFFFu, 0u);
}
inline std::uint32_t crc32c_ext4(std::span<const std::uint8_t> d) {
    return crc32<kCrc32cPoly>(d, 0xFFFFFFFFu, 0u);
}

// CRC of [off, off+len) of a Span, read in bounded chunks so a multi-gigabyte
// payload never has to be copied whole. nullopt if the range is not fully
// inside the Span.
template <std::uint32_t Poly = kCrc32Poly>
std::optional<std::uint32_t> crc32_span(const Span& span, std::uint64_t off, std::uint64_t len,
                                        std::uint32_t init, std::uint32_t xorout) {
    if (off > span.size() || len > span.size() - off) return std::nullopt;
    std::uint32_t crc = init;
    std::uint64_t done = 0;
    std::array<std::uint8_t, 64 * 1024> buf{};
    while (done < len) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
        if (auto v = span.view(off + done, want)) {
            crc = crc32_update<Poly>(crc, *v);
        } else {
            if (span.read(off + done, std::span<std::uint8_t>(buf.data(), want)) != want)
                return std::nullopt;
            crc = crc32_update<Poly>(crc, std::span<const std::uint8_t>(buf.data(), want));
        }
        done += want;
    }
    return crc ^ xorout;
}

}  // namespace omnitrace::discovery
