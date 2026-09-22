// compression_test.cpp — round trips through the real encoders, output caps,
// corrupt and truncated streams, and the in-tree LZO1X / rtime decoders.
#include "omnitrace/core/Compression.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <vector>

#include <lz4.h>
#include <lz4frame.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

namespace omnitrace::compress {
namespace {

using Bytes = std::vector<std::uint8_t>;

// LZO1X streams produced by liblzo2 2.10 (lzo1x_1_compress / lzo1x_999_compress)
// from lzo_sample() below; embedded so the test needs no LZO library.
constexpr unsigned char kLzo1x1Sample[] = {
    0x00, 0x18, 0x6c, 0x69, 0x6e, 0x65, 0x20, 0x30, 0x30, 0x30, 0x30, 0x3a, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78,
    0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x78, 0x03, 0x08, 0x6c,
    0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x20, 0x30, 0x0a, 0xe1, 0x07, 0x31, 0x20, 0x0d, 0xe1,
    0x00, 0x37, 0x27, 0xe1, 0x00, 0x32, 0x20, 0x0d, 0xe2, 0x00, 0x31, 0x34, 0x27, 0xe5, 0x00, 0x33,
    0x20, 0x0d, 0xe6, 0x00, 0x32, 0x31, 0x27, 0xe5, 0x00, 0x34, 0x20, 0x0e, 0xe5, 0x00, 0x38, 0x27,
    0xe5, 0x00, 0x35, 0x20, 0x0d, 0xe6, 0x00, 0x33, 0x35, 0x27, 0xe5, 0x00, 0x36, 0x20, 0x0d, 0xe6,
    0x00, 0x34, 0x32, 0x27, 0xe5, 0x00, 0x37, 0x20, 0x0e, 0xe5, 0x00, 0x39, 0x27, 0xe5, 0x00, 0x38,
    0x20, 0x0d, 0xe6, 0x00, 0x35, 0x36, 0x27, 0xe5, 0x00, 0x39, 0x20, 0x0d, 0xe6, 0x00, 0x36, 0x33,
    0xe5, 0x07, 0x31, 0x20, 0x0e, 0x05, 0x09, 0x37, 0x27, 0x09, 0x09, 0x31, 0x20, 0x0f, 0x08, 0x09,
    0x27, 0x0d, 0x09, 0x31, 0x20, 0x0e, 0x0d, 0x09, 0x38, 0x27, 0x0d, 0x09, 0x31, 0x20, 0x0e, 0x0d,
    0x09, 0x39, 0x27, 0x0d, 0x09, 0x31, 0x20, 0x0e, 0x0d, 0x09, 0x39, 0x27, 0x0d, 0x09, 0x31, 0x20,
    0x0e, 0x0e, 0x09, 0x31, 0x30, 0x27, 0x11, 0x09, 0x31, 0x20, 0x0e, 0x12, 0x09, 0x31, 0x31, 0x27,
    0x15, 0x09, 0x31, 0x20, 0x0e, 0x16, 0x09, 0x31, 0x31, 0x27, 0x19, 0x09, 0x31, 0x20, 0x0e, 0x1a,
    0x09, 0x31, 0x32, 0x27, 0x1d, 0x09, 0x31, 0x20, 0x0e, 0x1e, 0x09, 0x31, 0x33, 0x27, 0x21, 0x09,
    0x32, 0x20, 0x0e, 0x22, 0x09, 0x31, 0x34, 0x27, 0x25, 0x09, 0x32, 0x20, 0x0e, 0x26, 0x09, 0x31,
    0x34, 0x27, 0x29, 0x09, 0x32, 0x20, 0x0e, 0x2a, 0x09, 0x31, 0x35, 0x27, 0x2d, 0x09, 0x32, 0x20,
    0x0e, 0x2e, 0x09, 0x31, 0x36, 0x27, 0x31, 0x09, 0x32, 0x20, 0x0e, 0x32, 0x09, 0x31, 0x36, 0x27,
    0x35, 0x09, 0x32, 0x20, 0x0f, 0x35, 0x09, 0x37, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0f, 0x35, 0x09,
    0x38, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0f,
    0x35, 0x09, 0x39, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x30, 0x27, 0x35, 0x09,
    0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x31, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32,
    0x31, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x32, 0x27, 0x35, 0x09, 0x33, 0x20,
    0x0e, 0x36, 0x09, 0x32, 0x33, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x33, 0x27,
    0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x34, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36,
    0x09, 0x32, 0x35, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x35, 0x27, 0x35, 0x09,
    0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x36, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0f, 0x35, 0x09, 0x37,
    0x27, 0x35, 0x09, 0x34, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0f, 0x35,
    0x09, 0x38, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0f, 0x35, 0x09, 0x39, 0x27, 0x35, 0x09, 0x34, 0x20,
    0x0e, 0x36, 0x09, 0x33, 0x30, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x30, 0x27,
    0x35, 0x09, 0x34, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x31, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0e, 0x36,
    0x09, 0x33, 0x32, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x32, 0x27, 0x35, 0x09,
    0x34, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x33, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0e, 0x36, 0x09, 0x33,
    0x34, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x35, 0x27, 0x35, 0x09, 0x35, 0x20,
    0x0e, 0x36, 0x09, 0x33, 0x35, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x36, 0x27,
    0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09, 0x37, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09,
    0x37, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f,
    0x35, 0x09, 0x39, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09, 0x39, 0x27, 0x35, 0x09, 0x35,
    0x20, 0x0e, 0x36, 0x09, 0x34, 0x30, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x31,
    0x27, 0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x32, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0e,
    0x36, 0x09, 0x34, 0x32, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x33, 0x27, 0x35,
    0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x34, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09,
    0x34, 0x34, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x35, 0x27, 0x35, 0x09, 0x36,
    0x20, 0x0e, 0x36, 0x09, 0x34, 0x36, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x36,
    0x27, 0x35, 0x09, 0x36, 0x20, 0x03, 0x34, 0x09, 0x0c, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20,
    0x64, 0x6f, 0x67, 0x20, 0x34, 0x37, 0x36, 0x0a, 0x11, 0x00, 0x00,
};
constexpr std::size_t kLzo1x1Sample_len = 731;
constexpr unsigned char kLzo1x999Sample[] = {
    0x17, 0x6c, 0x69, 0x6e, 0x65, 0x20, 0x30, 0x40, 0x00, 0x00, 0x0e, 0x3a, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78,
    0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x98, 0x03, 0x08, 0x6c, 0x61,
    0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x20, 0x30, 0x0a, 0xe1, 0x07, 0x31, 0x20, 0x0d, 0xe1, 0x00,
    0x37, 0x27, 0xe1, 0x00, 0x32, 0x20, 0x0d, 0xe2, 0x00, 0x31, 0x34, 0x27, 0xe5, 0x00, 0x33, 0x20,
    0x0d, 0xe6, 0x00, 0x32, 0x31, 0x27, 0xe5, 0x00, 0x34, 0x20, 0x0e, 0xe5, 0x00, 0x38, 0x27, 0xe5,
    0x00, 0x35, 0x20, 0x0d, 0xe6, 0x00, 0x33, 0x35, 0x27, 0xe5, 0x00, 0x36, 0x20, 0x0d, 0xe6, 0x00,
    0x34, 0x32, 0x27, 0xe5, 0x00, 0x37, 0x20, 0x0e, 0xe5, 0x00, 0x39, 0x27, 0xe5, 0x00, 0x38, 0x20,
    0x0d, 0xe6, 0x00, 0x35, 0x36, 0x27, 0xe5, 0x00, 0x39, 0x20, 0x0d, 0xe6, 0x00, 0x36, 0x33, 0xe5,
    0x07, 0x31, 0x20, 0x0e, 0x05, 0x09, 0x37, 0x27, 0x09, 0x09, 0x31, 0x20, 0x0f, 0x08, 0x09, 0x27,
    0x0d, 0x09, 0x31, 0x20, 0x0e, 0x0d, 0x09, 0x38, 0x27, 0x0d, 0x09, 0x31, 0x20, 0x0e, 0x0d, 0x09,
    0x39, 0x27, 0x0d, 0x09, 0x31, 0x20, 0x0e, 0x0d, 0x09, 0x39, 0x27, 0x0d, 0x09, 0x31, 0x20, 0x0e,
    0x0e, 0x09, 0x31, 0x30, 0x27, 0x11, 0x09, 0x31, 0x20, 0x0e, 0x12, 0x09, 0x31, 0x31, 0x27, 0x16,
    0x09, 0x31, 0x37, 0x20, 0x0f, 0xe8, 0x00, 0x27, 0x19, 0x09, 0x31, 0x20, 0x0e, 0x1a, 0x09, 0x31,
    0x32, 0x27, 0x1d, 0x09, 0x31, 0x20, 0x0e, 0x1e, 0x09, 0x31, 0x33, 0x27, 0x22, 0x09, 0x32, 0x30,
    0x20, 0x0f, 0x60, 0x10, 0x27, 0x26, 0x09, 0x32, 0x31, 0x20, 0x0f, 0xe8, 0x00, 0x27, 0x29, 0x09,
    0x32, 0x20, 0x0f, 0x39, 0x12, 0x35, 0x27, 0x2d, 0x09, 0x32, 0x20, 0x0e, 0x2e, 0x09, 0x31, 0x36,
    0x27, 0x32, 0x09, 0x32, 0x34, 0x20, 0x0f, 0xe8, 0x00, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0f, 0x35,
    0x09, 0x37, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x32, 0x20,
    0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x32, 0x20, 0x0f, 0x35, 0x09, 0x39, 0x27, 0x35, 0x09,
    0x32, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x30, 0x27, 0x36, 0x09, 0x33, 0x30, 0x20, 0x0f, 0xb0, 0x18,
    0x27, 0x36, 0x09, 0x33, 0x31, 0x20, 0x0f, 0xe8, 0x00, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36,
    0x09, 0x32, 0x32, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0f, 0x75, 0x1b, 0x33, 0x27, 0x35, 0x09, 0x33,
    0x20, 0x0f, 0x79, 0x1b, 0x33, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x34, 0x27,
    0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x35, 0x27, 0x36, 0x09, 0x33, 0x37, 0x20, 0x0f,
    0xe8, 0x00, 0x27, 0x35, 0x09, 0x33, 0x20, 0x0e, 0x36, 0x09, 0x32, 0x36, 0x27, 0x35, 0x09, 0x33,
    0x20, 0x0f, 0x35, 0x09, 0x37, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35,
    0x09, 0x34, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0f, 0x35, 0x09, 0x39,
    0x27, 0x35, 0x09, 0x34, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x30, 0x27, 0x36, 0x09, 0x34, 0x34, 0x20,
    0x0f, 0xe8, 0x00, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0f, 0xb5, 0x24, 0x31, 0x27, 0x35, 0x09, 0x34,
    0x20, 0x0e, 0x36, 0x09, 0x33, 0x32, 0x27, 0x36, 0x09, 0x34, 0x37, 0x20, 0x0f, 0xe8, 0x00, 0x27,
    0x35, 0x09, 0x34, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x33, 0x27, 0x35, 0x09, 0x34, 0x20, 0x0e, 0x36,
    0x09, 0x33, 0x34, 0x27, 0x36, 0x09, 0x35, 0x30, 0x20, 0x0f, 0x50, 0x29, 0x27, 0x36, 0x09, 0x35,
    0x31, 0x20, 0x0f, 0xe8, 0x00, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0e, 0x36, 0x09, 0x33, 0x36, 0x27,
    0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09, 0x37, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09,
    0x37, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09, 0x38, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f,
    0x35, 0x09, 0x39, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0f, 0x35, 0x09, 0x39, 0x27, 0x35, 0x09, 0x35,
    0x20, 0x0e, 0x36, 0x09, 0x34, 0x30, 0x27, 0x35, 0x09, 0x35, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x31,
    0x27, 0x36, 0x09, 0x36, 0x30, 0x20, 0x0f, 0xa0, 0x31, 0x27, 0x36, 0x09, 0x36, 0x31, 0x20, 0x0f,
    0xe8, 0x00, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x33, 0x27, 0x35, 0x09, 0x36,
    0x20, 0x0e, 0x36, 0x09, 0x34, 0x34, 0x27, 0x36, 0x09, 0x36, 0x34, 0x20, 0x0f, 0xe8, 0x00, 0x27,
    0x35, 0x09, 0x36, 0x20, 0x0e, 0x36, 0x09, 0x34, 0x35, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0f, 0x29,
    0x37, 0x36, 0x27, 0x35, 0x09, 0x36, 0x20, 0x0f, 0x2d, 0x37, 0x36, 0x27, 0x35, 0x09, 0x36, 0x20,
    0x0f, 0x35, 0x09, 0x37, 0x04, 0x93, 0x11, 0x00, 0x00,
};
constexpr std::size_t kLzo1x999Sample_len = 697;
constexpr unsigned char kLzo1xEmpty[] = {
    0x11,
    0x00,
    0x00,
};
constexpr std::size_t kLzo1xEmpty_len = 3;

// ---------------------------------------------------------------- sample data

Bytes pseudo_random(std::size_t n, std::uint64_t seed) {
    Bytes v(n);
    std::uint64_t x = seed;
    for (std::size_t i = 0; i < n; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v[i] = static_cast<std::uint8_t>((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    return v;
}

// Compressible text with a little entropy mixed in: ~1 MiB.
Bytes sample_text(std::size_t target = 1u << 20) {
    Bytes v;
    const Bytes noise = pseudo_random(4096, 1);
    std::size_t i = 0;
    while (v.size() < target) {
        char line[96];
        const int n = std::snprintf(line, sizeof line,
                                    "record %06zu: firmware image partition table entry %zu\n", i,
                                    i * 31 % 977);
        v.insert(v.end(), line, line + n);
        if (i % 64 == 0)
            v.insert(v.end(), noise.begin() + static_cast<std::ptrdiff_t>(i % 3000),
                     noise.begin() + static_cast<std::ptrdiff_t>(i % 3000) + 32);
        ++i;
    }
    v.resize(target);
    return v;
}

// The 4 KiB sample liblzo2 compressed to make the embedded LZO fixture below.
Bytes lzo_sample() {
    Bytes buf(4096);
    std::size_t n = 0;
    for (int i = 0; n + 64 < buf.size(); ++i) {
        n += static_cast<std::size_t>(
            std::snprintf(reinterpret_cast<char*>(buf.data()) + n, buf.size() - n,
                          "line %04d: the quick brown fox jumps over the lazy dog %d\n", i, i * 7));
    }
    buf.resize(n);
    return buf;
}

// ---------------------------------------------------------------- encoders

Bytes zlib_encode(const Bytes& in, int window_bits) {
    z_stream zs{};
    EXPECT_EQ(deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY),
              Z_OK);
    Bytes out(deflateBound(&zs, static_cast<uLong>(in.size())) + 64);
    zs.next_in = const_cast<Bytef*>(in.data());
    zs.avail_in = static_cast<uInt>(in.size());
    zs.next_out = out.data();
    zs.avail_out = static_cast<uInt>(out.size());
    EXPECT_EQ(deflate(&zs, Z_FINISH), Z_STREAM_END);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

Bytes xz_encode(const Bytes& in) {
    Bytes out(lzma_stream_buffer_bound(in.size()));
    std::size_t out_pos = 0;
    EXPECT_EQ(lzma_easy_buffer_encode(6, LZMA_CHECK_CRC32, nullptr, in.data(), in.size(),
                                      out.data(), &out_pos, out.size()),
              LZMA_OK);
    out.resize(out_pos);
    return out;
}

Bytes lzma_alone_encode(const Bytes& in) {
    lzma_options_lzma opt;
    EXPECT_FALSE(lzma_lzma_preset(&opt, 6));
    lzma_stream s = LZMA_STREAM_INIT;
    EXPECT_EQ(lzma_alone_encoder(&s, &opt), LZMA_OK);
    Bytes out(in.size() + in.size() / 2 + 1024);
    s.next_in = in.data();
    s.avail_in = in.size();
    s.next_out = out.data();
    s.avail_out = out.size();
    EXPECT_EQ(lzma_code(&s, LZMA_FINISH), LZMA_STREAM_END);
    out.resize(s.total_out);
    lzma_end(&s);
    return out;
}

Bytes lz4_block_encode(const Bytes& in) {
    Bytes out(static_cast<std::size_t>(LZ4_compressBound(static_cast<int>(in.size()))));
    const int n = LZ4_compress_default(reinterpret_cast<const char*>(in.data()),
                                       reinterpret_cast<char*>(out.data()),
                                       static_cast<int>(in.size()), static_cast<int>(out.size()));
    EXPECT_GT(n, 0);
    out.resize(static_cast<std::size_t>(n));
    return out;
}

Bytes lz4_frame_encode(const Bytes& in) {
    LZ4F_preferences_t prefs{};
    prefs.frameInfo.blockSizeID = LZ4F_max64KB;
    prefs.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
    Bytes out(LZ4F_compressFrameBound(in.size(), &prefs));
    const std::size_t n = LZ4F_compressFrame(out.data(), out.size(), in.data(), in.size(), &prefs);
    EXPECT_FALSE(LZ4F_isError(n));
    out.resize(n);
    return out;
}

void put_le32(Bytes& v, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}

// Legacy frame: magic 0x184C2102 then [u32 csize][block] with 8 MiB blocks.
Bytes lz4_legacy_encode(const Bytes& in) {
    Bytes out;
    put_le32(out, 0x184C2102u);
    constexpr std::size_t kBlock = 8u << 20;
    for (std::size_t off = 0; off < in.size(); off += kBlock) {
        const Bytes block(
            in.begin() + static_cast<std::ptrdiff_t>(off),
            in.begin() + static_cast<std::ptrdiff_t>(std::min(in.size(), off + kBlock)));
        const Bytes c = lz4_block_encode(block);
        put_le32(out, static_cast<std::uint32_t>(c.size()));
        out.insert(out.end(), c.begin(), c.end());
    }
    return out;
}

// zstd with the content checksum turned on; ZSTD_compress leaves it off.
Bytes zstd_encode_checked(const Bytes& in) {
    ZSTD_CCtx* c = ZSTD_createCCtx();
    EXPECT_NE(c, nullptr);
    EXPECT_FALSE(ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 1)));
    Bytes out(ZSTD_compressBound(in.size()));
    const std::size_t n = ZSTD_compress2(c, out.data(), out.size(), in.data(), in.size());
    EXPECT_FALSE(ZSTD_isError(n));
    out.resize(n);
    ZSTD_freeCCtx(c);
    return out;
}

Bytes zstd_encode(const Bytes& in) {
    Bytes out(ZSTD_compressBound(in.size()));
    const std::size_t n = ZSTD_compress(out.data(), out.size(), in.data(), in.size(), 3);
    EXPECT_FALSE(ZSTD_isError(n));
    out.resize(n);
    return out;
}

// Reference rtime encoder, from the algorithm description in compr_rtime.c:
// emit the byte, then the number of following bytes that repeat what followed
// the previous occurrence of that byte.
Bytes rtime_encode(const Bytes& in) {
    Bytes out;
    std::size_t positions[256] = {};
    std::size_t pos = 0;
    while (pos < in.size()) {
        const std::uint8_t value = in[pos];
        out.push_back(value);
        ++pos;
        std::size_t back = positions[value];
        positions[value] = pos;
        std::size_t run = 0;
        while (back < pos && pos < in.size() && in[pos] == in[back] && run < 255) {
            ++pos;
            ++back;
            ++run;
        }
        out.push_back(static_cast<std::uint8_t>(run));
    }
    return out;
}

// Every codec whose encoder we have, with the encoder to build its input.
struct RoundTrip {
    Codec codec;
    Bytes (*encode)(const Bytes&);
};

const RoundTrip kRoundTrips[] = {
    {Codec::Zlib, [](const Bytes& b) { return zlib_encode(b, 15); }},
    {Codec::Zlib,
     [](const Bytes& b) { return zlib_encode(b, 15 + 16); }},  // auto-detect accepts gzip
    {Codec::Deflate, [](const Bytes& b) { return zlib_encode(b, -15); }},
    {Codec::Gzip, [](const Bytes& b) { return zlib_encode(b, 15 + 16); }},
    {Codec::Xz, xz_encode},
    {Codec::Lzma, lzma_alone_encode},
    {Codec::Lz4, lz4_frame_encode},
    {Codec::Lz4, lz4_block_encode},
    {Codec::Lz4, lz4_legacy_encode},
    {Codec::Lz4Legacy, lz4_legacy_encode},
    {Codec::Lz4Legacy, lz4_block_encode},
    {Codec::Zstd, zstd_encode},
    {Codec::Rtime, rtime_encode},
};

// ---------------------------------------------------------------- round trips

TEST(Compression, CodecNames) {
    EXPECT_STREQ(codec_name(Codec::None), "none");
    EXPECT_STREQ(codec_name(Codec::Zlib), "zlib");
    EXPECT_STREQ(codec_name(Codec::Deflate), "deflate");
    EXPECT_STREQ(codec_name(Codec::Gzip), "gzip");
    EXPECT_STREQ(codec_name(Codec::Xz), "xz");
    EXPECT_STREQ(codec_name(Codec::Lzma), "lzma");
    EXPECT_STREQ(codec_name(Codec::Lz4), "lz4");
    EXPECT_STREQ(codec_name(Codec::Lz4Legacy), "lz4-legacy");
    EXPECT_STREQ(codec_name(Codec::Zstd), "zstd");
    EXPECT_STREQ(codec_name(Codec::Lzo1x), "lzo1x");
    EXPECT_STREQ(codec_name(Codec::Rtime), "rtime");
}

TEST(Compression, RoundTripsText) {
    const Bytes plain = sample_text();
    for (const auto& rt : kRoundTrips) {
        const Bytes packed = rt.encode(plain);
        Bytes out{1, 2, 3};  // must be cleared
        const Status s = decompress(rt.codec, packed, out, plain.size());
        ASSERT_TRUE(s) << codec_name(rt.codec) << ": " << s.error;
        EXPECT_EQ(out, plain) << codec_name(rt.codec);
        // Exact form with the right size.
        Bytes out2;
        const Status s2 = decompress_exact(rt.codec, packed, out2, plain.size());
        ASSERT_TRUE(s2) << codec_name(rt.codec) << ": " << s2.error;
        EXPECT_EQ(out2, plain) << codec_name(rt.codec);
    }
}

TEST(Compression, RoundTripsIncompressible) {
    const Bytes plain = pseudo_random(300'000, 99);
    for (const auto& rt : kRoundTrips) {
        const Bytes packed = rt.encode(plain);
        Bytes out;
        const Status s = decompress(rt.codec, packed, out, plain.size() * 2);
        ASSERT_TRUE(s) << codec_name(rt.codec) << ": " << s.error;
        EXPECT_EQ(out, plain) << codec_name(rt.codec);
    }
}

TEST(Compression, RoundTripsEmptyPayload) {
    const Bytes plain;
    for (const auto& rt : kRoundTrips) {
        const Bytes packed = rt.encode(plain);
        Bytes out;
        const Status s = decompress(rt.codec, packed, out, 0);
        EXPECT_TRUE(s) << codec_name(rt.codec) << ": " << s.error;
        EXPECT_TRUE(out.empty()) << codec_name(rt.codec);
        EXPECT_TRUE(decompress_exact(rt.codec, packed, out, 0)) << codec_name(rt.codec);
    }
}

TEST(Compression, LargeMultiBlockLz4Legacy) {
    const Bytes plain = sample_text(9u << 20);  // two legacy blocks
    const Bytes packed = lz4_legacy_encode(plain);
    Bytes out;
    ASSERT_TRUE(decompress(Codec::Lz4Legacy, packed, out, plain.size()));
    EXPECT_EQ(out, plain);
}

TEST(Compression, NoneCopiesAndCaps) {
    const Bytes plain = pseudo_random(1000, 5);
    Bytes out;
    ASSERT_TRUE(decompress(Codec::None, plain, out, 1000));
    EXPECT_EQ(out, plain);
    EXPECT_EQ(decompress(Codec::None, plain, out, 999).error, "decompress-cap");
    EXPECT_TRUE(decompress_exact(Codec::None, plain, out, 1000));
    EXPECT_FALSE(decompress_exact(Codec::None, plain, out, 1001));
}

// ---------------------------------------------------------------- caps

TEST(Compression, CapOneByteShortFails) {
    const Bytes plain = sample_text();
    for (const auto& rt : kRoundTrips) {
        const Bytes packed = rt.encode(plain);
        Bytes out;
        const Status s = decompress(rt.codec, packed, out, plain.size() - 1);
        EXPECT_FALSE(s) << codec_name(rt.codec);
        EXPECT_EQ(s.error, "decompress-cap") << codec_name(rt.codec);
        EXPECT_LE(out.size(), plain.size() - 1) << codec_name(rt.codec);
        // Tiny cap: output never exceeds it.
        const Status t = decompress(rt.codec, packed, out, 10);
        EXPECT_EQ(t.error, "decompress-cap") << codec_name(rt.codec);
        EXPECT_LE(out.size(), 10u) << codec_name(rt.codec);
        // Zero cap.
        const Status z = decompress(rt.codec, packed, out, 0);
        EXPECT_EQ(z.error, "decompress-cap") << codec_name(rt.codec);
        EXPECT_TRUE(out.empty()) << codec_name(rt.codec);
    }
}

TEST(Compression, ExactSizeMismatchFails) {
    const Bytes plain = sample_text(100'000);
    for (const auto& rt : kRoundTrips) {
        const Bytes packed = rt.encode(plain);
        Bytes out;
        EXPECT_FALSE(decompress_exact(rt.codec, packed, out, plain.size() - 1))
            << codec_name(rt.codec);
        const Status s = decompress_exact(rt.codec, packed, out, plain.size() + 1);
        EXPECT_FALSE(s) << codec_name(rt.codec);
        EXPECT_EQ(s.error, "decompress-size-mismatch") << codec_name(rt.codec);
    }
}

// A zip bomb style stream: 64 MiB of zeros compresses to a few KiB. The cap
// must stop it long before it allocates 64 MiB.
TEST(Compression, HighRatioStreamStopsAtCap) {
    const Bytes zeros(64u << 20, 0);
    const Bytes packed = zlib_encode(zeros, 15);
    ASSERT_LT(packed.size(), zeros.size() / 100);  // at least 100:1 (default level gives ~230:1)
    Bytes out;
    const Status s = decompress(Codec::Zlib, packed, out, 1u << 20);
    EXPECT_EQ(s.error, "decompress-cap");
    EXPECT_LE(out.size(), 1u << 20);
    EXPECT_LE(out.capacity(), (1u << 20) + (1u << 20));
}

// ---------------------------------------------------------------- hostile input

TEST(Compression, EmptyInputFails) {
    Bytes out;
    for (Codec c : {Codec::Zlib, Codec::Deflate, Codec::Gzip, Codec::Xz, Codec::Lzma, Codec::Lz4,
                    Codec::Lz4Legacy, Codec::Zstd, Codec::Lzo1x}) {
        EXPECT_FALSE(decompress(c, {}, out, 1 << 20)) << codec_name(c);
        EXPECT_TRUE(out.empty()) << codec_name(c);
    }
    // rtime: empty in, empty out is well defined.
    EXPECT_TRUE(decompress(Codec::Rtime, {}, out, 1 << 20));
    EXPECT_TRUE(out.empty());
}

TEST(Compression, GarbageInputFails) {
    const Bytes garbage = pseudo_random(4096, 1234);
    Bytes out;
    for (Codec c : {Codec::Zlib, Codec::Deflate, Codec::Gzip, Codec::Xz, Codec::Lzma, Codec::Lz4,
                    Codec::Lz4Legacy, Codec::Zstd, Codec::Lzo1x}) {
        const Status s = decompress(c, garbage, out, 1 << 20);
        EXPECT_FALSE(s) << codec_name(c);
        EXPECT_FALSE(s.error.empty()) << codec_name(c);
    }
}

TEST(Compression, TruncatedStreamsFailCleanly) {
    const Bytes plain = sample_text(200'000);
    for (const auto& rt : kRoundTrips) {
        const Bytes packed = rt.encode(plain);
        // Several truncation points, including inside the header and one byte short.
        for (std::size_t keep : {std::size_t{1}, std::size_t{3}, std::size_t{7}, packed.size() / 3,
                                 packed.size() / 2, packed.size() - 1}) {
            if (keep >= packed.size()) continue;
            const std::span<const std::uint8_t> cut(packed.data(), keep);
            Bytes out;
            const Status s = decompress(rt.codec, cut, out, plain.size());
            if (rt.codec == Codec::Rtime) {
                // rtime has no end marker: a truncated stream just yields a prefix
                // (or fails on a dangling odd byte). Either way it must be a prefix.
                if (s) {
                    EXPECT_TRUE(std::equal(out.begin(), out.end(), plain.begin()))
                        << "rtime keep=" << keep;
                }
                continue;
            }
            if ((rt.codec == Codec::Lz4 || rt.codec == Codec::Lz4Legacy) && keep == 1) {
                // One byte cannot hold a frame magic, so this is decoded as a
                // raw block, and lz4's own decoder defines a lone token with a
                // zero literal count as a valid empty block (LZ4_compress emits
                // exactly that for empty input). Nothing distinguishes the two,
                // but an exact-size check still rejects it.
                if (s) {
                    EXPECT_TRUE(out.empty()) << codec_name(rt.codec) << " keep=1";
                }
            } else {
                EXPECT_FALSE(s) << codec_name(rt.codec) << " keep=" << keep;
            }
            EXPECT_FALSE(decompress_exact(rt.codec, cut, out, plain.size()))
                << codec_name(rt.codec) << " keep=" << keep;
        }
    }
}

TEST(Compression, CorruptedBodyFails) {
    const Bytes plain = sample_text(200'000);
    for (const auto& rt : kRoundTrips) {
        if (rt.codec == Codec::Rtime) continue;  // no integrity check in the format
        Bytes packed = rt.encode(plain);
        // Flip bytes in the middle of the payload.
        for (std::size_t i = packed.size() / 2; i < packed.size() / 2 + 16 && i < packed.size();
             ++i)
            packed[i] ^= 0xA5;
        Bytes out;
        const Status s = decompress_exact(rt.codec, packed, out, plain.size());
        EXPECT_FALSE(s) << codec_name(rt.codec);
        EXPECT_LE(out.size(), plain.size()) << codec_name(rt.codec);
    }
}

TEST(Compression, TrailingGarbageAfterStreamIsTolerated) {
    const Bytes plain = sample_text(50'000);
    const Bytes junk = pseudo_random(777, 8);
    for (const auto& rt : kRoundTrips) {
        if (rt.codec == Codec::Rtime || rt.encode == lz4_block_encode)
            continue;                                  // no framing to end on
        if (rt.encode == lz4_legacy_encode) continue;  // legacy frame reads blocks until input ends
        Bytes packed = rt.encode(plain);
        packed.insert(packed.end(), junk.begin(), junk.end());
        Bytes out;
        const Status s = decompress(rt.codec, packed, out, plain.size() * 2);
        EXPECT_TRUE(s) << codec_name(rt.codec) << ": " << s.error;
        EXPECT_EQ(out, plain) << codec_name(rt.codec);
    }
}

TEST(Compression, ConcatenatedMembersDecodeAsOne) {
    const Bytes a = sample_text(30'000);
    const Bytes b = pseudo_random(20'000, 3);
    Bytes both = a;
    both.insert(both.end(), b.begin(), b.end());
    struct Case {
        Codec codec;
        Bytes (*enc)(const Bytes&);
    };
    const Case cases[] = {
        {Codec::Gzip, [](const Bytes& x) { return zlib_encode(x, 15 + 16); }},
        {Codec::Zlib, [](const Bytes& x) { return zlib_encode(x, 15 + 16); }},
        {Codec::Xz, xz_encode},
        {Codec::Lz4, lz4_frame_encode},
        {Codec::Zstd, zstd_encode},
    };
    for (const auto& c : cases) {
        Bytes packed = c.enc(a);
        const Bytes second = c.enc(b);
        packed.insert(packed.end(), second.begin(), second.end());
        Bytes out;
        const Status s = decompress(c.codec, packed, out, both.size());
        ASSERT_TRUE(s) << codec_name(c.codec) << ": " << s.error;
        EXPECT_EQ(out, both) << codec_name(c.codec);
    }
    // Plain zlib (RFC 1950) has no member concept: the second stream is trailing data.
    {
        Bytes packed = zlib_encode(a, 15);
        const Bytes second = zlib_encode(b, 15);
        packed.insert(packed.end(), second.begin(), second.end());
        Bytes out;
        ASSERT_TRUE(decompress(Codec::Zlib, packed, out, both.size()));
        EXPECT_EQ(out, a);
    }
}

TEST(Compression, AbsurdLzmaDictionaryIsRefused) {
    // An .xz header declaring a 1.5 GiB dictionary for a tiny block must not
    // make liblzma allocate it: the memlimit is tied to the output cap.
    lzma_options_lzma opt;
    ASSERT_FALSE(lzma_lzma_preset(&opt, 0));
    opt.dict_size = 1536u << 20;
    lzma_filter filters[] = {{LZMA_FILTER_LZMA2, &opt}, {LZMA_VLI_UNKNOWN, nullptr}};
    const Bytes plain = sample_text(4096);
    Bytes packed(lzma_stream_buffer_bound(plain.size()));
    std::size_t pos = 0;
    ASSERT_EQ(lzma_stream_buffer_encode(filters, LZMA_CHECK_CRC32, nullptr, plain.data(),
                                        plain.size(), packed.data(), &pos, packed.size()),
              LZMA_OK);
    packed.resize(pos);
    Bytes out;
    const Status s = decompress_exact(Codec::Xz, packed, out, plain.size());
    EXPECT_FALSE(s);
    EXPECT_EQ(s.error, "decompress-memlimit");
}

// A raw lz4 block has no size field, so "bigger than the cap" and "corrupt"
// both make the strict decoder fail; the codes must still tell them apart,
// and a block cut short must never come back as a clean prefix.
TEST(Compression, Lz4RawBlockCapVersusCorrupt) {
    const Bytes plain = sample_text(50'000);
    const Bytes packed = lz4_block_encode(plain);
    Bytes out;
    for (Codec c : {Codec::Lz4, Codec::Lz4Legacy}) {
        EXPECT_EQ(decompress(c, packed, out, plain.size() - 1).error, "decompress-cap")
            << codec_name(c);
        EXPECT_LE(out.size(), plain.size() - 1) << codec_name(c);
        EXPECT_EQ(decompress(c, packed, out, 1).error, "decompress-cap") << codec_name(c);
        Bytes bad = packed;
        bad[bad.size() / 2] ^= 0xff;
        bad[bad.size() / 2 + 1] ^= 0xff;
        const Status s = decompress(c, bad, out, plain.size() * 2);
        EXPECT_FALSE(s) << codec_name(c);
        // Flipped bytes may decode as a giant match that crosses the cap
        // before the corruption is noticed; either way the code is stable and
        // the output never exceeds the cap.
        if (s.error == "decompress-cap") {
            EXPECT_LE(out.size(), plain.size() * 2) << codec_name(c);
        } else {
            EXPECT_EQ(s.error, "decompress-corrupt") << codec_name(c);
            EXPECT_TRUE(out.empty()) << codec_name(c);
        }
        // Truncated block: strict decoding rejects it even though the partial
        // decoder would happily return a prefix.
        const std::span<const std::uint8_t> cut(packed.data(), packed.size() - 20);
        EXPECT_EQ(decompress(c, cut, out, plain.size() * 2).error, "decompress-corrupt")
            << codec_name(c);
        EXPECT_TRUE(out.empty()) << codec_name(c);
        EXPECT_FALSE(decompress_exact(c, cut, out, plain.size())) << codec_name(c);
        // A block that is both truncated and over the cap reports the cap.
        EXPECT_EQ(decompress(c, cut, out, 100).error, "decompress-cap") << codec_name(c);
        EXPECT_LE(out.size(), 100u) << codec_name(c);
    }
    // Sizes beyond int range are refused, never truncated to int.
    Bytes out2;
    EXPECT_TRUE(decompress(Codec::Lz4, packed, out2, std::numeric_limits<std::uint64_t>::max()));
    EXPECT_EQ(out2, plain);
}

TEST(Compression, Lz4LegacyBlockSizeOverflowFails) {
    Bytes frame;
    put_le32(frame, 0x184C2102u);
    put_le32(frame, 0xFFFFFFF0u);  // block size far beyond the input
    frame.push_back(0);
    Bytes out;
    EXPECT_FALSE(decompress(Codec::Lz4Legacy, frame, out, 1 << 20));
    // Magic alone is an empty legacy frame (what the lz4 CLI writes for an empty file).
    frame.resize(4);
    EXPECT_TRUE(decompress(Codec::Lz4Legacy, frame, out, 1 << 20));
    EXPECT_TRUE(out.empty());
    // Magic followed by a partial block-size field.
    frame.push_back(0x10);
    EXPECT_EQ(decompress(Codec::Lz4Legacy, frame, out, 1 << 20).error, "decompress-truncated");
    // Zero-length block is not a block.
    frame.resize(4);
    put_le32(frame, 0);
    EXPECT_EQ(decompress(Codec::Lz4Legacy, frame, out, 1 << 20).error, "decompress-corrupt");
    // A block whose size field claims more than remains is truncated input.
    frame.resize(4);
    put_le32(frame, 100);
    frame.insert(frame.end(), 50, 0x00);
    EXPECT_EQ(decompress(Codec::Lz4Legacy, frame, out, 1 << 20).error, "decompress-truncated");
}

// ---------------------------------------------------------------- LZO1X

// Hand-built streams, encoded from the bitstream description.
TEST(Lzo1x, LiteralRunThenMatch) {
    // 0x15: first-byte literal run of 4 ("abcd"); 0x6C 0x00: M2 match len 4
    // dist 4, no trailing literals; 0x11 0x00 0x00: EOF.
    const Bytes stream = {0x15, 'a', 'b', 'c', 'd', 0x6C, 0x00, 0x11, 0x00, 0x00};
    Bytes out;
    const Status s = decompress(Codec::Lzo1x, stream, out, 64);
    ASSERT_TRUE(s) << s.error;
    EXPECT_EQ(std::string(out.begin(), out.end()), "abcdabcd");
    EXPECT_TRUE(decompress_exact(Codec::Lzo1x, stream, out, 8));
    EXPECT_FALSE(decompress_exact(Codec::Lzo1x, stream, out, 9));
    EXPECT_EQ(decompress_exact(Codec::Lzo1x, stream, out, 7).error, "decompress-cap");
}

TEST(Lzo1x, MatchWithTrailingLiteralAndShortMatchStates) {
    // As above but the M2 match carries S=1 ("x"), which puts the decoder in
    // state 1 so the following 0x00 opcode is a 2-byte match at distance 1.
    const Bytes stream = {0x15, 'a', 'b', 'c', 'd', 0x6D, 0x00, 'x', 0x00, 0x00, 0x11, 0x00, 0x00};
    Bytes out;
    ASSERT_TRUE(decompress(Codec::Lzo1x, stream, out, 64));
    EXPECT_EQ(std::string(out.begin(), out.end()), "abcdabcdxxx");
}

TEST(Lzo1x, LongLiteralRunAndExtension) {
    // State 0 opcode 0x02: literal run of 5. Then EOF.
    {
        const Bytes stream = {0x15, 'a', 'b', 'c', 'd', 0x6C, 0x00, 0x02,
                              '1',  '2', '3', '4', '5', 0x11, 0x00, 0x00};
        Bytes out;
        ASSERT_TRUE(decompress(Codec::Lzo1x, stream, out, 64));
        EXPECT_EQ(std::string(out.begin(), out.end()), "abcdabcd12345");
    }
    // Extended literal length: 0x00 0x00 0x01 = 3 + 15 + 255 + 1 = 274 literals.
    {
        Bytes stream = {0x00, 0x00, 0x01};
        for (int i = 0; i < 274; ++i) stream.push_back(static_cast<std::uint8_t>('A' + i % 26));
        stream.insert(stream.end(), {0x11, 0x00, 0x00});
        Bytes out;
        ASSERT_TRUE(decompress(Codec::Lzo1x, stream, out, 1024));
        ASSERT_EQ(out.size(), 274u);
        EXPECT_EQ(out[273], static_cast<std::uint8_t>('A' + 273 % 26));
    }
}

TEST(Lzo1x, M3AndM4Matches) {
    // 300 literals via extension (0x00, 0x00, 0x1b → 3+15+255+27 = 300), then
    // M3 (001LLLLL): len 2+5=7 at distance 300 (LE16 = (299<<2)|0), then
    // another M3: len 2+3=5 at distance 307 with S=2 trailing literals, then EOF.
    Bytes stream = {0x00, 0x00, 0x1b};
    for (int i = 0; i < 300; ++i) stream.push_back(static_cast<std::uint8_t>(i));
    stream.insert(stream.end(), {0x25, static_cast<std::uint8_t>((299u << 2) & 0xff),
                                 static_cast<std::uint8_t>((299u << 2) >> 8)});
    stream.insert(stream.end(), {0x23, static_cast<std::uint8_t>(((306u << 2) | 2) & 0xff),
                                 static_cast<std::uint8_t>((306u << 2) >> 8), 'p', 'q'});
    stream.insert(stream.end(), {0x11, 0x00, 0x00});
    Bytes out;
    const Status s = decompress(Codec::Lzo1x, stream, out, 4096);
    ASSERT_TRUE(s) << s.error;
    ASSERT_EQ(out.size(), 300u + 7 + 5 + 2);
    for (int i = 0; i < 7; ++i)
        EXPECT_EQ(out[300 + static_cast<std::size_t>(i)], static_cast<std::uint8_t>(i));
    for (int i = 0; i < 5; ++i)
        EXPECT_EQ(out[307 + static_cast<std::size_t>(i)], out[static_cast<std::size_t>(i)]);
    EXPECT_EQ(out[312], 'p');
    EXPECT_EQ(out[313], 'q');
}

TEST(Lzo1x, M4LongDistanceMatches) {
    // 33000 literals (0x00, 129 zero bytes, 0x57 → 3+15+129*255+87), then
    // M4 with H=0: 0x12 (len 4), D=16 → distance 16400, copies out[16600..];
    // M4 with H=1: 0x1A (len 4), D=200 → distance 32968, copies out[36..].
    Bytes stream = {0x00};
    stream.insert(stream.end(), 129, 0x00);
    stream.push_back(0x57);
    for (int i = 0; i < 33000; ++i) stream.push_back(static_cast<std::uint8_t>((i * 7) ^ (i >> 8)));
    stream.insert(stream.end(), {0x12, 0x40, 0x00});
    stream.insert(stream.end(), {0x1A, 0x20, 0x03});
    stream.insert(stream.end(), {0x11, 0x00, 0x00});
    Bytes out;
    const Status s = decompress(Codec::Lzo1x, stream, out, 1 << 20);
    ASSERT_TRUE(s) << s.error;
    ASSERT_EQ(out.size(), 33008u);
    for (std::size_t i = 0; i < 4; ++i) EXPECT_EQ(out[33000 + i], out[33000 - 16400 + i]);
    for (std::size_t i = 0; i < 4; ++i) EXPECT_EQ(out[33004 + i], out[33004 - 32968 + i]);
    // H=1 distance beyond what has been produced: lookbehind overrun.
    Bytes bad(stream.begin(), stream.begin() + static_cast<std::ptrdiff_t>(stream.size() - 6));
    bad.insert(bad.end(), {0x1A, 0xFC, 0xFF, 0x11, 0x00, 0x00});  // distance 32768 + 16383
    EXPECT_EQ(decompress(Codec::Lzo1x, bad, out, 1 << 20).error, "lzo1x-lookbehind-overrun");
}

TEST(Lzo1x, EmptyStreamIsJustEof) {
    const Bytes stream = {0x11, 0x00, 0x00};
    Bytes out{9};
    ASSERT_TRUE(decompress(Codec::Lzo1x, stream, out, 0));
    EXPECT_TRUE(out.empty());
    EXPECT_TRUE(decompress_exact(Codec::Lzo1x, stream, out, 0));
}

TEST(Lzo1x, RealEncoderStreams) {
    // Streams produced by liblzo2 (lzo1x_1 and lzo1x_999) from lzo_sample().
    const Bytes plain = lzo_sample();
    ASSERT_EQ(plain.size(), 4054u);
    for (auto [p, n] : {std::pair{kLzo1x1Sample, kLzo1x1Sample_len},
                        std::pair{kLzo1x999Sample, kLzo1x999Sample_len}}) {
        const std::span<const std::uint8_t> packed(p, n);
        Bytes out;
        const Status s = decompress_exact(Codec::Lzo1x, packed, out, plain.size());
        ASSERT_TRUE(s) << s.error;
        EXPECT_EQ(out, plain);
        // Every truncation must fail without faulting.
        for (std::size_t keep = 0; keep < n; ++keep) {
            Bytes t;
            EXPECT_FALSE(decompress(Codec::Lzo1x, packed.subspan(0, keep), t, plain.size()))
                << keep;
            EXPECT_LE(t.size(), plain.size());
        }
    }
    const Bytes empty(kLzo1xEmpty, kLzo1xEmpty + kLzo1xEmpty_len);
    Bytes out;
    EXPECT_TRUE(decompress_exact(Codec::Lzo1x, empty, out, 0));
}

TEST(Lzo1x, HostileStreams) {
    Bytes out;
    // Lookbehind before the start of output: match at distance 8 with 4 bytes emitted.
    {
        const Bytes stream = {0x15, 'a', 'b', 'c', 'd', 0x7C, 0x00, 0x11, 0x00, 0x00};
        const Status s = decompress(Codec::Lzo1x, stream, out, 64);
        EXPECT_EQ(s.error, "lzo1x-lookbehind-overrun");
        EXPECT_EQ(out.size(), 4u);
    }
    // Match into nothing at all. A first byte above 17 is always a literal
    // run, so the only way to open with a match is opcode 16 (0001 0000: M4,
    // length 7+ext+2, distance 16384+D), which the bitstream notes call
    // "always invalid at this place".
    {
        const Bytes stream = {0x10, 0x01, 0x04, 0x00, 0x11, 0x00, 0x00};
        EXPECT_EQ(decompress(Codec::Lzo1x, stream, out, 64).error, "lzo1x-lookbehind-overrun");
        EXPECT_TRUE(out.empty());
    }
    // Same via a first-byte literal of one byte followed by an M2 match of
    // distance 4 when only one byte exists.
    {
        const Bytes stream = {0x12, 'q', 0x6C, 0x00, 0x11, 0x00, 0x00};
        EXPECT_EQ(decompress(Codec::Lzo1x, stream, out, 64).error, "lzo1x-lookbehind-overrun");
        EXPECT_EQ(out.size(), 1u);
    }
    // Missing EOF marker.
    {
        const Bytes stream = {0x15, 'a', 'b', 'c', 'd'};
        EXPECT_EQ(decompress(Codec::Lzo1x, stream, out, 64).error, "lzo1x-eof-not-found");
        EXPECT_EQ(out.size(), 4u);
    }
    // Literal run longer than the input.
    {
        const Bytes stream = {0x40, 'a', 'b'};
        EXPECT_EQ(decompress(Codec::Lzo1x, stream, out, 64).error, "lzo1x-input-overrun");
    }
    // Absurd extended length exceeds the cap without allocating it.
    {
        Bytes stream = {0x00};
        for (int i = 0; i < 100'000; ++i) stream.push_back(0x00);  // 100000 * 255 bytes
        stream.push_back(0x01);
        EXPECT_EQ(decompress(Codec::Lzo1x, stream, out, 1 << 20).error, "decompress-cap");
        EXPECT_LE(out.capacity(), 1u << 20);
    }
    // Run-length copy overlapping itself (dist 1, len 8) must expand correctly.
    {
        const Bytes stream = {0x12, 'z',  0xE0, 0x00,
                              0x11, 0x00, 0x00};  // 1LLDDDSS: L=3 → len 8, dist 1
        ASSERT_TRUE(decompress(Codec::Lzo1x, stream, out, 64));
        EXPECT_EQ(std::string(out.begin(), out.end()), "zzzzzzzzz");
    }
    // Trailing input after EOF: tolerated by decompress, rejected by decompress_exact.
    {
        const Bytes stream = {0x15, 'a', 'b', 'c', 'd', 0x11, 0x00, 0x00, 0xde, 0xad};
        EXPECT_TRUE(decompress(Codec::Lzo1x, stream, out, 64));
        EXPECT_EQ(out.size(), 4u);
        EXPECT_EQ(decompress_exact(Codec::Lzo1x, stream, out, 4).error,
                  "decompress-trailing-input");
    }
}

// ---------------------------------------------------------------- rtime

TEST(Rtime, HandBuiltStreams) {
    Bytes out;
    // "aaaa": 'a' then repeat 3 from the (never seen) position 0 → overlap run.
    ASSERT_TRUE(decompress(Codec::Rtime, Bytes{'a', 3}, out, 16));
    EXPECT_EQ(std::string(out.begin(), out.end()), "aaaa");
    // "abab": 'a' r0, 'b' r2 (copies from position 0).
    ASSERT_TRUE(decompress(Codec::Rtime, Bytes{'a', 0, 'b', 2}, out, 16));
    EXPECT_EQ(std::string(out.begin(), out.end()), "abab");
    // "abcabcabc": 'a' r0, 'b' r0, 'c' r6: 'c' was never seen so its back
    // position is 0; copying 6 bytes from 0 while writing repeats "abc".
    ASSERT_TRUE(decompress(Codec::Rtime, Bytes{'a', 0, 'b', 0, 'c', 6}, out, 16));
    EXPECT_EQ(std::string(out.begin(), out.end()), "abcabcabc");
    // The back position is the output offset *after* the previous occurrence:
    // second 'x' has back = 1, so its repeat of 1 copies the 'y' at offset 1.
    ASSERT_TRUE(decompress(Codec::Rtime, Bytes{'x', 0, 'y', 0, 'x', 1}, out, 16));
    EXPECT_EQ(std::string(out.begin(), out.end()), "xyxy");
    EXPECT_TRUE(decompress_exact(Codec::Rtime, Bytes{'x', 0, 'y', 0, 'x', 1}, out, 4));
    EXPECT_EQ(decompress_exact(Codec::Rtime, Bytes{'x', 0, 'y', 0, 'x', 1}, out, 5).error,
              "decompress-size-mismatch");
}

TEST(Rtime, RoundTripsReferenceEncoder) {
    for (std::size_t n : {std::size_t{1}, std::size_t{2}, std::size_t{255}, std::size_t{256},
                          std::size_t{4096}, std::size_t{100'000}}) {
        for (const Bytes& plain :
             {sample_text(n), pseudo_random(n, n), Bytes(n, 0x00), Bytes(n, 0xff)}) {
            const Bytes packed = rtime_encode(plain);
            Bytes out;
            const Status s = decompress_exact(Codec::Rtime, packed, out, plain.size());
            ASSERT_TRUE(s) << n << ": " << s.error;
            EXPECT_EQ(out, plain) << n;
        }
    }
}

TEST(Rtime, HostileStreams) {
    Bytes out;
    // Dangling value byte with no repeat count.
    EXPECT_EQ(decompress(Codec::Rtime, Bytes{'a', 3, 'b'}, out, 16).error, "rtime-input-overrun");
    EXPECT_EQ(std::string(out.begin(), out.end()), "aaaa");
    // Output cap: 'a' r255 wants 256 bytes.
    EXPECT_EQ(decompress(Codec::Rtime, Bytes{'a', 255}, out, 255).error, "decompress-cap");
    EXPECT_LE(out.size(), 255u);
    EXPECT_TRUE(decompress(Codec::Rtime, Bytes{'a', 255}, out, 256));
    EXPECT_EQ(out.size(), 256u);
    // Zero cap with non-empty input.
    EXPECT_EQ(decompress(Codec::Rtime, Bytes{'a', 0}, out, 0).error, "decompress-cap");
    // A long hostile stream that would expand to 128x its size is stopped at the cap.
    Bytes bomb;
    for (int i = 0; i < 100'000; ++i) {
        bomb.push_back(0);
        bomb.push_back(255);
    }
    EXPECT_EQ(decompress(Codec::Rtime, bomb, out, 1 << 20).error, "decompress-cap");
    EXPECT_LE(out.capacity(), 1u << 20);
}

// ---------------------------------------------------------------- checksums

// What a stream promises about its own payload, read from its header alone.
TEST(Compression, StreamCheckNamesWhatTheHeaderDeclares) {
    const Bytes plain = sample_text(1u << 16);

    EXPECT_EQ(stream_check(Codec::Gzip, zlib_encode(plain, 15 + 16)), "crc32");
    // Auto-detect follows the wrapper actually present.
    EXPECT_EQ(stream_check(Codec::Zlib, zlib_encode(plain, 15 + 16)), "crc32");
    EXPECT_EQ(stream_check(Codec::Zlib, zlib_encode(plain, 15)), "adler32");
    // Raw deflate and LZMA-alone record nothing at all.
    EXPECT_EQ(stream_check(Codec::Deflate, zlib_encode(plain, -15)), "none");
    EXPECT_EQ(stream_check(Codec::Lzma, lzma_alone_encode(plain)), "none");
    // bzip2 always carries CRC-32s, so the answer needs no input.
    EXPECT_EQ(stream_check(Codec::Bzip2, {}), "crc32");
    EXPECT_EQ(stream_check(Codec::Xz, xz_encode(plain)), "crc32");  // xz_encode picks CRC32
    EXPECT_EQ(stream_check(Codec::Lz4, lz4_frame_encode(plain)), "xxh32");
    // ZSTD_compress leaves the content checksum off by default.
    EXPECT_EQ(stream_check(Codec::Zstd, zstd_encode(plain)), "none");
    EXPECT_EQ(stream_check(Codec::Zstd, zstd_encode_checked(plain)), "xxh64");
    // Bare blocks: whatever checks them is not in these bytes.
    EXPECT_EQ(stream_check(Codec::Lzo1x, {}), "");
    EXPECT_EQ(stream_check(Codec::Rtime, {}), "");
    // A header too short to read is not an invitation to guess.
    EXPECT_EQ(stream_check(Codec::Xz, Bytes{0xFD, '7', 'z'}), "");
    EXPECT_EQ(stream_check(Codec::Zstd, Bytes{0x28, 0xB5}), "");
}

// xz names four checks in one nibble of its header; none of them is decoded.
TEST(Compression, StreamCheckReadsEveryXzCheckId) {
    Bytes xz = xz_encode(sample_text(4096));
    const auto with_id = [&](std::uint8_t id) {
        Bytes v = xz;
        v[7] = static_cast<std::uint8_t>((v[7] & 0xF0u) | id);
        return stream_check(Codec::Xz, v);
    };
    EXPECT_EQ(with_id(0x00), "none");
    EXPECT_EQ(with_id(0x01), "crc32");
    EXPECT_EQ(with_id(0x04), "crc64");
    EXPECT_EQ(with_id(0x0A), "sha256");
    EXPECT_EQ(with_id(0x07), "");  // reserved
}

// The payload decoded to its end and only the recorded check disagreed. That
// is not the same failure as corrupt data, and the difference is worth having:
// every byte is recovered and the caller keeps them.
TEST(Compression, ACheckThatFailsIsNotTheSameAsCorruptData) {
    const Bytes plain = sample_text(200000);

    {  // gzip: the 8-byte trailer is CRC-32 then ISIZE.
        Bytes gz = zlib_encode(plain, 15 + 16);
        const std::size_t whole = gz.size();
        gz[gz.size() - 8] ^= 0xFF;
        Bytes out;
        std::uint64_t consumed = 0;
        const Status st = decompress_stream(Codec::Gzip, gz, out, 1u << 22, consumed);
        EXPECT_FALSE(st);
        EXPECT_EQ(st.error, "decompress-checksum-mismatch");
        EXPECT_EQ(out, plain);       // nothing is thrown away
        EXPECT_EQ(consumed, whole);  // and the member's extent is still exact
    }
    {  // zlib: a 4-byte Adler-32 trailer.
        Bytes z = zlib_encode(plain, 15);
        z.back() ^= 0xFF;
        Bytes out;
        std::uint64_t consumed = 0;
        EXPECT_EQ(decompress_stream(Codec::Zlib, z, out, 1u << 22, consumed).error,
                  "decompress-checksum-mismatch");
        EXPECT_EQ(out, plain);
    }
    {  // zstd: the content checksum is the frame's last four bytes.
        Bytes z = zstd_encode_checked(plain);
        z.back() ^= 0xFF;
        Bytes out;
        std::uint64_t consumed = 0;
        EXPECT_EQ(decompress_stream(Codec::Zstd, z, out, 1u << 22, consumed).error,
                  "decompress-checksum-mismatch");
        // Short by at most one output window: neither zstd nor lz4 reports
        // what it wrote on the call that failed the check.
        EXPECT_GE(out.size(), plain.size() - (64u << 10));
        EXPECT_TRUE(std::equal(out.begin(), out.end(), plain.begin()));
    }
    {  // lz4 frame: likewise an xxHash32 at the end.
        Bytes l = lz4_frame_encode(plain);
        l.back() ^= 0xFF;
        Bytes out;
        std::uint64_t consumed = 0;
        EXPECT_EQ(decompress_stream(Codec::Lz4, l, out, 1u << 22, consumed).error,
                  "decompress-checksum-mismatch");
        EXPECT_GE(out.size(), plain.size() - (64u << 10));
        EXPECT_TRUE(std::equal(out.begin(), out.end(), plain.begin()));
    }
    {  // Wrecked deflate data is still plain corruption, not a check failure.
        Bytes gz = zlib_encode(plain, 15 + 16);
        std::fill(gz.begin() + 100, gz.end() - 8, 0x5A);
        Bytes out;
        std::uint64_t consumed = 0;
        EXPECT_EQ(decompress_stream(Codec::Gzip, gz, out, 1u << 22, consumed).error,
                  "decompress-corrupt");
    }
    {  // liblzma does not separate the two, and the code says so.
        Bytes x = xz_encode(plain);
        x[x.size() - 20] ^= 0xFF;
        Bytes out;
        std::uint64_t consumed = 0;
        EXPECT_EQ(decompress_stream(Codec::Xz, x, out, 1u << 22, consumed).error,
                  "decompress-corrupt");
    }
}

}  // namespace
}  // namespace omnitrace::compress

// `stream_ran_out` is the rule that decides whether an unfinished stream still
// earns an extent and a payload. It lives in core and is tested here directly
// because the two callers -- the compressed-stream validator and StreamReader
// -- must not answer it differently, and because two of its three conditions
// are otherwise unreachable from a hand-built gzip: inflate_zlib only reports
// `truncated` when the input is already exhausted, so `consumed == avail`
// holds there by construction. The lzma and lz4 decoders do not have that
// property -- they report a stall as truncated with input still in hand -- and
// this is what stops that becoming a claim on bytes.
TEST(Compression, StreamRanOutIsTruncatedPlusExhaustedPlusOutput) {
    using omnitrace::compress::stream_ran_out;

    // The case it exists for: every byte decoded, more was wanted, output real.
    EXPECT_TRUE(stream_ran_out("decompress-truncated", 998327, 2837007, 998327));

    // Broke mid-data with input to spare. This is every one of the 195
    // unmeasurable hits in the corpus, and how much it managed to decode first
    // is not a defence -- one in the router-wrt image reaches 3774806 bytes.
    EXPECT_FALSE(stream_ran_out("decompress-corrupt", 419097, 1431318, 28341795));
    EXPECT_FALSE(stream_ran_out("decompress-corrupt", 998327, 2837007, 998327))
        << "corrupt is corrupt even when it happens to have eaten everything";

    // Truncated but with input left: the lzma/lz4 stall. Claiming here would
    // take bytes that something else may own.
    EXPECT_FALSE(stream_ran_out("decompress-truncated", 4096, 65536, 1048576));

    // Nothing came out, so there is nothing to recover -- a header in the last
    // few bytes of a region.
    EXPECT_FALSE(stream_ran_out("decompress-truncated", 20, 0, 20));

    // The other failures are not this rule's business.
    EXPECT_FALSE(stream_ran_out("decompress-cap", 100, 100, 100));
    EXPECT_FALSE(stream_ran_out("decompress-checksum-mismatch", 100, 100, 100));
    EXPECT_FALSE(stream_ran_out("decompress-unsupported", 100, 100, 100));
    EXPECT_FALSE(stream_ran_out("", 100, 100, 100));
}
