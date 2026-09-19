// Limits.h — guard rails for hostile input. A tripped guard stops that branch,
// records a Diagnostic, and keeps everything recovered so far.
#pragma once
#include <cstddef>
#include <cstdint>

namespace omnitrace {

struct Limits {
    std::size_t max_depth = 8;                   // nested extraction levels
    std::uint64_t max_files = 500'000;           // entries per run
    std::uint64_t max_bytes = 4ull << 30;        // total bytes written per run
    std::uint64_t max_file_bytes = 1ull << 30;   // single extracted file
    std::uint64_t max_decompress_ratio = 1000;   // out/in for one stream
    std::uint64_t max_nodes_per_fs = 5'000'000;  // parsed FS nodes (JFFS2 nodes, inodes...)
};

}  // namespace omnitrace
