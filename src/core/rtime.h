// rtime.h — JFFS2 "rtime" decompressor.
//
// rtime is JFFS2's cheap run-length style codec (compr_rtime.c in the kernel;
// also used as the fallback when zlib/lzo do not help). The stream is a
// sequence of (value, repeat) byte pairs: emit `value`, then copy `repeat`
// bytes starting at the output position that followed the previous occurrence
// of `value` (0 if never seen). Copies may overlap the bytes being written,
// which is how runs are expressed. There is no end marker: the stream ends
// when the input does, and the expected output size comes from the node.
//
// Independent implementation from the algorithm description. The kernel
// decoder does no bounds checking at all; this one checks every access.
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace omnitrace::compress::rtime {

enum class RtimeStatus {
    Ok,
    InputOverrun,   // odd number of input bytes (dangling value with no repeat)
    OutputOverrun,  // output would exceed max_out
};

const char* rtime_status_code(RtimeStatus s);  // stable kebab-case code

// Decompress the whole of `in` into `out` (cleared first). Never produces more
// than `max_out` bytes; on failure `out` holds what was recovered.
RtimeStatus rtime_decompress(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                             std::uint64_t max_out);

}  // namespace omnitrace::compress::rtime
