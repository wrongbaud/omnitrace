// lzo1x.h — bounds-checked LZO1X decompressor (decompress only).
//
// JFFS2, UBIFS and SquashFS store data compressed with the LZO1X bitstream
// (what the kernel feeds to lzo1x_decompress_safe). This is an independent
// implementation written from the published bitstream description
// (Documentation/lzo.txt in the Linux kernel, "LZO stream format as
// understood by Linux's LZO decompressor"). Every input read, every output
// write and every back-reference is range checked; a hostile stream yields a
// status code, never an out-of-bounds access.
//
// The LZO-RLE extension (bitstream version header 0x11 <ver>) is NOT decoded:
// no filesystem this project reads uses it, and a leading 0x11 in plain LZO1X
// is a legitimate empty stream ("11 00 00").
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace omnitrace::compress::lzo {

enum class Lzo1xStatus {
    Ok,                 // EOF marker found; `consumed` says how much input was used
    InputOverrun,       // instruction needed more input bytes than remained
    OutputOverrun,      // output would exceed max_out
    LookbehindOverrun,  // match distance reaches before the start of the output
    EofNotFound,        // input ended without the 0x11 0x00 0x00 EOF marker
    Corrupt,            // absurd length field
};

const char* lzo1x_status_code(Lzo1xStatus s);  // stable kebab-case code

// Decompress `in` into `out` (cleared first). Never produces more than
// `max_out` bytes. On Ok, `consumed` (if non-null) receives the number of input
// bytes up to and including the EOF marker; trailing input is left to the
// caller to judge. On failure `out` holds whatever was recovered before the
// fault.
Lzo1xStatus lzo1x_decompress_safe(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                                  std::uint64_t max_out, std::size_t* consumed = nullptr);

}  // namespace omnitrace::compress::lzo
