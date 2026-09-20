// ucl.h — bounds-checked UCL NRV2B decompressor (decompress only).
//
// QNX mkifs compresses an image filesystem with UCL's NRV2B algorithm (the
// "ucl_nrv2b_99_compress" encoder, decoded on the target by the 8-bit-buffer
// variant of the NRV2B decoder). This is an independent implementation
// written from the published description of the NRV2B bit stream: a bit
// buffer refilled one byte at a time (MSB first, a sentinel bit marks the
// empty buffer), literals introduced by a 1 bit, matches by a 0 bit followed
// by a prefix-coded offset (2 = repeat the previous offset, otherwise
// (code - 3) * 256 + one byte + 1), a 2-bit or prefix-coded length, and an
// end marker (offset code 0x1000002 with byte 0xff). Every input read, every
// output write and every back-reference is range checked; a hostile stream
// yields a status code, never an out-of-bounds access.
//
// The NRV2D and NRV2E variants are not decoded: mkifs does not use them.
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace omnitrace::compress::ucl {

enum class Nrv2bStatus {
    Ok,                 // end marker found; `consumed` says how much input was used
    InputOverrun,       // the stream ended before its end marker
    OutputOverrun,      // output would exceed max_out
    LookbehindOverrun,  // match distance reaches before the start of the output
    Corrupt,            // absurd offset or length code
};

const char* nrv2b_status_code(Nrv2bStatus s);  // stable kebab-case code

// Decompress `in` into `out` (cleared first). Never produces more than
// `max_out` bytes. On Ok, `consumed` (if non-null) receives the number of input
// bytes up to and including the end marker; trailing input is left to the
// caller to judge. On failure `out` holds whatever was recovered before the
// fault.
Nrv2bStatus nrv2b_decompress(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                             std::uint64_t max_out, std::size_t* consumed = nullptr);

}  // namespace omnitrace::compress::ucl
