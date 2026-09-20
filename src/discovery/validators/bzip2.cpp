// bzip2.cpp — bzip2 stream validator.
//
// Header: "BZh" then one digit '1'..'9', the block size in units of 100 kB.
// What follows is a bit stream, but its first field is byte-aligned in
// practice because the header is a whole number of bytes: either a compressed
// block, which begins with the 48-bit magic 31 41 59 26 53 59 (the first six
// digits of pi, in BCD), or the end-of-stream magic 17 72 45 38 50 90 (the
// square root of pi) for an empty stream.
//
// "BZh" is three bytes and turns up in text, so the digit and that 48-bit
// magic are what actually identify a stream: ten bytes of discriminator
// before the decode probe is asked for anything.
//
// Reference: the bzip2 format description in the bzip2 source
// (`compress.c` / `decompress.c`), and the julian seward format notes.
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

// pi and sqrt(pi) as BCD, the block and end-of-stream markers.
constexpr std::array<std::uint8_t, 6> kBlockMagic{0x31, 0x41, 0x59, 0x26, 0x53, 0x59};
constexpr std::array<std::uint8_t, 6> kEosMagic{0x17, 0x72, 0x45, 0x38, 0x50, 0x90};

std::optional<Finding> validate_bzip2(const Span& span, std::uint64_t start,
                                      const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);

    const auto level = span.u8(start + 3);
    if (!level) {
        diag(f, Severity::Warning, "bzip2-truncated-header",
             "fewer than 4 bytes available for the header");
        return f;
    }
    if (*level < '1' || *level > '9') return std::nullopt;  // not a block-size digit
    f.attrs["block_size"] = dec((*level - '0') * 100000) ;
    f.attrs["level"] = dec(*level - '0');

    const bool block = span.matches_at(
        start + 4, std::span<const std::uint8_t>(kBlockMagic.data(), kBlockMagic.size()));
    const bool eos = span.matches_at(
        start + 4, std::span<const std::uint8_t>(kEosMagic.data(), kEosMagic.size()));
    if (!block && !eos) {
        // Three letters and a digit are not evidence on their own, and "BZh1"
        // through "BZh9" occur in ordinary text.
        return std::nullopt;
    }
    f.attrs["empty"] = eos ? "true" : "false";
    f.confidence = Confidence::Structural;

    if (const std::uint64_t n =
            compressed_stream_length(f, span, start, ::omnitrace::compress::Codec::Bzip2, sig);
        n != 0) {
        f.size = n;
        f.confidence = Confidence::Consistent;
    }
    f.evidence = "level " + dec(*level - '0') + " (" + dec((*level - '0') * 100) + " kB blocks)" +
                 (eos ? ", empty stream" : "");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("bzip2", validate_bzip2);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(bzip2)
