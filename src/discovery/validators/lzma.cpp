// lzma.cpp — LZMA-alone (.lzma) stream validator.
//
// 13-byte header: 0 properties, 1 dictionary size u32 LE, 5 uncompressed size
// u64 LE (all-ones when the encoder did not know it, in which case the stream
// carries an end marker instead).
//
// The properties byte packs three numbers: `lc + lp * 9 + pb * 45`, so it is
// below 225 and each of lc (0..8), lp (0..4) and pb (0..4) is in range. That
// is the whole of the format's self-description -- there is no magic. The
// signatures therefore key on a specific properties byte followed by the two
// zero bytes a dictionary size that is a multiple of 64 KiB always has, and
// the real check is the decode probe: a stream that runs to its end is a
// stream, and one that does not is two coincidental bytes.
//
// Reference: xz-utils `doc/lzma-file-format.txt`.
#include <bit>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kHeaderSize = 13;
constexpr std::uint8_t kMaxProps = 225;  // 8 + 4*9 + 4*45 + 1
constexpr std::uint64_t kUnknownSize = UINT64_MAX;
// A dictionary below 4 KiB or above 1.5 GiB is not something an encoder emits.
constexpr std::uint32_t kMinDict = 4096;
constexpr std::uint32_t kMaxDict = 1536U << 20;

// The format's own portability rule: "only sizes of 2^n and 2^n + 2^(n-1)
// should be used" (xz doc/lzma-file-format.txt). Any 32-bit value is legal in
// principle, but nothing that writes .lzma emits another, and the field is
// otherwise four bytes of whatever happened to be there. Every real stream in
// the corpus is 2^n; every dictionary that is neither belonged to a false
// positive.
bool plausible_dict(std::uint32_t d) {
    if (d == 0) return false;
    if (std::has_single_bit(d)) return true;  // 2^n
    const std::uint32_t high = std::bit_floor(d);
    return d == high + (high >> 1);  // 2^n + 2^(n-1)
}

std::string attr_or_empty(const Finding& f, const char* key) {
    const auto it = f.attrs.find(key);
    return it == f.attrs.end() ? std::string("?") : it->second;
}

std::optional<Finding> validate_lzma(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;

    // Every check below rejects rather than downgrading. The validator
    // contract says to prefer rejection when the magic is short and the only
    // discriminator failed (docs/formats/signatures.md), and here there is no
    // magic at all: "5d 00 00" is a properties byte that happens to be the
    // encoder default followed by two zero bytes, and it turns up roughly a
    // hundred times in a 16 MB router image. Reporting those as magic-tier
    // findings would bury the one real stream among them.
    const auto props = span.u8(start);
    const auto dict = span.at<std::uint32_t>(start + 1, Endian::Little);
    const auto usize = span.at<std::uint64_t>(start + 5, Endian::Little);
    if (!props || !dict || !usize) return std::nullopt;  // fewer than 13 bytes
    if (*props >= kMaxProps) return std::nullopt;        // not a properties byte
    if (*dict < kMinDict || *dict > kMaxDict) return std::nullopt;
    if (!plausible_dict(*dict)) return std::nullopt;

    const std::uint64_t cap = extra_u64(sig, "max_payload").value_or(4ULL << 30);
    if (*usize != kUnknownSize && *usize > cap) return std::nullopt;
    // A declared size of zero makes the decode probe below prove nothing: the
    // decoder consumes the header and its five priming bytes, produces the
    // zero bytes it was promised, and reports success. Any 18 bytes that pass
    // the cheap screens above would do the same. No encoder writes it either
    // -- an empty file compressed with `lzma` gets the all-ones "unknown"
    // size, not 0 -- so this is the shape of a false positive, and it was 16
    // of the 17 the corpus produced.
    if (*usize == 0) return std::nullopt;

    // The first byte of the range-coded data is always zero: the decoder reads
    // five bytes to prime itself and the encoder writes the first as padding.
    // One byte of screening in front of a probe that has liblzma allocate the
    // declared dictionary before it can fail, so ~255 of every 256 false
    // positives never reach it.
    const auto first = span.u8(start + kHeaderSize);
    if (!first || *first != 0) return std::nullopt;

    // With nothing else to go on, the decode is the evidence: a stream that
    // runs to its end is a stream. A real but truncated .lzma is therefore
    // missed, which is the price of a format with no magic.
    const std::uint64_t n =
        compressed_stream_length(f, span, start, ::omnitrace::compress::Codec::Lzma, sig);
    if (n == 0) return std::nullopt;

    const std::uint8_t lc = *props % 9;
    const std::uint8_t lp = (*props / 9) % 5;
    const std::uint8_t pb = (*props / 9) / 5;
    f.attrs["lc"] = dec(lc);
    f.attrs["lp"] = dec(lp);
    f.attrs["pb"] = dec(pb);
    f.attrs["dict_size"] = dec(*dict);
    f.attrs["uncompressed_size"] = *usize == kUnknownSize ? "unknown" : dec(*usize);
    f.size = n;
    f.confidence = Confidence::Consistent;
    f.evidence = "lc" + dec(lc) + " lp" + dec(lp) + " pb" + dec(pb) + ", dictionary " + dec(*dict) +
                 " bytes, decodes to " + attr_or_empty(f, "payload_bytes") + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("lzma", validate_lzma);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(lzma)
