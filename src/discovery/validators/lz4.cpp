// lz4.cpp — LZ4 frame descriptor validator.
//
// 0 04 22 4D 18, 4 FLG (bits 7-6 version = 01, bit 5 block independence,
// bit 4 block checksum, bit 3 content size present, bit 2 content checksum,
// bit 1 reserved 0, bit 0 dict id present), 5 BD (bits 6-4 block max size
// 4..7, other bits 0), then optional u64 content size and u32 dict id, then HC.
// Reference: LZ4 Frame Format Description v1.6.x
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::optional<Finding> validate_lz4(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    const auto flg = span.u8(start + 4);
    const auto bd = span.u8(start + 5);
    if (!bd) {
        diag(f, Severity::Warning, "lz4-truncated-header",
             "fewer than 6 bytes available for the frame descriptor");
        return f;
    }
    const unsigned version = (*flg >> 6) & 0x3;
    const unsigned bmax = (*bd >> 4) & 0x7;
    if (version != 1 || (*flg & 0x02) != 0 || (*bd & 0x8F) != 0 || bmax < 4) {
        diag(f, Severity::Warning, "lz4-bad-frame-descriptor",
             "FLG/BD bytes " + hex_fixed(*flg, 2) + "/" + hex_fixed(*bd, 2) + " are not valid");
        return f;
    }
    f.confidence = Confidence::Structural;
    static const char* sizes[] = {"64KiB", "256KiB", "1MiB", "4MiB"};
    f.attrs["block_max_size"] = sizes[bmax - 4];
    f.attrs["block_independence"] = (*flg & 0x20) ? "true" : "false";
    f.attrs["block_checksum"] = (*flg & 0x10) ? "true" : "false";
    f.attrs["content_checksum"] = (*flg & 0x04) ? "true" : "false";
    std::uint64_t pos = start + 6;
    if ((*flg & 0x08) != 0) {
        if (const auto cs = span.at<std::uint64_t>(pos, Endian::Little))
            f.attrs["content_size"] = dec(*cs);
        pos += 8;
    }
    if ((*flg & 0x01) != 0) {
        if (const auto id = span.at<std::uint32_t>(pos, Endian::Little))
            f.attrs["dictionary_id"] = hex_fixed(*id, 8);
        pos += 4;
    }
    f.attrs["header_len"] = dec(pos + 1 - start);
    // The frame descriptor says nothing about where the frame ends, so the
    // decoder is asked. It stops after the last frame it accepts, which is
    // exactly what the reader will do with the same bytes.
    if (const std::uint64_t n =
            compressed_stream_length(f, span, start, ::omnitrace::compress::Codec::Lz4, sig);
        n != 0) {
        f.size = n;
        f.confidence = Confidence::Consistent;
    }
    f.evidence = "frame descriptor valid, block max " + f.attrs["block_max_size"];
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("lz4", validate_lz4);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(lz4)
