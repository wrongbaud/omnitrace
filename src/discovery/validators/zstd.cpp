// zstd.cpp — Zstandard frame header validator.
//
// 0 28 B5 2F FD, 4 frame header descriptor: bits 7-6 FCS field size flag,
// bit 5 single segment, bit 4 unused (0), bit 3 reserved (0), bit 2 content
// checksum, bits 1-0 dictionary id flag. Window descriptor follows unless
// single segment; then dictionary id (0/1/2/4 bytes), then frame content size
// (0/1/2/4/8 bytes; 1 byte only when single segment). Reference: RFC 8878 §3.1.1
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::optional<Finding> validate_zstd(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    const auto fhd = span.u8(start + 4);
    if (!fhd) {
        diag(f, Severity::Warning, "zstd-truncated-header",
             "fewer than 5 bytes available for the frame header");
        return f;
    }
    if ((*fhd & 0x18) != 0) {
        diag(f, Severity::Warning, "zstd-bad-frame-header",
             "reserved bits set in the frame header descriptor " + hex_fixed(*fhd, 2));
        return f;
    }
    const unsigned fcs_flag = (*fhd >> 6) & 0x3;
    const bool single = (*fhd & 0x20) != 0;
    const unsigned did_flag = *fhd & 0x3;
    f.confidence = Confidence::Structural;
    f.attrs["content_checksum"] = (*fhd & 0x04) ? "true" : "false";
    f.attrs["single_segment"] = single ? "true" : "false";
    std::uint64_t pos = start + 5;
    if (!single) {
        if (const auto wd = span.u8(pos)) {
            const unsigned exponent = (*wd >> 3) & 0x1F;
            const unsigned mantissa = *wd & 0x7;
            const std::uint64_t base = 1ull << (10 + exponent);
            f.attrs["window_size"] = dec(base + (base / 8) * mantissa);
        }
        pos += 1;
    }
    const unsigned did_len = did_flag == 0 ? 0 : did_flag == 1 ? 1 : did_flag == 2 ? 2 : 4;
    if (did_len == 1) {
        if (const auto v = span.u8(pos)) f.attrs["dictionary_id"] = dec(*v);
    } else if (did_len == 2) {
        if (const auto v = span.at<std::uint16_t>(pos, Endian::Little))
            f.attrs["dictionary_id"] = dec(*v);
    } else if (did_len == 4) {
        if (const auto v = span.at<std::uint32_t>(pos, Endian::Little))
            f.attrs["dictionary_id"] = dec(*v);
    }
    pos += did_len;
    const unsigned fcs_len = fcs_flag == 0   ? (single ? 1u : 0u)
                             : fcs_flag == 1 ? 2u
                             : fcs_flag == 2 ? 4u
                                             : 8u;
    if (fcs_len == 1) {
        if (const auto v = span.u8(pos)) f.attrs["frame_content_size"] = dec(*v);
    } else if (fcs_len == 2) {
        if (const auto v = span.at<std::uint16_t>(pos, Endian::Little))
            f.attrs["frame_content_size"] = dec(*v + 256u);
    } else if (fcs_len == 4) {
        if (const auto v = span.at<std::uint32_t>(pos, Endian::Little))
            f.attrs["frame_content_size"] = dec(*v);
    } else if (fcs_len == 8) {
        if (const auto v = span.at<std::uint64_t>(pos, Endian::Little))
            f.attrs["frame_content_size"] = dec(*v);
    }
    pos += fcs_len;
    f.attrs["header_len"] = dec(pos - start);
    f.evidence = "frame header valid";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("zstd", validate_zstd);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(zstd)
