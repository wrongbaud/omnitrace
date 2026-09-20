// android_sparse.cpp — Android sparse image validator.
//
// 28-byte little-endian file header: 0 magic u32 0xED26FF3A, so the bytes on
// disk are 3a ff 26 ed; 4 major u16 (1),
// 6 minor u16 (0), 8 file_hdr_sz u16 (28), 10 chunk_hdr_sz u16 (12),
// 12 blk_sz u32 (multiple of 4), 16 total_blks, 20 total_chunks, 24 checksum.
// Chunk header: 0 type u16 (CAC1 raw, CAC2 fill, CAC3 don't-care, CAC4 crc32),
// 2 reserved, 4 chunk_sz u32 (blocks), 8 total_sz u32 (bytes incl. header).
// Reference: AOSP system/core/libsparse/sparse_format.h
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::optional<Finding> validate_sparse(const Span& span, std::uint64_t start,
                                       const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const Endian e = Endian::Little;
    Finding f = make_finding(sig, start, Confidence::Magic);
    const auto major = span.at<std::uint16_t>(start + 4, e);
    const auto minor = span.at<std::uint16_t>(start + 6, e);
    const auto file_hdr = span.at<std::uint16_t>(start + 8, e);
    const auto chunk_hdr = span.at<std::uint16_t>(start + 10, e);
    const auto blk_sz = span.at<std::uint32_t>(start + 12, e);
    const auto total_blks = span.at<std::uint32_t>(start + 16, e);
    const auto total_chunks = span.at<std::uint32_t>(start + 20, e);
    const auto checksum = span.at<std::uint32_t>(start + 24, e);
    if (!checksum) {
        diag(f, Severity::Warning, "sparse-truncated-header",
             "fewer than 28 bytes available for the file header");
        return f;
    }
    if (*major != 1 || *minor != 0) {
        diag(f, Severity::Warning, "sparse-unknown-version",
             "version " + dec(*major) + "." + dec(*minor) + " is not 1.0");
        return f;
    }
    if (*file_hdr != 28 || *chunk_hdr != 12 || *blk_sz == 0 || (*blk_sz % 4) != 0) {
        diag(f, Severity::Warning, "sparse-bad-header", "header sizes or block size out of range");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["block_size"] = dec(*blk_sz);
    f.attrs["total_blocks"] = dec(*total_blks);
    f.attrs["total_chunks"] = dec(*total_chunks);
    f.attrs["output_size"] = dec(static_cast<std::uint64_t>(*total_blks) * *blk_sz);
    f.attrs["image_checksum"] = hex_fixed(*checksum, 8);

    // Walk the chunk list: each chunk advances at least 12 bytes, so the walk
    // is bounded by the Span even for a hostile total_chunks.
    std::uint64_t pos = start + 28;
    std::uint64_t blocks = 0, raw = 0, fill = 0, dont_care = 0, crc = 0;
    bool consistent = true;
    std::uint32_t i = 0;
    for (; i < *total_chunks; ++i) {
        const auto type = span.at<std::uint16_t>(pos, e);
        const auto chunk_sz = span.at<std::uint32_t>(pos + 4, e);
        const auto total_sz = span.at<std::uint32_t>(pos + 8, e);
        if (!total_sz) {
            diag(f, Severity::Warning, "sparse-truncated",
                 "chunk " + dec(i) + " header is past the end of the data");
            consistent = false;
            break;
        }
        const std::uint64_t data = static_cast<std::uint64_t>(*chunk_sz) * *blk_sz;
        std::uint64_t expect = 0;
        switch (*type) {
            case 0xCAC1:
                expect = 12 + data;
                ++raw;
                break;
            case 0xCAC2:
                expect = 16;
                ++fill;
                break;
            case 0xCAC3:
                expect = 12;
                ++dont_care;
                break;
            case 0xCAC4:
                expect = 16;
                ++crc;
                break;
            default:
                diag(f, Severity::Warning, "sparse-bad-chunk-type",
                     "chunk " + dec(i) + " has type " + hex_fixed(*type, 4));
                consistent = false;
                break;
        }
        if (!consistent) break;
        if (*total_sz != expect) {
            diag(f, Severity::Warning, "sparse-chunk-size-mismatch",
                 "chunk " + dec(i) + " total_sz " + dec(*total_sz) + " != expected " + dec(expect));
            consistent = false;
            break;
        }
        if (*total_sz > remaining(span, pos)) {
            diag(f, Severity::Warning, "sparse-truncated",
                 "chunk " + dec(i) + " extends past the end of the data");
            consistent = false;
            pos = span.size();
            break;
        }
        blocks += *chunk_sz;
        pos += *total_sz;
    }
    f.size = pos - start;
    f.attrs["raw_chunks"] = dec(raw);
    f.attrs["fill_chunks"] = dec(fill);
    f.attrs["dont_care_chunks"] = dec(dont_care);
    f.attrs["crc_chunks"] = dec(crc);
    f.attrs["chunks_walked"] = dec(i);
    if (consistent && blocks != *total_blks) {
        diag(f, Severity::Warning, "sparse-block-count-mismatch",
             "chunks cover " + dec(blocks) + " blocks but header says " + dec(*total_blks));
        consistent = false;
    }
    if (consistent) f.confidence = Confidence::Consistent;
    f.evidence = dec(i) + " chunks, " + dec(blocks) + " blocks of " + dec(*blk_sz);
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("android-sparse", validate_sparse);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(android_sparse)
