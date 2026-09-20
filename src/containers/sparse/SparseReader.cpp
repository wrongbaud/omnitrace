// SparseReader.cpp — Android sparse images. See the header.
//
// Field offsets are in src/discovery/validators/android_sparse.cpp, which
// validates and sizes the same structures. This reader repeats the parse,
// because a reader is handed a Span and never a Finding, and then expands the
// chunks into the raw image they describe.
//
// Reference: AOSP system/core/libsparse/sparse_format.h, and `simg2img`,
// whose output this matches byte for byte.
#include "SparseReader.h"

#include <algorithm>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Endian.h"

namespace omnitrace::container {

namespace {

// The value of the __le32 magic field, not the byte order on disk.
constexpr std::uint32_t kMagic = 0xED26FF3AU;
constexpr std::uint64_t kFileHeader = 28;
constexpr std::uint64_t kChunkHeader = 12;

constexpr std::uint16_t kChunkRaw = 0xCAC1;
constexpr std::uint16_t kChunkFill = 0xCAC2;
constexpr std::uint16_t kChunkDontCare = 0xCAC3;
constexpr std::uint16_t kChunkCrc32 = 0xCAC4;

constexpr const char* kCodeBadChunk = "sparse-bad-chunk";
constexpr const char* kCodeTruncated = "container-section-truncated";
constexpr const char* kCodeSinkError = "container-sink-error";

// The entry name. Unlike a wrapper's "payload" this really is an image, and
// naming it so is what makes the nested scan's output readable.
constexpr const char* kImageName = "image";

}  // namespace

Status SparseReader::open(const Span& span) {
    opened_ = false;
    consumed_ = 0;
    produced_ = 0;
    const auto magic = span.at<std::uint32_t>(0, Endian::Little);
    if (!magic || *magic != kMagic)
        return Status::fail("container-bad-magic: no sparse image magic at offset 0");
    const auto file_hdr = span.at<std::uint16_t>(8, Endian::Little);
    const auto chunk_hdr = span.at<std::uint16_t>(10, Endian::Little);
    const auto blk = span.at<std::uint32_t>(12, Endian::Little);
    const auto blocks = span.at<std::uint32_t>(16, Endian::Little);
    const auto chunks = span.at<std::uint32_t>(20, Endian::Little);
    const auto sum = span.at<std::uint32_t>(24, Endian::Little);
    if (!file_hdr || !chunk_hdr || !blk || !blocks || !chunks || !sum)
        return Status::fail("container-empty: fewer than 28 sparse header bytes");
    // The header sizes are fixed by the format; anything else is a variant
    // this reader would mis-walk rather than read.
    if (*file_hdr != kFileHeader || *chunk_hdr != kChunkHeader || *blk == 0 || (*blk % 4) != 0)
        return Status::fail("container-bad-magic: sparse header sizes or block size are not the "
                            "format's");
    block_size_ = *blk;
    total_blocks_ = *blocks;
    total_chunks_ = *chunks;
    checksum_ = *sum;
    span_ = span;
    opened_ = true;
    return Status::success();
}

ContainerInfo SparseReader::info() const {
    ContainerInfo i;
    i.format = "android-sparse";
    i.size = consumed_;
    i.attrs["block_size"] = std::to_string(block_size_);
    i.attrs["total_blocks"] = std::to_string(total_blocks_);
    i.attrs["total_chunks"] = std::to_string(total_chunks_);
    i.attrs["output_size"] =
        std::to_string(static_cast<std::uint64_t>(total_blocks_) * block_size_);
    return i;
}

Status SparseReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    FileMeta meta;
    meta.path = kImageName;
    meta.kind = EntryKind::Regular;
    meta.mode = 0644;
    meta.size = static_cast<std::uint64_t>(total_blocks_) * block_size_;

    EntryResult r;
    if (Status st = sink.begin_file(meta); !st) {
        out.diagnostics.push_back({Severity::Warning, kCodeSinkError,
                                   "'" + std::string(kImageName) + "': " + st.error});
        return Status::success();
    }

    std::vector<std::uint8_t> buf(
        static_cast<std::size_t>(std::min<std::uint64_t>(kCopyChunk, meta.size != 0 ? meta.size
                                                                                    : kCopyChunk)));
    bool stopped = false;
    std::uint64_t pos = kFileHeader;
    std::uint64_t blocks_done = 0;

    // Write `len` bytes of whatever `fill` holds, repeating it. `fill` is
    // either four bytes (a fill chunk), or empty for zeros.
    auto write_pattern = [&](std::uint64_t len, const std::uint8_t* fill) -> bool {
        if (!opts.extract_data) {
            produced_ += len;
            return true;
        }
        std::fill(buf.begin(), buf.end(), static_cast<std::uint8_t>(0));
        if (fill != nullptr) {
            for (std::size_t i = 0; i + 4 <= buf.size(); i += 4) {
                std::copy(fill, fill + 4, buf.begin() + static_cast<std::ptrdiff_t>(i));
            }
        }
        std::uint64_t done = 0;
        while (done < len) {
            const std::size_t n =
                static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
            if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), n)); !st) {
                out.diagnostics.push_back({Severity::Warning, kCodeSinkError,
                                           "'" + std::string(kImageName) + "': " + st.error});
                return false;
            }
            done += n;
            produced_ += n;
        }
        return true;
    };

    // Copy `len` bytes of the image through, streaming.
    auto write_raw = [&](std::uint64_t at, std::uint64_t len) -> bool {
        if (!opts.extract_data) {
            produced_ += len;
            return true;
        }
        std::uint64_t done = 0;
        while (done < len) {
            const std::size_t want =
                static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
            const std::size_t got =
                span_.read(at + done, std::span<std::uint8_t>(buf.data(), want));
            if (got == 0) return false;
            if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), got)); !st) {
                out.diagnostics.push_back({Severity::Warning, kCodeSinkError,
                                           "'" + std::string(kImageName) + "': " + st.error});
                return false;
            }
            done += got;
            produced_ += got;
            if (got < want) return false;
        }
        return true;
    };

    for (std::uint32_t i = 0; i < total_chunks_ && !stopped; ++i) {
        const auto type = span_.at<std::uint16_t>(pos, Endian::Little);
        const auto chunk_blocks = span_.at<std::uint32_t>(pos + 4, Endian::Little);
        const auto total_sz = span_.at<std::uint32_t>(pos + 8, Endian::Little);
        if (!type || !chunk_blocks || !total_sz) {
            out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                       "the image ends inside chunk " + std::to_string(i)});
            out.truncated = true;
            break;
        }
        const std::uint64_t data_at = pos + kChunkHeader;
        const std::uint64_t output = static_cast<std::uint64_t>(*chunk_blocks) * block_size_;

        switch (*type) {
            case kChunkRaw: {
                const std::uint64_t have =
                    span_.size() > data_at ? std::min(output, span_.size() - data_at) : 0;
                if (!write_raw(data_at, have) || have < output) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeTruncated,
                         "chunk " + std::to_string(i) + " claims " + std::to_string(output) +
                             " bytes of raw data but only " + std::to_string(have) +
                             " are present"});
                    out.truncated = true;
                    stopped = true;
                }
                break;
            }
            case kChunkFill: {
                const auto fill = span_.bytes(data_at, 4);
                if (!fill) {
                    out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                               "chunk " + std::to_string(i) +
                                                   " has no fill value"});
                    out.truncated = true;
                    stopped = true;
                    break;
                }
                if (!write_pattern(output, fill->data())) stopped = true;
                break;
            }
            case kChunkDontCare:
                // A hole. simg2img writes zeros, and so does this: the output
                // has to be the right length for anything to read it.
                if (!write_pattern(output, nullptr)) stopped = true;
                break;
            case kChunkCrc32:
                // A checksum over the output so far, carrying no blocks.
                break;
            default:
                out.diagnostics.push_back({Severity::Warning, kCodeBadChunk,
                                           "chunk " + std::to_string(i) + " has type " +
                                               std::to_string(*type) +
                                               ", which is not one of the four defined; the walk "
                                               "stops there"});
                out.truncated = true;
                stopped = true;
                break;
        }
        if (*type != kChunkCrc32) blocks_done += *chunk_blocks;
        if (*total_sz < kChunkHeader || pos + *total_sz <= pos) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadChunk,
                                       "chunk " + std::to_string(i) + " declares a total size of " +
                                           std::to_string(*total_sz) + ", which cannot be walked"});
            out.truncated = true;
            break;
        }
        pos += *total_sz;
        if (pos > span_.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                       "chunk " + std::to_string(i) + " runs past the image"});
            out.truncated = true;
            break;
        }
    }
    consumed_ = std::min(pos, span_.size());

    if (blocks_done != total_blocks_) {
        out.diagnostics.push_back(
            {Severity::Warning, kCodeBadChunk,
             "the chunks cover " + std::to_string(blocks_done) + " blocks but the header says " +
                 std::to_string(total_blocks_) + "; the expanded image is short"});
        out.truncated = true;
    }

    if (Status st = sink.end_file(r); !st) {
        out.diagnostics.push_back({Severity::Warning, kCodeSinkError,
                                   "'" + std::string(kImageName) + "': " + st.error});
        return Status::success();
    }
    if (out.truncated) r.truncated = true;
    count_entry(out, r);
    out.entries_out.push_back(std::move(r));
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("android-sparse", SparseReader);

namespace detail {
void omnitrace_container_anchor_sparse() {}
}  // namespace detail

}  // namespace omnitrace::container
