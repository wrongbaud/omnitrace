// StreamReader.cpp — gzip and xz, the single-payload wrappers. See the header.
//
// Layering: the reader never touches the host filesystem (docs/ARCHITECTURE.md
// rule 2). It reads through the Span and writes through the Sink, exactly like
// a FilesystemReader, so the caller decides where the payload lands.
#include "StreamReader.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

// The payload is held in memory in one piece, so the entry cap is also the
// allocation bound. max_file_bytes is the right knob: the payload becomes one
// file, and the CLI exposes it as --max-file-bytes.
std::uint64_t payload_cap(const WalkOptions& opts) {
    return opts.limits.max_file_bytes;
}

// gzip and xz both carry the original name in the header on some producers,
// but neither is required and a name from evidence must never steer where the
// Sink writes. The entry is always "payload" (Container.h) and the original
// name, when present, is metadata only.
constexpr const char* kPayloadName = "payload";

// Stable codes. They are layer-scoped rather than "<fmt>-...", like the
// sink-* and analyze-* families: one reader serves every stream format, so a
// per-format code would have to be built at run time and
// scripts/gen_docs.py could not catalogue it. The message names the format.
constexpr const char* kCodeDecompressFailed = "container-decompress-failed";
constexpr const char* kCodeLimitFileBytes = "container-limit-file-bytes";
constexpr const char* kCodeSinkError = "container-sink-error";
constexpr const char* kCodeChecksumMismatch = "container-checksum-mismatch";

}  // namespace

StreamReader::StreamReader(std::string format, compress::Codec codec,
                           std::vector<std::uint8_t> magic)
    : format_(std::move(format)), codec_(codec), magic_(std::move(magic)) {}

Status StreamReader::check_header(const Span& span) const {
    if (!span.matches_at(0, std::span<const std::uint8_t>(magic_.data(), magic_.size())))
        return Status::fail("container-bad-magic: no " + format_ + " magic at offset 0");
    return Status::success();
}

Status StreamReader::open(const Span& span) {
    if (span.empty()) return Status::fail("container-empty: no bytes at the container's start");
    if (const Status st = check_header(span); !st) return st;
    span_ = span;
    consumed_ = 0;
    produced_ = 0;
    truncated_ = false;
    check_kind_.clear();
    return Status::success();
}

ContainerInfo StreamReader::info() const {
    ContainerInfo i;
    i.format = format_;
    i.compression = compress::codec_name(codec_);
    // Only a completed walk knows where the stream ended; before that the
    // extent is unknown (0) and the caller leaves the node's length alone.
    i.size = consumed_;
    if (consumed_ != 0) {
        i.attrs["stream_bytes"] = std::to_string(consumed_);
        i.attrs["payload_bytes"] = std::to_string(produced_);
    }
    if (!check_kind_.empty()) i.attrs["checksum_kind"] = check_kind_;
    return i;
}

Status StreamReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (span_.empty()) return Status::fail("container-not-open: walk before a successful open");

    // The decoder needs the compressed bytes contiguously. A mapped Source
    // gives them for free; a derived view (word swap) has to be copied, and
    // the copy is bounded by the Span the validator sized.
    const std::size_t avail = static_cast<std::size_t>(
        std::min<std::uint64_t>(span_.size(), std::numeric_limits<std::size_t>::max()));
    std::optional<std::span<const std::uint8_t>> mapped = span_.view(0, avail);
    std::optional<std::vector<std::uint8_t>> copied;
    if (!mapped) {
        copied = span_.bytes(0, avail);
        if (!copied)
            return Status::fail("container-unreadable: the container's bytes could not be read");
        mapped = std::span<const std::uint8_t>(copied->data(), copied->size());
    }

    // What the stream promises about its own payload. Read from the header
    // before the decode, because a failed decode may not reach the trailer.
    check_kind_ = compress::stream_check(codec_, *mapped);

    std::vector<std::uint8_t> payload;
    std::uint64_t consumed = 0;
    const Status st =
        compress::decompress_stream(codec_, *mapped, payload, payload_cap(opts), consumed);
    consumed_ = consumed;
    produced_ = payload.size();

    bool mismatch = false;
    if (!st) {
        // A capped stream is a truncated payload, not a failed walk: what was
        // decoded before the cap is real evidence and is still emitted. So is
        // a payload that decoded whole and then disagreed with its own
        // checksum -- those bytes are all there, they are just not the bytes
        // that were compressed, and dropping them would hide the damage.
        // Every other decode error means there is no payload to emit.
        if (st.error == "decompress-checksum-mismatch") {
            mismatch = true;
            const std::string kind = check_kind_.empty() ? "checksum" : check_kind_;
            out.diagnostics.push_back(
                {Severity::Error, kCodeChecksumMismatch,
                 "the " + format_ + " payload does not match the " + kind +
                     " the stream records over it; emitted anyway, treat it as damaged"});
        } else if (st.error != "decompress-cap") {
            out.diagnostics.push_back(
                {Severity::Error, kCodeDecompressFailed,
                 format_ + " stream did not decode (" + st.error + "); no payload emitted"});
            return Status::fail(st.error);
        } else {
            truncated_ = true;
            out.truncated = true;
            out.diagnostics.push_back({Severity::Warning, kCodeLimitFileBytes,
                                       "the " + format_ + " payload exceeds max_file_bytes (" +
                                           std::to_string(payload_cap(opts)) +
                                           "); data cut there"});
        }
    }

    FileMeta meta;
    meta.path = kPayloadName;
    meta.kind = EntryKind::Regular;
    meta.mode = 0644;
    meta.size = payload.size();

    EntryResult r;
    Status emit = Status::success();
    if (opts.extract_data) {
        emit = sink.file(meta, std::span<const std::uint8_t>(payload.data(), payload.size()), r);
    } else {
        emit = sink.begin_file(meta);
        if (emit) emit = sink.end_file(r);
    }
    if (!emit) {
        out.diagnostics.push_back({Severity::Warning, kCodeSinkError,
                                   "'" + std::string(kPayloadName) + "' (" + format_ +
                                       "): " + emit.error});
        return Status::success();  // nothing recovered, but the walk itself held
    }
    if (truncated_) r.truncated = true;
    // What the payload is worth: the decoders verify the stream's own check
    // as they go, so a decode that reached the end is a check that passed.
    // A format that records none -- raw deflate, LZMA-alone, `xz --check=none`
    // -- gets "none", the same third answer LzopReader gives for `lzop -F`.
    // A payload cut short by the cap was never checked against anything.
    r.meta.extra["checksum"] = mismatch                                         ? "mismatch"
                               : truncated_                                     ? "unchecked"
                               : (check_kind_.empty() || check_kind_ == "none") ? "none"
                                                                                : "ok";

    ++out.entries;
    ++out.files;
    out.bytes += payload.size();
    out.entries_out.push_back(std::move(r));
    return Status::success();
}

namespace {

// gzip: 1f 8b 08 (deflate is the only method ever produced).
class GzipReader final : public StreamReader {
   public:
    GzipReader() : StreamReader("gzip", compress::Codec::Gzip, {0x1F, 0x8B, 0x08}) {}
};

// xz: fd 37 7a 58 5a 00.
class XzReader final : public StreamReader {
   public:
    XzReader() : StreamReader("xz", compress::Codec::Xz, {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) {}
};

// LZMA-alone has no magic: the 13-byte header is a properties byte, a
// dictionary size and an uncompressed size. The properties byte packs
// lc + lp*9 + pb*45, so anything from 225 up is not one
// (docs/formats/compressed-streams.md).
class LzmaReader final : public StreamReader {
   public:
    LzmaReader() : StreamReader("lzma", compress::Codec::Lzma, {}) {}

   protected:
    Status check_header(const Span& span) const override {
        const auto props = span.u8(0);
        if (!props) return Status::fail("container-empty: fewer than 13 lzma header bytes");
        if (*props >= 225)
            return Status::fail("container-bad-magic: lzma properties byte " +
                                std::to_string(*props) + " is out of range");
        return Status::success();
    }
};

// bzip2: "BZh" plus a block-size digit, which the reader does not pin down
// (the validator has already checked it and the 48-bit block magic behind it).
class Bzip2Reader final : public StreamReader {
   public:
    Bzip2Reader() : StreamReader("bzip2", compress::Codec::Bzip2, {'B', 'Z', 'h'}) {}
};

// lz4 frame: 04 22 4d 18. The raw-block and legacy forms have no frame
// header to recognise, so only the frame format gets a reader.
class Lz4Reader final : public StreamReader {
   public:
    Lz4Reader() : StreamReader("lz4", compress::Codec::Lz4, {0x04, 0x22, 0x4D, 0x18}) {}
};

// zstd frame: 28 b5 2f fd.
class ZstdReader final : public StreamReader {
   public:
    ZstdReader() : StreamReader("zstd", compress::Codec::Zstd, {0x28, 0xB5, 0x2F, 0xFD}) {}
};

}  // namespace

OMNITRACE_REGISTER_CONTAINER("bzip2", Bzip2Reader);
OMNITRACE_REGISTER_CONTAINER("lz4", Lz4Reader);
OMNITRACE_REGISTER_CONTAINER("zstd", ZstdReader);
OMNITRACE_REGISTER_CONTAINER("gzip", GzipReader);
OMNITRACE_REGISTER_CONTAINER("xz", XzReader);
OMNITRACE_REGISTER_CONTAINER("lzma", LzmaReader);

namespace detail {
void omnitrace_container_anchor_stream() {}
}  // namespace detail

}  // namespace omnitrace::container
