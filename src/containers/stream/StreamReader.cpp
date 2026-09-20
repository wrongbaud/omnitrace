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

}  // namespace

StreamReader::StreamReader(std::string format, compress::Codec codec,
                           std::vector<std::uint8_t> magic)
    : format_(std::move(format)), codec_(codec), magic_(std::move(magic)) {}

Status StreamReader::open(const Span& span) {
    if (span.empty()) return Status::fail("container-empty: no bytes at the container's start");
    if (!span.matches_at(0, std::span<const std::uint8_t>(magic_.data(), magic_.size())))
        return Status::fail("container-bad-magic: no " + format_ + " magic at offset 0");
    span_ = span;
    consumed_ = 0;
    produced_ = 0;
    truncated_ = false;
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

    std::vector<std::uint8_t> payload;
    std::uint64_t consumed = 0;
    const Status st =
        compress::decompress_stream(codec_, *mapped, payload, payload_cap(opts), consumed);
    consumed_ = consumed;
    produced_ = payload.size();

    if (!st) {
        // A capped stream is a truncated payload, not a failed walk: what was
        // decoded before the cap is real evidence and is still emitted. Every
        // other decode error means there is no payload to emit.
        if (st.error != "decompress-cap") {
            out.diagnostics.push_back({Severity::Error, kCodeDecompressFailed,
                                       format_ + " stream did not decode (" + st.error +
                                           "); no payload emitted"});
            return Status::fail(st.error);
        }
        truncated_ = true;
        out.truncated = true;
        out.diagnostics.push_back({Severity::Warning, kCodeLimitFileBytes,
                                   "the " + format_ + " payload exceeds max_file_bytes (" +
                                       std::to_string(payload_cap(opts)) + "); data cut there"});
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

}  // namespace

OMNITRACE_REGISTER_CONTAINER("gzip", GzipReader);
OMNITRACE_REGISTER_CONTAINER("xz", XzReader);

namespace detail {
void omnitrace_container_anchor_stream() {}
}  // namespace detail

}  // namespace omnitrace::container
