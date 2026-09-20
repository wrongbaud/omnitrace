// StreamReader.h — the single-payload compressed wrappers: gzip and xz.
//
// A gzip or xz stream is a container with exactly one member. The reader
// decodes it into memory, emits it as one entry named "payload", and reports
// the input length the stream actually used so `analyze` can give the
// Container node a real extent (the validators cannot: a deflate header says
// nothing about where the stream ends).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// One compressed stream holding one payload. `format()` is the format id the
/// signature uses (`gzip`, `xz`); the codec is fixed at construction.
///
/// `open()` checks the magic only, so it is cheap; the decode happens in
/// `walk()`, capped by `WalkOptions::limits.max_file_bytes`. `info().size` is
/// 0 until `walk()` has run, because the extent is a property of the decode.
/// Subclassed once per concrete format to fix the codec and the magic.
class StreamReader : public ContainerReader {
   public:
    /// `format` is the format id, `codec` the decoder, `magic` the bytes
    /// `open()` requires at offset 0.
    StreamReader(std::string format, compress::Codec codec, std::vector<std::uint8_t> magic);

    std::string format() const override { return format_; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    std::string format_;
    compress::Codec codec_;
    std::vector<std::uint8_t> magic_;
    Span span_;
    std::uint64_t consumed_ = 0;   // input bytes the stream used (0 before walk)
    std::uint64_t produced_ = 0;   // payload bytes
    bool truncated_ = false;       // a limit or a short stream cut the payload
};

}  // namespace omnitrace::container
