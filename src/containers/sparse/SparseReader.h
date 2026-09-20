// SparseReader.h — Android sparse images (the `simg` format flashed by
// fastboot).
#pragma once
#include <cstdint>
#include <string>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// An Android sparse image: a header, then chunks that each describe a run of
/// output blocks as raw data, a repeated 4-byte fill, or nothing at all.
///
/// The reader *expands* it, emitting the single entry `image`: the raw
/// filesystem the chunks describe, which is the whole point of the format and
/// the only form anything else can read. A `system.img` is a sparse ext4 and
/// is useless until it is expanded.
///
/// The output is synthesised rather than copied, so it is written to the Sink
/// in 1 MiB pieces and never held whole; a don't-care chunk becomes zeros,
/// which is what `simg2img` writes too. `Limits::max_file_bytes` bounds it,
/// and a multi-gigabyte `system.img` will meet that bound long before memory
/// does.
class SparseReader final : public ContainerReader {
   public:
    std::string format() const override { return "android-sparse"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    Span span_;
    bool opened_ = false;
    std::uint32_t block_size_ = 0;
    std::uint32_t total_blocks_ = 0;
    std::uint32_t total_chunks_ = 0;
    std::uint32_t checksum_ = 0;
    std::uint64_t consumed_ = 0;   // input bytes the chunks used
    std::uint64_t produced_ = 0;   // output bytes written
};

}  // namespace omnitrace::container
