// LzopReader.h — lzop (`.lzo`) files. See the .cpp for the layout.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Lzop.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// An lzop file: one or more members, each a checksummed header and a run of
/// LZO1X blocks. Each member becomes one entry, `payload` when there is only
/// one and `payload0`, `payload1`, ... when there are several; the name the
/// header records is metadata (`original_name`), never the path, because a
/// name out of evidence must not steer where the Sink writes.
///
/// Every block carries a checksum of its uncompressed bytes, so unlike the
/// wrapper formats this reader can say whether what it produced is what was
/// compressed. The entry's `checksum` extra reports it.
class LzopReader final : public ContainerReader {
   public:
    std::string format() const override { return "lzop"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// Members and blocks one file may hold, so a stream that only looks like
    /// one still terminates.
    static constexpr std::uint64_t kMaxMembers = 4096;
    static constexpr std::uint64_t kMaxBlocks = 1u << 20;

    /// Count the members and find where the file ends, by walking the block
    /// headers alone. Cheap enough for open(), which decodes nothing.
    bool survey();

    Span span_;
    bool opened_ = false;
    lzop::Header first_{};
    std::vector<std::uint64_t> members_;  ///< Span offset of each member's magic.
    std::uint64_t consumed_ = 0;
    std::uint64_t blocks_ = 0, payload_bytes_ = 0, bad_checksums_ = 0;
};

}  // namespace omnitrace::container
