// UImageReader.h — U-Boot legacy image (uImage). See the .cpp for the layout.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// The U-Boot legacy image wrapper: a 64-byte big-endian header and one
/// payload, emitted as `payload`. The multi-file (`ih_type` 4) and script (6)
/// types carry a table of sizes and become `image0`, `image1`, ...
///
/// The payload is emitted as stored: `ih_comp` says how it is packed, and
/// decompressing it here would duplicate the stream readers, which the
/// analysis pass reaches anyway by re-scanning what this writes.
class UImageReader final : public ContainerReader {
   public:
    std::string format() const override { return "uimage"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// A multi-file table longer than this is treated as corrupt: real images
    /// hold a kernel, a ramdisk and a device tree, not thousands of entries.
    static constexpr std::size_t kMaxMultiEntries = 4096;

    std::vector<std::uint64_t> multi_sizes(WalkResult& out) const;

    Span span_;
    bool opened_ = false;
    std::uint32_t data_size_ = 0;
    std::uint8_t type_ = 0;
    std::uint8_t comp_ = 0;
    std::string name_;
};

}  // namespace omnitrace::container
