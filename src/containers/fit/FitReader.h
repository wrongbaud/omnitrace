// FitReader.h — U-Boot FIT image (flattened image tree). See the .cpp.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Fdt.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// A U-Boot FIT: a flattened device tree whose `/images` node names the
/// payloads. Each subnode of `/images` becomes one entry, named after the
/// node (`kernel`, `ramdisk-1`, `fdt@1`, ...).
///
/// Payloads are emitted as stored. `compression` says how each one is packed,
/// and decompressing here would duplicate the stream readers, which the
/// analysis pass reaches anyway by re-scanning what this writes.
class FitReader final : public ContainerReader {
   public:
    std::string format() const override { return "fit"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// Where one image's payload lives, once the two encodings are resolved.
    struct Image {
        std::string name;       ///< Entry path: the node name, made host-safe.
        std::uint64_t off = 0;  ///< Span-relative first byte of the payload.
        std::uint64_t size = 0;
        bool external = false;  ///< Outside the tree (data-position/data-offset).
        bool present = false;   ///< The payload's bytes are inside the Span.
        std::uint32_t node = 0;  ///< Index into `tree_.nodes`, for the metadata.
    };

    std::vector<Image> images() const;

    Span span_;
    bool opened_ = false;
    fdt::Header header_{};
    fdt::Tree tree_;
    std::uint32_t images_node_ = 0;
    std::uint64_t consumed_ = 0;
};

}  // namespace omnitrace::container
