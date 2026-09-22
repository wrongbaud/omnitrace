// SuperReader.h — Android logical partitions (super) as a container.
#pragma once
#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Lp.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// Emits each logical partition of an Android `super` image as one entry,
/// named as the metadata names it (`system_a`, `vendor_a`, ...) and assembled
/// from its extents in order.
///
/// The map is parsed by `omnitrace::lp` (core/Lp.h), which the `android_super`
/// validator also uses, so neither owns the parse. `open()` insists on the
/// same thing the validator does -- a matching SHA-256 over the tables --
/// because a reader more permissive than its validator turns a magic-tier
/// guess into bytes on disk.
///
/// Each entry is the concatenation of its extents: a `linear` extent is bytes
/// read through the Span, and a `zero` extent is that many zero bytes, written
/// out so the entry is the image the device would see. Every extracted
/// partition is then re-scanned by `analyze`, which is how the ext4 inside one
/// is found and walked without this reader knowing anything about ext4.
class SuperReader final : public ContainerReader {
   public:
    std::string format() const override { return "android-super"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    Span span_;
    lp::Metadata meta_;
    bool opened_ = false;
};

}  // namespace omnitrace::container
