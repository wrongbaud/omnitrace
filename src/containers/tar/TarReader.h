// TarReader.h — tar archives: ustar, GNU and pax.
#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// A tar archive: 512-byte member headers, each followed by its data padded
/// to 512, ending with two zero blocks. Entries keep their mode, owner,
/// mtime, link target and device numbers.
///
/// Three ways of carrying a path too long for the 100-byte `name` field are
/// handled, because all three turn up in firmware:
///
/// * ustar splits it across `prefix` (155 bytes) and `name`;
/// * GNU writes an `L` member whose data is the next member's name (`K` for
///   its link target);
/// * pax writes an `x` member holding `key=value` records, of which `path`,
///   `linkpath`, `size`, `mtime`, `uid` and `gid` are applied to the member
///   that follows. A `g` member sets the same keys for the rest of the
///   archive.
///
/// Hard links (typeflag `1`) are emitted as symlink-free empty regular files
/// with `nlink` set and the target in `extra["hardlink"]`: the Sink has no
/// hard-link primitive, and the data lives on the member being linked to.
class TarReader final : public ContainerReader {
   public:
    std::string format() const override { return "tar"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// Overrides an `x`/`g`/`L`/`K` member sets for the member after it.
    struct Pending {
        std::string path, linkpath;
        std::optional<std::uint64_t> size;
        std::optional<std::int64_t> mtime;
        std::optional<std::uint32_t> uid, gid;
        bool any() const {
            return !path.empty() || !linkpath.empty() || size || mtime || uid || gid;
        }
        void clear() { *this = Pending{}; }
    };

    /// Parse `len` bytes of pax `key=value` records at `off` into `into`.
    void apply_pax(std::uint64_t off, std::uint64_t len, Pending& into, WalkResult& out) const;

    Span span_;
    bool opened_ = false;
    std::string variant_ = "ustar";
    std::uint64_t entries_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace omnitrace::container
