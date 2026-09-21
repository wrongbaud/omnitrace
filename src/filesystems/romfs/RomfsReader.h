// RomfsReader.h — romfs, the uncompressed read-only filesystem. See the .cpp.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

/// romfs (`-rom1fs-`): a big-endian, uncompressed, read-only filesystem whose
/// directories are singly linked lists of 16-byte-aligned headers. There is no
/// inode table, no free space and no timestamps — a header, its name and its
/// data sit together, and the next header follows.
///
/// Every directory begins with `.` and `..` as hard links, which the walk
/// skips: following them is how a reader ends up in a loop.
class RomfsReader final : public FilesystemReader {
   public:
    RomfsReader();
    ~RomfsReader() override;
    std::string format() const override;
    Status open(const Span& span) override;
    FilesystemInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace detail {
void omnitrace_fs_anchor_romfs();
}

}  // namespace omnitrace::fs
