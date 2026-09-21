// CramfsReader.h — cramfs, the compressed ROM filesystem. See the .cpp.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

/// cramfs (`Compressed ROMFS`): a read-only filesystem of packed 12-byte
/// inodes and zlib-compressed 4 KiB blocks, in either byte order. Directories
/// are runs of inodes laid out contiguously rather than a table, so one is
/// walked by reading `size` bytes of consecutive inode-plus-name records.
///
/// The inode packs mode, uid, size, gid, name length and a data offset into
/// three 32-bit words using C bitfields, so the bit order flips with the
/// image's endianness, not just the byte order.
class CramfsReader final : public FilesystemReader {
   public:
    CramfsReader();
    ~CramfsReader() override;
    std::string format() const override;
    Status open(const Span& span) override;
    FilesystemInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace detail {
void omnitrace_fs_anchor_cramfs();
}

}  // namespace omnitrace::fs
