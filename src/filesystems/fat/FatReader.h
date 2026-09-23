// FatReader.h — FAT12/FAT16/FAT32. See the .cpp.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

/// FAT12/16/32: the boot partition of a large share of embedded devices, and
/// the format most likely to still hold a deleted file's bytes.
///
/// There is no inode table. A directory is a list of 32-byte entries, each
/// naming a first cluster, and the file's remaining clusters are found by
/// following a chain through the File Allocation Table. Long names are carried
/// in extra entries that sit *before* the one they name, in reverse order.
///
/// Deleting a file here only stamps 0xE5 over the first byte of its name and
/// frees its chain — the start cluster and the size stay in the entry. With
/// `WalkOptions::history` those entries are recovered, contiguously from the
/// start cluster, and labelled with how they were read: the chain is gone, so
/// a fragmented file recovers as the right length of the wrong bytes and says
/// so rather than pretending.
class FatReader final : public FilesystemReader {
   public:
    FatReader();
    ~FatReader() override;
    std::string format() const override;
    Status open(const Span& span) override;
    FilesystemInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace detail {
void omnitrace_fs_anchor_fat();
}

}  // namespace omnitrace::fs
