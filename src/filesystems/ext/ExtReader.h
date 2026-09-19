// ExtReader.h — native ext2 / ext3 / ext4 filesystem reader.
//
// Reads an ext2, ext3 or ext4 image entirely through Span and emits every
// entry into a Sink. Regular file data is streamed extent by extent (or
// block by block for ext2/ext3 block maps); nothing larger than one data
// block, one inode or one directory block is held in memory at a time. With
// `WalkOptions::history` the reader also surfaces freed inodes and the
// directory-entry remnants ("slack dirents") that still name them. See
// docs/formats/ext.md for the on-disk layout, the diagnostics this reader
// emits, how history is recovered and the known gaps. No external library
// (libtsk, libext2fs) is used.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class ExtReader final : public FilesystemReader {
   public:
    ExtReader();
    ~ExtReader() override;
    ExtReader(const ExtReader&) = delete;
    ExtReader& operator=(const ExtReader&) = delete;

    /// "ext2", "ext3" or "ext4" after a successful open() (the same rule the
    /// discovery validator uses); "ext" before.
    std::string format() const override;
    Status open(const Span& span) override;
    FilesystemInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace detail {
// Force-link anchor so the static registrar survives static linking; see
// src/filesystems/Registry.cpp.
void omnitrace_fs_anchor_ext();
}  // namespace detail

}  // namespace omnitrace::fs
