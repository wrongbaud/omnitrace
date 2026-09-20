// UbifsReader.h — UBIFS filesystem reader.
//
// Reads a UBIFS volume through Span: the superblock and master node, the
// on-flash index (a B-tree of `idx` nodes whose leaves point at the inode,
// directory-entry, data and extended-attribute nodes), and the journal, whose
// buds hold the writes made since the last commit and which a mount would
// replay before showing anything. File data is streamed block by block, so
// nothing larger than one decompressed 4 KiB block is held at a time.
//
// The LEBs must be contiguous, which is what a reassembled UBI volume gives
// (src/containers/ubi/UbiReader.cpp). On raw flash they are not, and a UBIFS
// superblock found there identifies the filesystem but cannot be walked.
// See docs/formats/ubifs.md.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class UbifsReader final : public FilesystemReader {
   public:
    UbifsReader();
    ~UbifsReader() override;
    UbifsReader(const UbifsReader&) = delete;
    UbifsReader& operator=(const UbifsReader&) = delete;

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
void omnitrace_fs_anchor_ubifs();
}  // namespace detail

}  // namespace omnitrace::fs
