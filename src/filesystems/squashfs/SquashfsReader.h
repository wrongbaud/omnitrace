// SquashfsReader.h — SquashFS v4 filesystem reader.
//
// Reads a SquashFS 4.x image (little- or big-endian, standard or vendor
// magic) entirely through Span and emits every entry into a Sink. Regular file
// data is streamed block by block; nothing larger than one decompressed block
// (at most the superblock's block_size, or 8 KiB for metadata) is ever held
// in memory. See docs/formats/squashfs.md for the on-disk layout, the
// diagnostics this reader emits and its known gaps.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class SquashfsReader final : public FilesystemReader {
   public:
    SquashfsReader();
    ~SquashfsReader() override;
    SquashfsReader(const SquashfsReader&) = delete;
    SquashfsReader& operator=(const SquashfsReader&) = delete;

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
void omnitrace_fs_anchor_squashfs();
}  // namespace detail

}  // namespace omnitrace::fs
