// Yaffs2Reader.h — YAFFS2 filesystem reader with version history.
//
// Reads a YAFFS2 image through Span: the chunk grid (omnitrace::yaffs,
// include/omnitrace/core/Yaffs.h), the object headers that describe every
// file, and the data chunks that hold their contents. File data is streamed
// chunk by chunk, so nothing larger than one page is held at a time.
//
// YAFFS2 never overwrites: a change is a new chunk with a higher sequence
// number, and the old one stays on the flash until its block is erased. With
// WalkOptions::history the reader emits those earlier states too, along with
// every object the filesystem marked deleted or unlinked -- which it does by
// writing a header whose parent is one of the two ids reserved for it, so
// the file's data is still exactly where it was.
//
// See docs/formats/yaffs2.md.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class Yaffs2Reader final : public FilesystemReader {
   public:
    Yaffs2Reader();
    ~Yaffs2Reader() override;
    Yaffs2Reader(const Yaffs2Reader&) = delete;
    Yaffs2Reader& operator=(const Yaffs2Reader&) = delete;

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
void omnitrace_fs_anchor_yaffs2();
}  // namespace detail

}  // namespace omnitrace::fs
