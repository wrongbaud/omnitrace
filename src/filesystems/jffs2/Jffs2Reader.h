// Jffs2Reader.h — JFFS2 filesystem reader with full version history.
//
// Reads a JFFS2 partition (little- or big-endian) entirely through Span:
// scans every node, rebuilds the live tree the way a mount would show it and,
// with WalkOptions::history, also emits every older version of every file
// and every inode that no longer has a directory entry. Regular file data is
// streamed to the Sink fragment by fragment; nothing larger than one
// decompressed node (one page for kernel-written images) is held in memory.
// See docs/formats/jffs2.md for the reconstruction semantics, the history
// model, the diagnostics this reader emits and its known gaps.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class Jffs2Reader final : public FilesystemReader {
   public:
    Jffs2Reader();
    ~Jffs2Reader() override;
    Jffs2Reader(const Jffs2Reader&) = delete;
    Jffs2Reader& operator=(const Jffs2Reader&) = delete;

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
void omnitrace_fs_anchor_jffs2();
}  // namespace detail

}  // namespace omnitrace::fs
