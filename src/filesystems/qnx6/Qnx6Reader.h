// Qnx6Reader.h — QNX6 (Power-Safe, fs-qnx6) filesystem reader with snapshot
// history.
//
// Reads a QNX6 partition (little- or big-endian) entirely through Span: picks
// the current superblock by serial, walks the inode tree, directories and
// long-name table the way fs-qnx6 does and streams file data to the Sink one
// block at a time. With WalkOptions::history it also walks the previous
// snapshot (the other superblock) and emits every entry that differs from
// the current tree as superseded or deleted, plus inode-table records that no
// live directory entry names any more. See docs/formats/qnx6.md for the
// on-disk layout, the history model, the diagnostics and the known gaps.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class Qnx6Reader final : public FilesystemReader {
   public:
    Qnx6Reader();
    ~Qnx6Reader() override;
    Qnx6Reader(const Qnx6Reader&) = delete;
    Qnx6Reader& operator=(const Qnx6Reader&) = delete;

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
void omnitrace_fs_anchor_qnx6();
}  // namespace detail

}  // namespace omnitrace::fs
