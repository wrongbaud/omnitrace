// QnxIfsReader.h — QNX IFS (mkifs image filesystem) reader.
//
// Reads an IFS from its startup header: parses the startup header, locates
// the image filesystem after the startup code (decompressing it into a
// bounded in-memory image when flags1 says ucl, lzo, lz4 or zlib), then walks
// the directory in stored order and emits every file, directory, symlink and
// device with the metadata mkifs recorded. Everything is read through Span;
// file data is streamed to the Sink one chunk at a time. An IFS is immutable,
// so there is no history: `WalkOptions::history` is accepted and ignored.
// See docs/formats/qnx-ifs.md for the layout, the attrs, the diagnostics and
// the known gaps.
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class QnxIfsReader final : public FilesystemReader {
   public:
    QnxIfsReader();
    ~QnxIfsReader() override;
    QnxIfsReader(const QnxIfsReader&) = delete;
    QnxIfsReader& operator=(const QnxIfsReader&) = delete;

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
void omnitrace_fs_anchor_qnxifs();
}  // namespace detail

}  // namespace omnitrace::fs
