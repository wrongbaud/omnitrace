// SevenZipReader.h — 7z archives. See the .cpp for the layout.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/SevenZip.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// A 7z archive. Unlike tar or zip, a file here does not own its bytes: the
/// archive holds **folders**, each a coder chain producing one output stream
/// that is then cut into one substream per file. A folder has to be decoded
/// whole to get at any file in it, which is what "solid" means.
///
/// Every substream carries a CRC-32, so the reader can say whether what it
/// produced is what was archived, the way `LzopReader` does.
class SevenZipReader final : public ContainerReader {
   public:
    std::string format() const override { return "7z"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    Span span_;
    bool opened_ = false;
    sevenzip::Archive archive_;
    std::uint64_t bad_crcs_ = 0, skipped_folders_ = 0;
};

}  // namespace omnitrace::container
