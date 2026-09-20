// ZipReader.h — ZIP archives.
#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// A ZIP archive, read through its **central directory** rather than by
/// walking the local headers.
///
/// The directory is the archive's own index: it holds every member's name,
/// sizes, method and the offset of its local header, and it is what every
/// correct reader uses. Walking local headers instead means trusting sizes
/// that a streaming writer leaves as zero, and means a member removed from the
/// directory but still present in the file would be treated as live. Reading
/// the directory also makes the walk independent of the order members happen
/// to be stored in.
///
/// `open()` finds the end-of-central-directory record by searching back from
/// the end of the Span, which is where the format puts it. ZIP64 archives are
/// followed through their own EOCD record.
///
/// Stored (method 0) members are streamed; deflated (method 8) members are
/// decompressed whole, bounded by `Limits::max_file_bytes`. Any other method
/// is reported and the member is emitted empty rather than dropped.
class ZipReader final : public ContainerReader {
   public:
    std::string format() const override { return "zip"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// One central-directory entry, located but not yet read.
    struct Entry {
        std::string name;
        std::string comment;
        std::uint64_t csize = 0, usize = 0;
        std::uint64_t local_at = 0;
        std::uint64_t next = 0;
        std::uint32_t crc = 0;
        std::uint32_t external_attrs = 0;
        std::uint16_t method = 0;
        std::uint16_t flags = 0;
        std::uint16_t made_by = 0;
        std::int64_t mtime = 0;
        bool ok = false;
    };

    Entry read_entry(std::uint64_t pos) const;
    /// Offset of the member's data, from its local header (the name and extra
    /// lengths there differ from the directory's).
    std::optional<std::uint64_t> data_offset(const Entry& e) const;

    Span span_;
    bool opened_ = false;
    bool zip64_ = false;
    std::uint64_t cd_at_ = 0;
    std::uint64_t cd_size_ = 0;
    std::uint64_t declared_entries_ = 0;
    std::uint64_t entries_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace omnitrace::container
