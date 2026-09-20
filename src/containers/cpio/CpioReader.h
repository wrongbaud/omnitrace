// CpioReader.h — cpio archives: SVR4 "newc"/"crc" and POSIX "odc".
#pragma once
#include <cstdint>
#include <string>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// A cpio archive: a flat list of members, each a header, a name and its
/// data, ending with a member named `TRAILER!!!`. Every entry keeps its mode,
/// owner, mtime and inode; a symlink's target is its data, and devices,
/// fifos and sockets are emitted as their kinds for the Sink to record.
///
/// Three header flavours share the format id and differ only in field widths
/// and padding, so one walk covers them: `newc` (070701) and `crc` (070702)
/// use 110-byte ASCII hex headers with the name and data each padded to 4,
/// `odc` (070707) a 76-byte ASCII octal header with no padding.
///
/// Hard links (`nlink > 1`) are emitted as independent entries, the way the
/// SquashFS reader does; cpio stores the data on the last link, so the
/// earlier ones are empty and say so through `nlink`.
class CpioReader final : public ContainerReader {
   public:
    std::string format() const override { return "cpio"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// One member, located but not yet read.
    struct Member {
        std::uint64_t data_at = 0;
        std::uint64_t size = 0;
        std::uint64_t next = 0;
        std::string name;
        std::uint32_t mode = 0;
        std::uint32_t uid = 0, gid = 0, nlink = 0;
        std::uint64_t mtime = 0, ino = 0;
        std::uint32_t rdev_major = 0, rdev_minor = 0;
        bool trailer = false;
        bool ok = false;
    };

    Member read_member(std::uint64_t pos) const;

    Span span_;
    bool opened_ = false;
    bool odc_ = false;
    const char* variant_ = "newc";
    std::uint64_t entries_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace omnitrace::container
