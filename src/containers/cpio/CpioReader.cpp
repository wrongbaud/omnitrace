// CpioReader.cpp — cpio archives. See the header for the layout.
//
// The same walk as src/discovery/validators/cpio.cpp, which sizes the archive;
// this one emits the members. A reader is handed a Span and never a Finding,
// so the header parse is repeated rather than shared.
#include "CpioReader.h"

#include <algorithm>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr std::uint64_t kNewcHeader = 110;
constexpr std::uint64_t kOdcHeader = 76;
constexpr std::uint64_t kBlock = 512;
constexpr const char* kTrailerName = "TRAILER!!!";

// A member name longer than this is not a path any filesystem produced.
constexpr std::size_t kMaxNameLen = 4096;
// A symlink target is read whole, so it is capped the same way.
constexpr std::size_t kMaxLinkLen = 4096;

constexpr const char* kCodeBadHeader = "cpio-bad-header";
constexpr const char* kCodeTruncated = "cpio-truncated";
constexpr const char* kCodeSinkError = "container-sink-error";
constexpr const char* kCodeLimitEntries = "cpio-limit-entries";

// POSIX mode bits. cpio stores the full st_mode, so the kind is in the top.
constexpr std::uint32_t kIfmt = 0170000;
constexpr std::uint32_t kIfreg = 0100000, kIfdir = 0040000, kIflnk = 0120000;
constexpr std::uint32_t kIfchr = 0020000, kIfblk = 0060000, kIffifo = 0010000,
                        kIfsock = 0140000;

EntryKind kind_of(std::uint32_t mode) {
    switch (mode & kIfmt) {
        case kIfdir:
            return EntryKind::Directory;
        case kIflnk:
            return EntryKind::Symlink;
        case kIfchr:
            return EntryKind::CharDevice;
        case kIfblk:
            return EntryKind::BlockDevice;
        case kIffifo:
            return EntryKind::Fifo;
        case kIfsock:
            return EntryKind::Socket;
        case kIfreg:
        default:
            return EntryKind::Regular;
    }
}

std::optional<std::uint64_t> ascii_field(const Span& span, std::uint64_t off, std::size_t n,
                                         unsigned base) {
    const auto bytes = span.bytes(off, n);
    if (!bytes) return std::nullopt;
    std::uint64_t v = 0;
    for (const std::uint8_t c : *bytes) {
        unsigned d = 0;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            d = 10U + (c - 'A');
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            d = 10U + (c - 'a');
        } else {
            return std::nullopt;
        }
        if (d >= base) return std::nullopt;
        if (v > (UINT64_MAX - d) / base) return std::nullopt;
        v = (v * base) + d;
    }
    return v;
}

std::uint64_t align4(std::uint64_t v) {
    return v > UINT64_MAX - 3 ? v : (v + 3) & ~std::uint64_t{3};
}

// Leading "./" and a trailing "/" are how cpio writes paths; the Sink wants
// neither. Path safety itself (absolute paths, "..") is the Sink's job.
std::string clean_path(std::string p) {
    while (p.rfind("./", 0) == 0) p.erase(0, 2);
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

}  // namespace

CpioReader::Member CpioReader::read_member(std::uint64_t pos) const {
    Member m;
    static constexpr std::uint8_t kNewc[6] = {'0', '7', '0', '7', '0', '1'};
    static constexpr std::uint8_t kCrc[6] = {'0', '7', '0', '7', '0', '2'};
    static constexpr std::uint8_t kOdc[6] = {'0', '7', '0', '7', '0', '7'};
    const bool is_newc = span_.matches_at(pos, std::span<const std::uint8_t>(kNewc, 6)) ||
                         span_.matches_at(pos, std::span<const std::uint8_t>(kCrc, 6));
    const bool is_odc = span_.matches_at(pos, std::span<const std::uint8_t>(kOdc, 6));
    if (odc_ ? !is_odc : !is_newc) return m;

    std::optional<std::uint64_t> namesize, filesize;
    std::uint64_t header = 0;
    if (odc_) {
        header = kOdcHeader;
        m.ino = ascii_field(span_, pos + 12, 6, 8).value_or(0);
        m.mode = static_cast<std::uint32_t>(ascii_field(span_, pos + 18, 6, 8).value_or(0));
        m.uid = static_cast<std::uint32_t>(ascii_field(span_, pos + 24, 6, 8).value_or(0));
        m.gid = static_cast<std::uint32_t>(ascii_field(span_, pos + 30, 6, 8).value_or(0));
        m.nlink = static_cast<std::uint32_t>(ascii_field(span_, pos + 36, 6, 8).value_or(0));
        const std::uint64_t rdev = ascii_field(span_, pos + 42, 6, 8).value_or(0);
        m.rdev_major = static_cast<std::uint32_t>((rdev >> 8) & 0xFF);
        m.rdev_minor = static_cast<std::uint32_t>(rdev & 0xFF);
        m.mtime = ascii_field(span_, pos + 48, 11, 8).value_or(0);
        namesize = ascii_field(span_, pos + 59, 6, 8);
        filesize = ascii_field(span_, pos + 65, 11, 8);
    } else {
        header = kNewcHeader;
        m.ino = ascii_field(span_, pos + 6, 8, 16).value_or(0);
        m.mode = static_cast<std::uint32_t>(ascii_field(span_, pos + 14, 8, 16).value_or(0));
        m.uid = static_cast<std::uint32_t>(ascii_field(span_, pos + 22, 8, 16).value_or(0));
        m.gid = static_cast<std::uint32_t>(ascii_field(span_, pos + 30, 8, 16).value_or(0));
        m.nlink = static_cast<std::uint32_t>(ascii_field(span_, pos + 38, 8, 16).value_or(0));
        m.mtime = ascii_field(span_, pos + 46, 8, 16).value_or(0);
        filesize = ascii_field(span_, pos + 54, 8, 16);
        m.rdev_major = static_cast<std::uint32_t>(ascii_field(span_, pos + 78, 8, 16).value_or(0));
        m.rdev_minor = static_cast<std::uint32_t>(ascii_field(span_, pos + 86, 8, 16).value_or(0));
        namesize = ascii_field(span_, pos + 94, 8, 16);
    }
    if (!namesize || !filesize || *namesize == 0) return m;

    const std::uint64_t name_at = pos + header;
    const auto raw = span_.cstring(
        name_at, static_cast<std::size_t>(std::min<std::uint64_t>(*namesize, kMaxNameLen)));
    if (!raw) return m;
    if (*raw == kTrailerName) {
        m.trailer = true;
        m.ok = true;
        m.next = odc_ ? name_at + *namesize : align4(name_at + *namesize);
        return m;
    }
    m.name = clean_path(sanitize_utf8(*raw));
    m.size = *filesize;
    m.data_at = odc_ ? name_at + *namesize : align4(name_at + *namesize);
    m.next = odc_ ? m.data_at + *filesize : align4(m.data_at + *filesize);
    m.ok = !m.name.empty();
    return m;
}

Status CpioReader::open(const Span& span) {
    opened_ = false;
    entries_ = 0;
    total_ = 0;
    static constexpr std::uint8_t kNewc[6] = {'0', '7', '0', '7', '0', '1'};
    static constexpr std::uint8_t kCrc[6] = {'0', '7', '0', '7', '0', '2'};
    static constexpr std::uint8_t kOdc[6] = {'0', '7', '0', '7', '0', '7'};
    if (span.matches_at(0, std::span<const std::uint8_t>(kNewc, 6))) {
        odc_ = false;
        variant_ = "newc";
    } else if (span.matches_at(0, std::span<const std::uint8_t>(kCrc, 6))) {
        odc_ = false;
        variant_ = "crc";
    } else if (span.matches_at(0, std::span<const std::uint8_t>(kOdc, 6))) {
        odc_ = true;
        variant_ = "odc";
    } else {
        return Status::fail("container-bad-magic: no cpio header at offset 0");
    }
    span_ = span;
    opened_ = true;
    return Status::success();
}

ContainerInfo CpioReader::info() const {
    ContainerInfo i;
    i.format = "cpio";
    i.size = total_;
    i.attrs["variant"] = variant_;
    i.attrs["entries"] = std::to_string(entries_);
    return i;
}

Status CpioReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    const std::uint64_t cap = opts.limits.max_nodes_per_fs;
    std::uint64_t pos = 0;
    entries_ = 0;
    bool trailer = false;

    while (pos < span_.size()) {
        if (entries_ >= cap) {
            out.diagnostics.push_back({Severity::Warning, kCodeLimitEntries,
                                       "max_nodes_per_fs (" + std::to_string(cap) +
                                           ") reached; the rest of the archive was not walked"});
            out.truncated = true;
            break;
        }
        const Member m = read_member(pos);
        if (!m.ok) {
            // A run of members that stops matching is the end of the archive,
            // not a failure: an initramfs is often several archives in a row.
            if (entries_ != 0 || trailer) break;
            out.diagnostics.push_back({Severity::Warning, kCodeBadHeader,
                                       "the header at offset " + std::to_string(pos) +
                                           " is not readable; nothing was emitted"});
            break;
        }
        if (m.trailer) {
            trailer = true;
            pos = m.next;
            break;
        }
        if (m.next <= pos || m.data_at > span_.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                       "'" + m.name + "' runs past the end of the archive"});
            out.truncated = true;
            break;
        }

        FileMeta meta;
        meta.path = m.name;
        meta.kind = kind_of(m.mode);
        meta.mode = m.mode & 07777U;
        meta.uid = m.uid;
        meta.gid = m.gid;
        meta.mtime = static_cast<std::int64_t>(m.mtime);
        meta.inode = m.ino;
        meta.nlink = m.nlink;
        meta.rdev_major = m.rdev_major;
        meta.rdev_minor = m.rdev_minor;

        EntryResult r;
        Status st;
        if (meta.kind == EntryKind::Symlink) {
            const auto target = span_.cstring(
                m.data_at, static_cast<std::size_t>(std::min<std::uint64_t>(m.size, kMaxLinkLen)));
            meta.link_target = target ? sanitize_utf8(*target) : std::string{};
            meta.size = meta.link_target.size();
            st = sink.entry(meta, r);
        } else if (meta.kind == EntryKind::Regular) {
            meta.size = std::min<std::uint64_t>(m.size, span_.size() - m.data_at);
            bool short_read = false;
            st = emit_span_file(sink, opts, meta, span_, m.data_at, meta.size, r, short_read);
            if (short_read || meta.size < m.size) {
                out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                           "'" + m.name + "' claims " + std::to_string(m.size) +
                                               " bytes but the archive ends first"});
                r.truncated = true;
                out.truncated = true;
            }
        } else {
            meta.size = 0;
            st = sink.entry(meta, r);
        }
        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + m.name + "': " + st.error});
        } else {
            ++entries_;
            count_entry(out, r);
            out.entries_out.push_back(std::move(r));
        }
        pos = m.next;
    }

    // The archive's extent: the trailer's end, plus the 512-byte block padding
    // cpio writes, but only when that padding really is zeros.
    std::uint64_t end = pos;
    if (trailer) {
        const std::uint64_t padded = (end + kBlock - 1) & ~(kBlock - 1);
        if (padded > end && padded <= span_.size()) {
            if (const auto tail = span_.bytes(end, static_cast<std::size_t>(padded - end))) {
                bool zeros = true;
                for (const std::uint8_t b : *tail) zeros = zeros && b == 0;
                if (zeros) end = padded;
            }
        }
    } else if (entries_ != 0) {
        out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                   "no TRAILER!!! member; the archive is incomplete"});
        out.truncated = true;
    }
    total_ = end;
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("cpio", CpioReader);

namespace detail {
void omnitrace_container_anchor_cpio() {}
}  // namespace detail

}  // namespace omnitrace::container
