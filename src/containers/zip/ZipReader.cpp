// ZipReader.cpp — ZIP archives, read through the central directory.
//
// Layout and field offsets are in src/discovery/validators/zip.cpp, which
// walks the same structures forward to size the archive. This reader goes the
// other way: back from the end to the EOCD, then through the directory.
//
// Reference: PKWARE APPNOTE.TXT 6.3.10.
#include "ZipReader.h"

#include <algorithm>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr std::uint32_t kLocal = 0x04034B50U;
constexpr std::uint32_t kCentral = 0x02014B50U;
constexpr std::uint32_t kEocd = 0x06054B50U;
constexpr std::uint32_t kEocd64 = 0x06064B50U;
constexpr std::uint32_t kEocd64Locator = 0x07064B50U;

constexpr std::uint64_t kLocalHeader = 30;
constexpr std::uint64_t kCentralHeader = 46;
constexpr std::uint64_t kEocdSize = 22;
constexpr std::uint32_t kZip64Marker = 0xFFFFFFFFU;
constexpr std::uint16_t kZip64ExtraId = 0x0001;

// The EOCD may be followed by a comment of at most 65535 bytes.
constexpr std::uint64_t kMaxComment = 65535;
// A member name longer than this is not a path any archiver produced.
constexpr std::size_t kMaxNameLen = 4096;

constexpr std::uint16_t kMethodStored = 0;
constexpr std::uint16_t kMethodDeflate = 8;

constexpr const char* kCodeBadEntry = "zip-bad-entry";
constexpr const char* kCodeTruncated = "zip-truncated";
constexpr const char* kCodeMethod = "zip-unsupported-method";
constexpr const char* kCodeDecompress = "zip-decompress-failed";
constexpr const char* kCodeSinkError = "container-sink-error";
constexpr const char* kCodeLimitEntries = "zip-limit-entries";

// Unix mode bits, present when the archive was made on a Unix host.
constexpr std::uint32_t kIfmt = 0170000;
constexpr std::uint32_t kIfdir = 0040000, kIflnk = 0120000;
constexpr std::uint16_t kMadeByUnix = 3;

std::optional<std::uint32_t> u32(const Span& s, std::uint64_t off) {
    return s.at<std::uint32_t>(off, Endian::Little);
}
std::optional<std::uint16_t> u16(const Span& s, std::uint64_t off) {
    return s.at<std::uint16_t>(off, Endian::Little);
}
std::optional<std::uint64_t> u64(const Span& s, std::uint64_t off) {
    return s.at<std::uint64_t>(off, Endian::Little);
}

// MS-DOS date and time to a Unix timestamp. The format has 2-second
// resolution and no time zone; it is read as UTC, which is what every other
// tool does with it.
std::int64_t dos_time(std::uint16_t time, std::uint16_t date) {
    const int year = 1980 + ((date >> 9) & 0x7F);
    const int month = (date >> 5) & 0x0F;
    const int day = date & 0x1F;
    const int hour = (time >> 11) & 0x1F;
    const int minute = (time >> 5) & 0x3F;
    const int second = (time & 0x1F) * 2;
    if (month < 1 || month > 12 || day < 1 || day > 31) return 0;
    // Days from the civil epoch (Howard Hinnant's algorithm).
    int y = year;
    y -= month <= 2 ? 1 : 0;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy =
        static_cast<unsigned>((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1);
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = static_cast<std::int64_t>(era) * 146097 +
                              static_cast<std::int64_t>(doe) - 719468;
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

// A trailing '/' is how a zip marks a directory; the Sink wants the path
// without it. Path safety itself is the Sink's job.
std::string clean_path(std::string p) {
    while (p.rfind("./", 0) == 0) p.erase(0, 2);
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

}  // namespace

ZipReader::Entry ZipReader::read_entry(std::uint64_t pos) const {
    Entry e;
    const auto sig = u32(span_, pos);
    if (!sig || *sig != kCentral) return e;
    const auto made_by = u16(span_, pos + 4);
    const auto flags = u16(span_, pos + 8);
    const auto method = u16(span_, pos + 10);
    const auto time = u16(span_, pos + 12);
    const auto date = u16(span_, pos + 14);
    const auto crc = u32(span_, pos + 16);
    const auto csize = u32(span_, pos + 20);
    const auto usize = u32(span_, pos + 24);
    const auto namelen = u16(span_, pos + 28);
    const auto extralen = u16(span_, pos + 30);
    const auto commentlen = u16(span_, pos + 32);
    const auto attrs = u32(span_, pos + 38);
    const auto local = u32(span_, pos + 42);
    if (!made_by || !flags || !method || !time || !date || !crc || !csize || !usize || !namelen ||
        !extralen || !commentlen || !attrs || !local) {
        return e;
    }
    const auto raw = span_.cstring(pos + kCentralHeader,
                                   static_cast<std::size_t>(std::min<std::uint64_t>(
                                       *namelen, kMaxNameLen)));
    if (!raw) return e;

    e.made_by = *made_by;
    e.flags = *flags;
    e.method = *method;
    e.crc = *crc;
    e.csize = *csize;
    e.usize = *usize;
    e.local_at = *local;
    e.external_attrs = *attrs;
    e.mtime = dos_time(*time, *date);
    e.name = sanitize_utf8(*raw);
    e.next = pos + kCentralHeader + *namelen + *extralen + *commentlen;

    // zip64: the 32-bit fields hold all-ones and the real values live in the
    // 0x0001 extra field, in the order sizes then local-header offset, each
    // present only when its 32-bit field was the marker.
    if (e.csize == kZip64Marker || e.usize == kZip64Marker || e.local_at == kZip64Marker) {
        std::uint64_t x = pos + kCentralHeader + *namelen;
        const std::uint64_t x_end = x + *extralen;
        while (x + 4 <= x_end) {
            const auto id = u16(span_, x);
            const auto len = u16(span_, x + 2);
            if (!id || !len) break;
            if (*id == kZip64ExtraId) {
                std::uint64_t v = x + 4;
                if (e.usize == kZip64Marker) {
                    if (const auto n = u64(span_, v)) e.usize = *n;
                    v += 8;
                }
                if (e.csize == kZip64Marker) {
                    if (const auto n = u64(span_, v)) e.csize = *n;
                    v += 8;
                }
                if (e.local_at == kZip64Marker) {
                    if (const auto n = u64(span_, v)) e.local_at = *n;
                }
                break;
            }
            x += 4ULL + *len;
        }
    }
    e.ok = !e.name.empty();
    return e;
}

std::optional<std::uint64_t> ZipReader::data_offset(const Entry& e) const {
    const auto sig = u32(span_, e.local_at);
    if (!sig || *sig != kLocal) return std::nullopt;
    const auto namelen = u16(span_, e.local_at + 26);
    const auto extralen = u16(span_, e.local_at + 28);
    if (!namelen || !extralen) return std::nullopt;
    return e.local_at + kLocalHeader + *namelen + *extralen;
}

Status ZipReader::open(const Span& span) {
    opened_ = false;
    zip64_ = false;
    entries_ = 0;
    if (span.size() < kEocdSize) return Status::fail("container-empty: too small for a zip");
    const auto first = span.at<std::uint32_t>(0, Endian::Little);
    if (!first || *first != kLocal)
        return Status::fail("container-bad-magic: no local file header at offset 0");

    // The EOCD is the last fixed record; search back from the end over the
    // largest comment the format allows.
    const std::uint64_t window = std::min<std::uint64_t>(span.size(), kMaxComment + kEocdSize);
    const std::uint64_t from = span.size() - window;
    std::optional<std::uint64_t> eocd;
    for (std::uint64_t p = span.size() - kEocdSize + 1; p-- > from;) {
        const auto s = u32(span, p);
        if (!s || *s != kEocd) continue;
        const auto commentlen = u16(span, p + 20);
        // The record must end exactly where its comment says, or it is four
        // bytes of payload that happen to read as a signature.
        if (commentlen && p + kEocdSize + *commentlen == span.size()) {
            eocd = p;
            break;
        }
        if (!eocd && commentlen && p + kEocdSize + *commentlen <= span.size()) eocd = p;
    }
    if (!eocd) return Status::fail("container-bad-magic: no end-of-central-directory record");

    const auto cd_size = u32(span, *eocd + 12);
    const auto cd_off = u32(span, *eocd + 16);
    const auto count = u16(span, *eocd + 10);
    if (!cd_size || !cd_off || !count)
        return Status::fail("container-empty: the EOCD record is cut short");
    cd_size_ = *cd_size;
    cd_at_ = *cd_off;
    declared_entries_ = *count;

    // zip64: a locator sits just before the EOCD and points at the real one.
    if (*eocd >= 20) {
        const auto loc = u32(span, *eocd - 20);
        if (loc && *loc == kEocd64Locator) {
            if (const auto at = u64(span, *eocd - 20 + 8)) {
                const auto s = u32(span, *at);
                if (s && *s == kEocd64) {
                    zip64_ = true;
                    if (const auto n = u64(span, *at + 32)) declared_entries_ = *n;
                    if (const auto n = u64(span, *at + 40)) cd_size_ = *n;
                    if (const auto n = u64(span, *at + 48)) cd_at_ = *n;
                }
            }
        }
    }
    // The EOCD's cd_offset is relative to the start of the archive, which is
    // not the start of the file for an appended or self-extracting zip, and is
    // not this Span's start when the scan found a local header part-way in.
    // The directory always sits immediately before the EOCD, so that is the
    // fallback when the stated offset does not land on a directory entry.
    const auto at_cd = u32(span, cd_at_);
    if (cd_at_ >= span.size() || !at_cd || *at_cd != kCentral) {
        if (cd_size_ <= *eocd) {
            const std::uint64_t back = *eocd - cd_size_;
            const auto s = u32(span, back);
            if (s && *s == kCentral) cd_at_ = back;
        }
    }
    if (cd_at_ >= span.size())
        return Status::fail("container-empty: the central directory is outside the archive");
    total_ = *eocd + kEocdSize + u16(span, *eocd + 20).value_or(0);
    span_ = span;
    opened_ = true;
    return Status::success();
}

ContainerInfo ZipReader::info() const {
    ContainerInfo i;
    i.format = "zip";
    i.size = total_;
    i.attrs["entries"] = std::to_string(entries_);
    i.attrs["declared_entries"] = std::to_string(declared_entries_);
    if (zip64_) i.attrs["zip64"] = "true";
    return i;
}

Status ZipReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    const std::uint64_t cap = opts.limits.max_nodes_per_fs;
    const std::uint64_t cd_end = std::min(cd_at_ + cd_size_, span_.size());
    std::uint64_t pos = cd_at_;
    entries_ = 0;

    while (pos < cd_end) {
        if (entries_ >= cap) {
            out.diagnostics.push_back({Severity::Warning, kCodeLimitEntries,
                                       "max_nodes_per_fs (" + std::to_string(cap) +
                                           ") reached; the rest of the directory was not walked"});
            out.truncated = true;
            break;
        }
        const Entry e = read_entry(pos);
        if (!e.ok) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadEntry,
                                       "the central directory entry at " + std::to_string(pos) +
                                           " is not readable; the walk stops there"});
            out.truncated = true;
            break;
        }

        FileMeta meta;
        meta.path = clean_path(e.name);
        meta.mtime = e.mtime;
        meta.extra["method"] = e.method == kMethodStored
                                   ? "stored"
                                   : (e.method == kMethodDeflate ? "deflate"
                                                                 : std::to_string(e.method));
        // A Unix-made archive keeps st_mode in the top half of the external
        // attributes; anything else only tells us "directory" by the name.
        const bool unix_made = (e.made_by >> 8) == kMadeByUnix;
        const std::uint32_t mode = unix_made ? (e.external_attrs >> 16) : 0;
        if (unix_made && (mode & kIfmt) == kIflnk) {
            meta.kind = EntryKind::Symlink;
        } else if ((unix_made && (mode & kIfmt) == kIfdir) || e.name.back() == '/') {
            meta.kind = EntryKind::Directory;
        } else {
            meta.kind = EntryKind::Regular;
        }
        meta.mode = mode != 0 ? (mode & 07777U)
                              : (meta.kind == EntryKind::Directory ? 0755U : 0644U);

        if (meta.path.empty()) {
            pos = e.next;
            continue;
        }

        const auto data_at = data_offset(e);
        if (!data_at || *data_at > span_.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadEntry,
                                       "'" + meta.path + "' has no readable local header"});
            pos = e.next;
            continue;
        }
        const std::uint64_t avail = span_.size() - *data_at;
        const std::uint64_t csize = std::min(e.csize, avail);

        EntryResult r;
        Status st;
        if (meta.kind == EntryKind::Directory) {
            meta.size = 0;
            st = sink.entry(meta, r);
        } else if (e.method == kMethodStored) {
            meta.size = csize;
            if (meta.kind == EntryKind::Symlink) {
                const auto target = span_.cstring(
                    *data_at, static_cast<std::size_t>(std::min<std::uint64_t>(csize, kMaxNameLen)));
                meta.link_target = target ? sanitize_utf8(*target) : std::string{};
                meta.size = meta.link_target.size();
                st = sink.entry(meta, r);
            } else {
                bool short_read = false;
                st = emit_span_file(sink, opts, meta, span_, *data_at, csize, r, short_read);
                if (short_read || csize < e.csize) {
                    out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                               "'" + meta.path + "' ends before its stored size"});
                    r.truncated = true;
                    out.truncated = true;
                }
            }
        } else if (e.method == kMethodDeflate) {
            // Deflate needs the member whole; max_file_bytes bounds it.
            const auto view = span_.view(*data_at, static_cast<std::size_t>(csize));
            std::optional<std::vector<std::uint8_t>> copy;
            std::span<const std::uint8_t> in;
            if (view) {
                in = *view;
            } else {
                copy = span_.bytes(*data_at, static_cast<std::size_t>(csize));
                if (copy) in = std::span<const std::uint8_t>(copy->data(), copy->size());
            }
            std::vector<std::uint8_t> plain;
            const Status dec = in.empty() && csize != 0
                                   ? Status::fail("decompress-empty-input")
                                   : compress::decompress(compress::Codec::Deflate, in, plain,
                                                          opts.limits.max_file_bytes);
            if (!dec) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeDecompress,
                     "'" + meta.path + "' did not inflate (" + dec.error + "); emitted empty"});
                meta.size = 0;
                st = sink.file(meta, {}, r);
                r.truncated = true;
                out.truncated = true;
            } else if (meta.kind == EntryKind::Symlink) {
                meta.link_target = sanitize_utf8(std::string(plain.begin(), plain.end()));
                meta.size = meta.link_target.size();
                st = sink.entry(meta, r);
            } else {
                meta.size = plain.size();
                st = sink.file(meta, std::span<const std::uint8_t>(plain.data(), plain.size()), r);
            }
        } else {
            out.diagnostics.push_back({Severity::Warning, kCodeMethod,
                                       "'" + meta.path + "' uses compression method " +
                                           std::to_string(e.method) +
                                           ", which is not decoded; emitted empty"});
            meta.size = 0;
            st = sink.file(meta, {}, r);
            r.truncated = true;
            out.truncated = true;
        }

        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + st.error});
        } else {
            ++entries_;
            count_entry(out, r);
            out.entries_out.push_back(std::move(r));
        }
        if (e.next <= pos) break;
        pos = e.next;
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("zip", ZipReader);

namespace detail {
void omnitrace_container_anchor_zip() {}
}  // namespace detail

}  // namespace omnitrace::container
