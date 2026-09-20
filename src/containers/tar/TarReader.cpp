// TarReader.cpp — tar archives. See the header for the layout and the three
// long-path conventions.
//
// The same header walk as src/discovery/validators/tar.cpp, which sizes the
// archive and checks the header checksums; this one emits the members. A
// reader is handed a Span and never a Finding, so the parse is repeated.
#include "TarReader.h"

#include <algorithm>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr std::uint64_t kBlock = 512;

// An extended header (a long name, or a pax record block) is read whole, so
// it is capped. No real path or record block approaches this.
constexpr std::uint64_t kMaxExtendedHeader = 1u << 20;

constexpr const char* kCodeBadHeader = "tar-bad-header";
constexpr const char* kCodeTruncated = "tar-truncated";
constexpr const char* kCodeBadPax = "tar-bad-pax-record";
constexpr const char* kCodeSinkError = "container-sink-error";
constexpr const char* kCodeLimitEntries = "tar-limit-entries";

std::optional<std::uint64_t> num_field(const Span& span, std::uint64_t off, std::size_t n) {
    const auto bytes = span.bytes(off, n);
    if (!bytes) return std::nullopt;
    const std::vector<std::uint8_t>& b = *bytes;
    if ((b[0] & 0x80U) != 0) {  // GNU base-256
        std::uint64_t v = b[0] & 0x7FU;
        for (std::size_t i = 1; i < b.size(); ++i) {
            if (v > (UINT64_MAX >> 8)) return std::nullopt;
            v = (v << 8) | b[i];
        }
        return v;
    }
    std::uint64_t v = 0;
    bool any = false;
    for (const std::uint8_t c : b) {
        if (c == 0 || c == ' ') {
            if (any) break;
            continue;
        }
        if (c < '0' || c > '7') return std::nullopt;
        if (v > (UINT64_MAX - static_cast<std::uint64_t>(c - '0')) / 8) return std::nullopt;
        v = (v * 8) + static_cast<std::uint64_t>(c - '0');
        any = true;
    }
    return any ? std::optional<std::uint64_t>(v) : std::optional<std::uint64_t>(0);
}

std::uint64_t round_block(std::uint64_t v) {
    return v > UINT64_MAX - (kBlock - 1) ? v : (v + kBlock - 1) & ~(kBlock - 1);
}

EntryKind kind_of(std::uint8_t flag) {
    switch (flag) {
        case '5':
            return EntryKind::Directory;
        case '2':
            return EntryKind::Symlink;
        case '3':
            return EntryKind::CharDevice;
        case '4':
            return EntryKind::BlockDevice;
        case '6':
            return EntryKind::Fifo;
        default:
            return EntryKind::Regular;  // '0', '\0', '7' (contiguous), '1' (hard link)
    }
}

// tar writes directories with a trailing '/' and often prefixes "./"; the
// Sink wants neither. Path safety is the Sink's job, not this one's.
std::string clean_path(std::string p) {
    while (p.rfind("./", 0) == 0) p.erase(0, 2);
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

bool all_zero(const std::vector<std::uint8_t>& b) {
    for (const std::uint8_t v : b) {
        if (v != 0) return false;
    }
    return true;
}

std::optional<std::uint64_t> parse_u64(const std::string& s) {
    if (s.empty() || s.size() > 20) return std::nullopt;
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = (v * 10) + d;
    }
    return v;
}

}  // namespace

void TarReader::apply_pax(std::uint64_t off, std::uint64_t len, Pending& into,
                          WalkResult& out) const {
    const auto bytes =
        span_.bytes(off, static_cast<std::size_t>(std::min(len, kMaxExtendedHeader)));
    if (!bytes) return;
    const std::string text(bytes->begin(), bytes->end());
    std::size_t pos = 0;
    while (pos < text.size()) {
        // "<length> <key>=<value>\n", length counting the whole record.
        const std::size_t sp = text.find(' ', pos);
        if (sp == std::string::npos) break;
        const auto reclen = parse_u64(text.substr(pos, sp - pos));
        if (!reclen || *reclen <= sp - pos || pos + *reclen > text.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadPax,
                                       "a pax record length is missing or runs past the block; "
                                       "the rest of the block is ignored"});
            return;
        }
        const std::string record = text.substr(sp + 1, pos + *reclen - sp - 2);  // drop the '\n'
        const std::size_t eq = record.find('=');
        if (eq != std::string::npos) {
            const std::string key = record.substr(0, eq);
            const std::string value = record.substr(eq + 1);
            if (key == "path") {
                into.path = sanitize_utf8(value);
            } else if (key == "linkpath") {
                into.linkpath = sanitize_utf8(value);
            } else if (key == "size") {
                into.size = parse_u64(value);
            } else if (key == "mtime") {
                // pax mtime may carry a fraction; the seconds part is enough.
                into.mtime = static_cast<std::int64_t>(parse_u64(value.substr(0, value.find('.')))
                                                           .value_or(0));
            } else if (key == "uid") {
                if (const auto v = parse_u64(value)) into.uid = static_cast<std::uint32_t>(*v);
            } else if (key == "gid") {
                if (const auto v = parse_u64(value)) into.gid = static_cast<std::uint32_t>(*v);
            }
        }
        pos += static_cast<std::size_t>(*reclen);
    }
}

Status TarReader::open(const Span& span) {
    opened_ = false;
    entries_ = 0;
    total_ = 0;
    static constexpr std::uint8_t kUstar[5] = {'u', 's', 't', 'a', 'r'};
    if (!span.matches_at(257, std::span<const std::uint8_t>(kUstar, 5)))
        return Status::fail("container-bad-magic: no ustar magic at offset 257");
    const auto ver = span.bytes(257, 8);
    if (!ver) return Status::fail("container-empty: fewer than 265 header bytes");
    variant_ = ((*ver)[5] == ' ' && (*ver)[6] == ' ') ? "gnu" : "ustar";
    span_ = span;
    opened_ = true;
    return Status::success();
}

ContainerInfo TarReader::info() const {
    ContainerInfo i;
    i.format = "tar";
    i.size = total_;
    i.attrs["variant"] = variant_;
    i.attrs["entries"] = std::to_string(entries_);
    return i;
}

Status TarReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    const std::uint64_t cap = opts.limits.max_nodes_per_fs;
    std::uint64_t pos = 0;
    entries_ = 0;
    bool end_marker = false;
    Pending pending;  // from the preceding L / K / x member
    Pending global;   // from a g member: applies to the rest of the archive

    while (pos + kBlock <= span_.size()) {
        if (entries_ >= cap) {
            out.diagnostics.push_back({Severity::Warning, kCodeLimitEntries,
                                       "max_nodes_per_fs (" + std::to_string(cap) +
                                           ") reached; the rest of the archive was not walked"});
            out.truncated = true;
            break;
        }
        const auto header = span_.bytes(pos, static_cast<std::size_t>(kBlock));
        if (!header) break;
        if (all_zero(*header)) {
            end_marker = true;
            pos += kBlock;
            if (const auto second = span_.bytes(pos, static_cast<std::size_t>(kBlock))) {
                if (all_zero(*second)) pos += kBlock;
            }
            break;
        }

        const auto size = num_field(span_, pos + 124, 12);
        const auto flag = span_.u8(pos + 156);
        if (!size || !flag) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadHeader,
                                       "the header at offset " + std::to_string(pos) +
                                           " is not readable; the walk stops there"});
            out.truncated = true;
            break;
        }
        const std::uint64_t data_at = pos + kBlock;
        const std::uint64_t next = data_at + round_block(*size);
        if (next <= pos || data_at > span_.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                       "a member runs past the end of the archive"});
            out.truncated = true;
            break;
        }

        // The extended-header members carry data for the member that follows.
        if (*flag == 'L' || *flag == 'K') {
            const auto raw = span_.cstring(
                data_at, static_cast<std::size_t>(std::min(*size, kMaxExtendedHeader)));
            if (raw) {
                if (*flag == 'L') {
                    pending.path = sanitize_utf8(*raw);
                } else {
                    pending.linkpath = sanitize_utf8(*raw);
                }
            }
            variant_ = "gnu";
            pos = next;
            continue;
        }
        if (*flag == 'x' || *flag == 'g') {
            apply_pax(data_at, *size, *flag == 'g' ? global : pending, out);
            variant_ = "pax";
            pos = next;
            continue;
        }

        // Name: pax/GNU override, else prefix + '/' + name.
        std::string path = pending.path.empty() ? global.path : pending.path;
        if (path.empty()) {
            const auto name = span_.cstring(pos, 100);
            const auto prefix = span_.cstring(pos + 345, 155);
            path = name ? sanitize_utf8(*name) : std::string{};
            if (prefix && !prefix->empty() && variant_ != "gnu")
                path = sanitize_utf8(*prefix) + "/" + path;
        }
        path = clean_path(std::move(path));
        if (path.empty() || path == ".") {
            pending.clear();
            pos = next;
            continue;
        }

        FileMeta meta;
        meta.path = path;
        meta.kind = kind_of(*flag);
        meta.mode = static_cast<std::uint32_t>(num_field(span_, pos + 100, 8).value_or(0) & 07777U);
        meta.uid = pending.uid ? *pending.uid
                               : (global.uid ? *global.uid
                                             : static_cast<std::uint32_t>(
                                                   num_field(span_, pos + 108, 8).value_or(0)));
        meta.gid = pending.gid ? *pending.gid
                               : (global.gid ? *global.gid
                                             : static_cast<std::uint32_t>(
                                                   num_field(span_, pos + 116, 8).value_or(0)));
        meta.mtime = pending.mtime
                         ? *pending.mtime
                         : static_cast<std::int64_t>(num_field(span_, pos + 136, 12).value_or(0));
        meta.rdev_major =
            static_cast<std::uint32_t>(num_field(span_, pos + 329, 8).value_or(0));
        meta.rdev_minor =
            static_cast<std::uint32_t>(num_field(span_, pos + 337, 8).value_or(0));
        if (const auto uname = span_.cstring(pos + 265, 32); uname && !uname->empty())
            meta.extra["uname"] = sanitize_utf8(*uname);
        if (const auto gname = span_.cstring(pos + 297, 32); gname && !gname->empty())
            meta.extra["gname"] = sanitize_utf8(*gname);

        const std::string linkname = !pending.linkpath.empty()
                                         ? pending.linkpath
                                         : sanitize_utf8(span_.cstring(pos + 157, 100).value_or(""));

        EntryResult r;
        Status st;
        if (*flag == '1') {
            // A hard link has no data of its own; the Sink has no primitive
            // for it, so it becomes an empty file that names its target.
            meta.size = 0;
            meta.nlink = 2;
            if (!linkname.empty()) meta.extra["hardlink"] = linkname;
            st = sink.entry(meta, r);
        } else if (meta.kind == EntryKind::Symlink) {
            meta.link_target = linkname;
            meta.size = linkname.size();
            st = sink.entry(meta, r);
        } else if (meta.kind == EntryKind::Regular) {
            const std::uint64_t claimed = pending.size ? *pending.size : *size;
            meta.size = std::min<std::uint64_t>(claimed, span_.size() - data_at);
            bool short_read = false;
            st = emit_span_file(sink, opts, meta, span_, data_at, meta.size, r, short_read);
            if (short_read || meta.size < claimed) {
                out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                           "'" + path + "' claims " + std::to_string(claimed) +
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
                {Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error});
        } else {
            ++entries_;
            count_entry(out, r);
            out.entries_out.push_back(std::move(r));
        }
        pending.clear();
        pos = next;
    }

    if (!end_marker && entries_ != 0) {
        out.diagnostics.push_back({Severity::Warning, kCodeTruncated,
                                   "no end-of-archive block; the archive is incomplete"});
        out.truncated = true;
    }
    total_ = pos;
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("tar", TarReader);

namespace detail {
void omnitrace_container_anchor_tar() {}
}  // namespace detail

}  // namespace omnitrace::container
