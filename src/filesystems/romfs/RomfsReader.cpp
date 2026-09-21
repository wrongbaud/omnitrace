// RomfsReader.cpp — romfs extraction.
//
// The format (Documentation/filesystems/romfs.rst) is the simplest filesystem
// this tool reads. Everything is big-endian and 16-byte aligned:
//
//     [ "-rom1fs-" | full size | checksum | volume name... ]   superblock
//     [ next|flags | spec      | size     | checksum | name... | data... ]
//     [ next|flags | ...                                                 ]
//
// `next` is the offset of the sibling that follows, with the low four bits
// carrying the type (0-7) and the executable bit; 0 ends the list. A
// directory's `spec` is the offset of its first child, so the whole tree is
// reachable by following two kinds of link and nothing else. There is no inode
// table, no block map and no timestamps.
//
// Two things about that shape drive this reader. A singly linked list with
// arbitrary offsets can be made to point at itself, so every traversal is
// bounded by a visited set rather than by trusting the image. And every
// directory starts with `.` and `..` as hard links, which have to be skipped
// by name: following them is the shortest path to a loop.
#include "RomfsReader.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/core/Text.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_romfs() {}
}  // namespace detail

namespace {

constexpr const char* kCodeBadHeader = "romfs-bad-header";
constexpr const char* kCodeCycle = "romfs-cycle";
constexpr const char* kCodeTruncatedEntry = "romfs-truncated-entry";
constexpr const char* kCodeBadLink = "romfs-bad-link";
constexpr const char* kCodeLimitNodes = "romfs-limit-nodes";
constexpr const char* kCodeLimitDepth = "romfs-limit-depth";
constexpr const char* kCodeSinkError = "romfs-sink-error";
constexpr const char* kCodeChecksumMismatch = "romfs-checksum-mismatch";

constexpr std::uint64_t kAlign = 16;
constexpr std::uint64_t kHeaderBytes = 16;
// A name field is NUL-terminated and padded to 16; nothing in the format caps
// it, so the reader does, well above any real name.
constexpr std::uint64_t kMaxNameBytes = 1024;
// How deep the tree may nest. romfs images are shallow; a deeper one is a
// loop that the visited set did not catch because each step is a fresh offset.
constexpr std::size_t kMaxDepth = 64;

std::uint64_t align16(std::uint64_t n) {
    return (n + kAlign - 1) & ~(kAlign - 1);
}

enum Type : std::uint32_t {
    kHardLink = 0,
    kDirectory = 1,
    kRegular = 2,
    kSymlink = 3,
    kBlockDev = 4,
    kCharDev = 5,
    kSocket = 6,
    kFifo = 7,
};

const char* type_name(std::uint32_t t) {
    switch (t) {
        case kHardLink:
            return "hard-link";
        case kDirectory:
            return "directory";
        case kRegular:
            return "regular";
        case kSymlink:
            return "symlink";
        case kBlockDev:
            return "block-device";
        case kCharDev:
            return "char-device";
        case kSocket:
            return "socket";
        case kFifo:
            return "fifo";
        default:
            return "unknown";
    }
}

EntryKind kind_of(std::uint32_t t) {
    switch (t) {
        case kDirectory:
            return EntryKind::Directory;
        case kSymlink:
            return EntryKind::Symlink;
        case kBlockDev:
            return EntryKind::BlockDevice;
        case kCharDev:
            return EntryKind::CharDevice;
        case kSocket:
            return EntryKind::Socket;
        case kFifo:
            return EntryKind::Fifo;
        default:
            return EntryKind::Regular;
    }
}

// romfs stores no permission bits: the type and one executable flag is all
// there is. Give an examiner the mode the kernel itself synthesises, so the
// extracted tree is usable, and say in the entry's extra that it was not read
// off the image.
std::uint32_t mode_for(std::uint32_t type, bool executable) {
    switch (type) {
        case kDirectory:
            return 0755;
        case kSymlink:
            return 0777;
        default:
            return executable ? 0755 : 0644;
    }
}

struct Header {
    std::uint64_t at = 0;        // where the header starts
    std::uint64_t next = 0;      // sibling offset, 0 when last
    std::uint32_t type = 0;      // low three bits of the raw `next`
    bool executable = false;     // bit three of the raw `next`
    std::uint64_t spec = 0;      // meaning depends on the type
    std::uint64_t size = 0;      // data bytes
    std::uint32_t checksum = 0;  // stored; the kernel checks only the superblock's
    std::string name;            // raw, as stored
    std::uint64_t data = 0;      // where the data starts
};

}  // namespace

struct RomfsReader::Impl {
    Span span;
    bool opened = false;
    std::string volume;
    std::uint64_t full_size = 0;
    std::uint64_t root = 0;  // first header of the root directory
    bool checksum_ok = false;

    std::optional<Header> read_header(std::uint64_t at) const {
        if (at % kAlign != 0) return std::nullopt;
        if (at + kHeaderBytes > span.size()) return std::nullopt;
        const auto raw_next = span.at<std::uint32_t>(at + 0, Endian::Big);
        const auto spec = span.at<std::uint32_t>(at + 4, Endian::Big);
        const auto size = span.at<std::uint32_t>(at + 8, Endian::Big);
        const auto sum = span.at<std::uint32_t>(at + 12, Endian::Big);
        if (!raw_next || !spec || !size || !sum) return std::nullopt;

        Header h;
        h.at = at;
        h.type = *raw_next & 0x7U;
        h.executable = (*raw_next & 0x8U) != 0;
        h.next = *raw_next & ~static_cast<std::uint32_t>(0xF);
        h.spec = *spec;
        h.size = *size;
        h.checksum = *sum;

        // The name runs from the end of the fixed header to its NUL, padded to
        // 16. Read it a chunk at a time so a missing terminator costs nothing.
        std::uint64_t n = 0;
        bool terminated = false;
        while (n < kMaxNameBytes) {
            const std::uint64_t at_byte = at + kHeaderBytes + n;
            if (at_byte >= span.size()) break;
            const auto c = span.u8(at_byte);
            if (!c) break;
            if (*c == 0) {
                terminated = true;
                break;
            }
            h.name.push_back(static_cast<char>(*c));
            ++n;
        }
        if (!terminated) return std::nullopt;
        h.data = at + kHeaderBytes + align16(n + 1);
        if (h.data > span.size()) return std::nullopt;
        return h;
    }
};

RomfsReader::RomfsReader() : impl_(std::make_unique<Impl>()) {}
RomfsReader::~RomfsReader() = default;

std::string RomfsReader::format() const {
    return "romfs";
}

Status RomfsReader::open(const Span& span) {
    static constexpr std::uint8_t kMagic[8] = {'-', 'r', 'o', 'm', '1', 'f', 's', '-'};
    if (span.size() < 32) return Status::fail("romfs-truncated: fewer than 32 bytes of superblock");
    if (!span.matches_at(0, std::span<const std::uint8_t>(kMagic, sizeof(kMagic))))
        return Status::fail("romfs-bad-magic: no \"-rom1fs-\" at offset 0");

    const auto full = span.at<std::uint32_t>(8, Endian::Big);
    if (!full) return Status::fail("romfs-truncated: the size field is not readable");

    Impl& d = *impl_;
    d.span = span;
    d.full_size = *full;

    // Volume name: NUL-terminated, padded to 16. The first file header follows.
    //
    // It has to be printable ASCII, which is the same rule the validator uses
    // and the reason it keeps a hit like this at the magic tier. `-rom1fs-`
    // turns up inside blkid's compiled magic table, between `XFSB` and
    // `iso9660`, and the audio corpus image has one. Accepting that meant
    // `info()` handed back a `full_size` read out of noise, the node got a
    // 1.87 GB extent from it, and two gigabytes of unrelated image were
    // carved to disk as a filesystem.
    std::uint64_t n = 0;
    bool terminated = false;
    bool printable = true;
    while (n < kMaxNameBytes && 16 + n < span.size()) {
        const auto c = span.u8(16 + n);
        if (!c) break;
        if (*c == 0) {
            terminated = true;
            break;
        }
        printable = printable && *c >= 0x20 && *c < 0x7F;
        d.volume.push_back(static_cast<char>(*c));
        ++n;
    }
    if (!terminated) return Status::fail("romfs-bad-name: the volume name has no terminator");
    if (!printable)
        return Status::fail(
            "romfs-bad-name: the volume name is not printable ASCII, so this is the magic string "
            "inside other data rather than a filesystem");

    d.root = 16 + align16(n + 1);
    // The size field has to be able to hold the header and one file entry, and
    // the first header has to be inside it. Both are the validator's checks:
    // a reader that accepts what the validator would not hands `analyze` an
    // extent built from noise.
    if (d.full_size < d.root + kHeaderBytes)
        return Status::fail("romfs-bad-size: full size " + std::to_string(d.full_size) +
                            " cannot hold the header and a file entry");
    if (d.root + kHeaderBytes > span.size())
        return Status::fail("romfs-truncated: no room for the first file header");
    if (!d.read_header(d.root))
        return Status::fail("romfs-bad-first-header: the first file header is not readable");

    // The one checksum the kernel itself verifies: the u32 words of the first
    // 512 bytes (or the whole image when smaller) sum to zero.
    const std::uint64_t covered = std::min<std::uint64_t>({512, d.full_size, span.size()}) & ~3ULL;
    std::uint32_t sum = 0;
    for (std::uint64_t off = 0; off + 4 <= covered; off += 4) {
        const auto w = span.at<std::uint32_t>(off, Endian::Big);
        if (!w) break;
        sum += *w;
    }
    d.checksum_ok = sum == 0;
    d.opened = true;
    return Status::success();
}

FilesystemInfo RomfsReader::info() const {
    const Impl& d = *impl_;
    FilesystemInfo i;
    i.format = "romfs";
    i.label = sanitize_utf8(d.volume);
    i.size = d.full_size;
    i.block_size = kAlign;  // the format's only granularity
    i.endian = Endian::Big;
    i.attrs["full_size"] = std::to_string(d.full_size);
    i.attrs["checksum"] = d.checksum_ok ? "ok" : "mismatch";
    return i;
}

Status RomfsReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& d = *impl_;
    if (!d.opened) return Status::fail("romfs-not-open: walk before a successful open");

    if (!d.checksum_ok)
        out.diagnostics.push_back({Severity::Warning, kCodeChecksumMismatch,
                                   "the superblock checksum does not sum to zero; the image is "
                                   "damaged or was edited, and what follows may be unreliable"});

    // Every header offset reached, so a list that points back at itself stops
    // rather than running until a limit trips.
    std::set<std::uint64_t> seen;
    std::uint64_t nodes = 0;
    bool stop = false;

    const auto count = [&out](const FileMeta& m) {
        ++out.entries;
        switch (m.kind) {
            case EntryKind::Directory:
                ++out.dirs;
                break;
            case EntryKind::Symlink:
                ++out.symlinks;
                break;
            case EntryKind::Regular:
                ++out.files;
                break;
            default:
                ++out.others;
                break;
        }
    };

    // Reads `h`'s data run. romfs stores it uncompressed and contiguous, so
    // this is a bounded copy and nothing more.
    const auto read_data = [&d](const Header& h, std::uint64_t cap) {
        const std::uint64_t want = std::min<std::uint64_t>(h.size, cap);
        const std::uint64_t have = d.span.size() > h.data ? d.span.size() - h.data : 0;
        const std::size_t n = static_cast<std::size_t>(std::min(want, have));
        auto b = d.span.bytes(h.data, n);
        return b ? std::move(*b) : std::vector<std::uint8_t>{};
    };

    // Follows a hard link to the header that holds the bytes. The format lets
    // one hard link point at another, so this is bounded too.
    const auto resolve = [&d](Header h, bool& ok) {
        std::set<std::uint64_t> hops;
        while (h.type == kHardLink) {
            if (!hops.insert(h.at).second) {
                ok = false;
                return h;
            }
            const auto target = d.read_header(h.spec);
            if (!target) {
                ok = false;
                return h;
            }
            h = *target;
        }
        ok = true;
        return h;
    };

    const std::function<void(std::uint64_t, const std::string&, std::size_t)> walk_dir =
        [&](std::uint64_t first, const std::string& prefix, std::size_t depth) {
            if (stop) return;
            if (depth > kMaxDepth) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeLimitDepth,
                     "directory nesting deeper than " + std::to_string(kMaxDepth) + " at '" +
                         prefix + "'; not descended (the image is looping or hostile)"});
                out.truncated = true;
                return;
            }
            for (std::uint64_t at = first; at != 0 && !stop;) {
                if (!seen.insert(at).second) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeCycle,
                         "the header at " + std::to_string(at) + " under '" + prefix +
                             "' was already visited; the directory list loops and was cut here"});
                    out.truncated = true;
                    return;
                }
                const auto h = d.read_header(at);
                if (!h) {
                    out.diagnostics.push_back({Severity::Warning, kCodeBadHeader,
                                               "the header at " + std::to_string(at) + " under '" +
                                                   prefix +
                                                   "' is unreadable; the rest of this directory "
                                                   "was not walked"});
                    out.truncated = true;
                    return;
                }
                if (nodes >= opts.limits.max_nodes_per_fs) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeLimitNodes,
                         "max_nodes_per_fs (" + std::to_string(opts.limits.max_nodes_per_fs) +
                             ") reached; the rest of the image was not walked"});
                    out.truncated = true;
                    stop = true;
                    return;
                }
                ++nodes;

                const std::uint64_t next = h->next;
                // "." and ".." are hard links every directory carries. They are
                // navigation, not entries, and following them is a loop.
                if (h->name == "." || h->name == "..") {
                    at = next;
                    continue;
                }
                if (h->name.empty()) {
                    out.diagnostics.push_back({Severity::Warning, kCodeBadHeader,
                                               "the header at " + std::to_string(at) + " under '" +
                                                   prefix + "' has an empty name; skipped"});
                    at = next;
                    continue;
                }

                const std::string path = prefix.empty() ? h->name : prefix + "/" + h->name;

                bool linked = true;
                const Header body = resolve(*h, linked);
                if (!linked) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeBadLink,
                         "'" + path + "' is a hard link that does not resolve; skipped"});
                    at = next;
                    continue;
                }

                FileMeta m;
                m.path = path;
                m.kind = kind_of(body.type);
                m.mode = mode_for(body.type, body.executable);
                m.inode = body.at;  // a header's offset is its only stable identity
                m.size = body.size;
                m.extra["romfs_type"] = type_name(body.type);
                // romfs records no permissions, owners or times. Saying so on
                // the entry keeps the synthesised mode from reading as evidence.
                m.extra["mode_source"] = "synthesised: romfs stores only a type and an exec bit";
                if (h->type == kHardLink) m.extra["hard_link_to"] = std::to_string(body.at);

                if (body.data + body.size > d.span.size()) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeTruncatedEntry,
                         "'" + path + "' claims " + std::to_string(body.size) +
                             " bytes but the image ends first; what was there is emitted"});
                    out.truncated = true;
                }

                EntryResult r;
                Status emitted = Status::success();
                if (body.type == kSymlink) {
                    const auto target = read_data(body, opts.limits.max_file_bytes);
                    m.link_target = sanitize_utf8(std::string(target.begin(), target.end()));
                    m.size = 0;
                    emitted = sink.entry(m, r);
                } else if (body.type == kBlockDev || body.type == kCharDev) {
                    m.rdev_major = static_cast<std::uint32_t>(body.spec >> 16);
                    m.rdev_minor = static_cast<std::uint32_t>(body.spec & 0xFFFF);
                    m.size = 0;
                    emitted = sink.entry(m, r);
                } else if (body.type == kDirectory || body.type == kSocket || body.type == kFifo) {
                    m.size = 0;
                    emitted = sink.entry(m, r);
                } else if (opts.extract_data) {
                    const auto data = read_data(body, opts.limits.max_file_bytes);
                    emitted =
                        sink.file(m, std::span<const std::uint8_t>(data.data(), data.size()), r);
                    out.bytes += data.size();
                } else {
                    emitted = sink.begin_file(m);
                    if (emitted) emitted = sink.end_file(r);
                }

                if (!emitted) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeSinkError, "'" + path + "': " + emitted.error});
                } else {
                    if (r.truncated) out.truncated = true;
                    count(r.meta.path.empty() ? m : r.meta);
                    out.entries_out.push_back(std::move(r));
                }

                if (body.type == kDirectory && body.spec != 0) walk_dir(body.spec, path, depth + 1);
                at = next;
            }
        };

    walk_dir(d.root, "", 0);
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("romfs", RomfsReader);

}  // namespace omnitrace::fs
