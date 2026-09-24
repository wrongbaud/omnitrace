// Yaffs2Reader.cpp — YAFFS2 reader. See Yaffs2Reader.h and docs/formats/yaffs2.md.
//
// Format knowledge: yaffs2 `yaffs_guts.h`, `yaffs_packedtags2.c` and
// `yaffs_ecc.c`, read for understanding; nothing copied. The chunk grid, the
// packed tags and the object header are parsed by omnitrace::yaffs
// (include/omnitrace/core/Yaffs.h), which the `yaffs2` validator shares.
//
// Pipeline:
//   open()  find the chunk grid, then read every chunk's tags once. A header
//           chunk (chunk_id 0) describes an object; any other chunk is data
//           block chunk_id - 1 of its object. Both are kept per key in the
//           order they were written, because that order *is* the history:
//           YAFFS2 never overwrites, so the newest chunk for a key is the
//           live one and everything before it is a past state.
//   walk()  the live tree from the root object, file data streamed chunk by
//           chunk (a block with no chunk is a hole and reads as zeros);
//           with history, the earlier states, the objects whose newest header
//           says deleted or unlinked, and anything with no reachable name.
//
// "Newest" is (seq_number, chunk index): the sequence number orders the
// erase blocks and the position inside one orders the chunks, which is what
// a mount does when it scans the flash.
#include "Yaffs2Reader.h"

#include <algorithm>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "omnitrace/core/Text.h"
#include "omnitrace/core/Yaffs.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_yaffs2() {}
}  // namespace detail

namespace {

using yaffs::Geometry;
using yaffs::ObjHeader;
using yaffs::ObjType;
using yaffs::Tags;

// Chunks the geometry probe looks at, and the cap on the scan. A 4 GiB NAND
// of 2 KiB pages is two million chunks; the cap leaves room and terminates.
constexpr std::uint64_t kProbeChunks = 16;
constexpr std::uint64_t kMaxChunks = 1u << 23;
constexpr std::uint64_t kMaxDepth = 512;
constexpr std::uint64_t kMaxSymlinkTarget = 4096;

// Diagnostic codes; literal so scripts/gen_docs.py can catalogue them.
constexpr const char* kCodeBadChunk = "yaffs2-bad-chunk";
constexpr const char* kCodeBadHeader = "yaffs2-bad-header";
constexpr const char* kCodeLimitChunks = "yaffs2-limit-chunks";
constexpr const char* kCodeLimitNodes = "yaffs2-limit-nodes";
constexpr const char* kCodeLoop = "yaffs2-directory-loop";
constexpr const char* kCodeMissingChunk = "yaffs2-missing-chunk";
constexpr const char* kCodeBrokenLink = "yaffs2-broken-hardlink";
constexpr const char* kCodeSinkError = "yaffs2-sink-error";
constexpr const char* kCodeHistoryScan = "yaffs2-history-scan";
constexpr const char* kCodeSizeBeyondImage = "yaffs2-size-beyond-image";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

// Where a chunk sits and how it is ordered against the others. YAFFS2 writes
// erase blocks in sequence-number order and chunks inside a block in address
// order, so the pair is the clock.
struct Pos {
    std::uint32_t seq = 0;
    std::uint64_t index = 0;  // chunk number from the image's first chunk
    friend bool operator<(const Pos& a, const Pos& b) {
        return a.seq != b.seq ? a.seq < b.seq : a.index < b.index;
    }
};

/// One chunk of interest: where it is, when it was written, how much of its
/// page is valid.
struct Chunk {
    Pos pos;
    std::uint32_t n_bytes = 0;
};

/// What a live entry needs, after hard links are followed.
struct Resolved {
    std::uint32_t inode = 0;  // the object the content and metadata come from
    ObjHeader hdr;
    bool ok = false;
};

EntryKind kind_of(ObjType t, std::uint32_t mode) {
    switch (t) {
        case ObjType::Directory:
            return EntryKind::Directory;
        case ObjType::Symlink:
            return EntryKind::Symlink;
        case ObjType::File:
        case ObjType::Hardlink:
            return EntryKind::Regular;
        case ObjType::Special:
            // YAFFS2 keeps the kind of a device only in the mode bits.
            switch (mode & 0170000u) {
                case 0060000u:
                    return EntryKind::BlockDevice;
                case 0020000u:
                    return EntryKind::CharDevice;
                case 0140000u:
                    return EntryKind::Socket;
                default:
                    return EntryKind::Fifo;
            }
        default:
            return EntryKind::Regular;
    }
}

}  // namespace

// ------------------------------------------------------------------ Impl

struct Yaffs2Reader::Impl {
    Span span;
    Geometry geo;
    bool opened = false;

    std::uint64_t chunks_seen = 0, used_chunks = 0, erased_chunks = 0, bad_ecc = 0;
    bool hit_chunk_cap = false;
    std::uint32_t seq_min = 0, seq_max = 0;

    // Every header of every object, and every data chunk of every block, in
    // write order. The last of each is what a mount would show.
    std::map<std::uint32_t, std::vector<Chunk>> headers;
    std::map<std::pair<std::uint32_t, std::uint32_t>, std::vector<Chunk>> blocks;
    /// How many hard links point at each object. YAFFS2 stores no link count,
    /// so the only way to know is to count the objects that are links to it.
    std::map<std::uint32_t, std::uint32_t> link_count;

    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        std::vector<std::uint8_t> page, zeros;
        std::set<std::uint32_t> on_path;   // directory loop guard
        std::set<std::uint32_t> seen_ino;  // for the hard-link flag
        std::map<std::uint32_t, std::string> live_path;
        bool stop = false;
    };

    std::uint64_t chunk_at(const Pos& p) const { return p.index * geo.chunk_size(); }
    bool header_at(const Pos& p, ObjHeader& out) const {
        return yaffs::read_header(span, geo, chunk_at(p), out);
    }
    /// The chunk of `key` that `cutoff` sees; see the definition.
    const Chunk* newest(const std::vector<Chunk>& v, const Pos& cutoff,
                        bool* fell_back = nullptr) const;
    /// The object a name resolves to: itself, or what a hard link points at.
    Resolved resolve(std::uint32_t obj_id, const Pos& cutoff, WalkResult& out) const;

    void scan();
    void emit_tree(std::uint32_t obj_id, const std::string& prefix, unsigned depth, Walk& w);
    void emit_object(const std::string& path, std::uint32_t obj_id, const Pos& cutoff,
                     bool deleted, bool superseded, std::uint64_t version, Walk& w,
                     std::map<std::string, std::string> extra);
    bool stream_file(const std::string& path, std::uint32_t obj_id, std::uint64_t size,
                     const Pos& cutoff, Walk& w, bool& truncated,
                     std::vector<Diagnostic>& diags, bool* fell_back = nullptr);
    void emit_history(Walk& w);

    void count_entry(WalkResult& out, const FileMeta& m) const {
        out.entries++;
        switch (m.kind) {
            case EntryKind::Regular:
                out.files++;
                break;
            case EntryKind::Directory:
                out.dirs++;
                break;
            case EntryKind::Symlink:
                out.symlinks++;
                break;
            default:
                out.others++;
                break;
        }
    }
    void diag(WalkResult& out, Severity s, const char* code, std::string msg) const {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }
};

// The chunk a block held at `cutoff`, which is the position of the object
// header whose state is being rebuilt. `Pos{}` means the live state: the
// newest chunk, whenever it was written.
//
// One wrinkle decides the `fell_back` case. A live filesystem writes a file's
// data and then the header that records its new size, so a state's data is
// always at or before its header. mkyaffs2 does it the other way round --
// it creates the object, writing the header, and then writes the contents --
// so the oldest state of a file that a device later modified has its data
// *after* its own header. Reading zeros there would be wrong: the bytes are
// on the medium. When a block has nothing at or before the cutoff, the
// earliest chunk it ever had is the closest thing to that state, and the
// entry says it had to reach for it. The header's size bounds the read, so
// this can only ever fill in a block the state really had.
const Chunk* Yaffs2Reader::Impl::newest(const std::vector<Chunk>& v, const Pos& cutoff,
                                        bool* fell_back) const {
    const Chunk* best = nullptr;
    for (const Chunk& c : v) {  // kept in write order
        if (cutoff.seq != 0 && cutoff < c.pos) break;
        best = &c;
    }
    if (best == nullptr && cutoff.seq != 0 && !v.empty()) {
        best = &v.front();
        if (fell_back != nullptr) *fell_back = true;
    }
    return best;
}

// ------------------------------------------------------------------ scan

// Read every chunk's tags once. This is the whole of the "mount": YAFFS2 has
// no index to consult, so a mount scans the flash exactly like this and keeps
// the newest chunk it finds for each key.
void Yaffs2Reader::Impl::scan() {
    const std::uint64_t chunk = geo.chunk_size();
    for (std::uint64_t i = 0; i * chunk + chunk <= span.size(); ++i) {
        if (i >= kMaxChunks) {
            hit_chunk_cap = true;
            break;
        }
        Tags t;
        if (!yaffs::read_tags(span, geo, i * chunk, t)) break;
        ++chunks_seen;
        if (t.erased) {
            ++erased_chunks;
            continue;
        }
        if (!t.ecc_ok) {
            // The tags carry their own checksum, so a chunk that fails it is
            // damaged. Believing it would put wrong bytes in a file.
            ++bad_ecc;
            continue;
        }
        ++used_chunks;
        if (used_chunks == 1) seq_min = seq_max = t.seq;
        seq_min = std::min(seq_min, t.seq);
        seq_max = std::max(seq_max, t.seq);

        Chunk c;
        c.pos = Pos{t.seq, i};
        c.n_bytes = t.n_bytes;
        if (t.is_header) {
            headers[t.obj_id].push_back(c);
        } else {
            blocks[{t.obj_id, t.chunk_id - 1}].push_back(c);
        }
    }
    auto by_pos = [](const Chunk& a, const Chunk& b) { return a.pos < b.pos; };
    for (auto& [id, v] : headers) std::sort(v.begin(), v.end(), by_pos);
    for (auto& [key, v] : blocks) std::sort(v.begin(), v.end(), by_pos);

    for (const auto& [id, v] : headers) {
        ObjHeader h;
        if (v.empty() || !header_at(v.back().pos, h)) continue;
        if (h.type == ObjType::Hardlink && h.equiv_id > 0)
            ++link_count[static_cast<std::uint32_t>(h.equiv_id)];
    }
}

// ------------------------------------------------------------------ open

Yaffs2Reader::Yaffs2Reader() : impl_(std::make_unique<Impl>()) {}
Yaffs2Reader::~Yaffs2Reader() = default;

std::string Yaffs2Reader::format() const {
    return "yaffs2";
}

Status Yaffs2Reader::open(const Span& span) {
    Impl& m = *impl_;
    m = Impl{};
    if (span.empty()) return Status::fail("yaffs2-empty: no bytes at the image's start");
    // The image's first chunk need not carry an object header, so the probe
    // is told not to require one.
    if (!yaffs::detect_geometry(span, 0, kProbeChunks, m.geo, /*require_header=*/false))
        return Status::fail("yaffs2-no-grid: no page and spare size makes the chunk tags verify "
                            "against their own checksum, so this is not a YAFFS2 chunk grid");
    m.span = span;
    m.scan();
    if (m.headers.empty())
        return Status::fail("yaffs2-no-objects: the chunk grid holds no object header");
    m.opened = true;
    return Status::success();
}

FilesystemInfo Yaffs2Reader::info() const {
    const Impl& m = *impl_;
    FilesystemInfo i;
    i.format = "yaffs2";
    i.size = m.chunks_seen * m.geo.chunk_size();
    i.block_size = m.geo.page;
    i.endian = Endian::Little;
    i.attrs["page_size"] = dec(m.geo.page);
    i.attrs["spare_size"] = dec(m.geo.spare);
    i.attrs["tags_offset"] = dec(m.geo.tags_offset);
    i.attrs["spare_layout"] = m.geo.layout_name();
    i.attrs["chunks"] = dec(m.chunks_seen);
    i.attrs["used_chunks"] = dec(m.used_chunks);
    i.attrs["erased_chunks"] = dec(m.erased_chunks);
    i.attrs["objects"] = dec(m.headers.size());
    i.attrs["seq_min"] = dec(m.seq_min);
    i.attrs["seq_max"] = dec(m.seq_max);
    if (m.bad_ecc != 0) i.attrs["bad_chunks"] = dec(m.bad_ecc);
    return i;
}

// ------------------------------------------------------------------ content

// Stream one object's data. A block with no chunk is a hole -- YAFFS2 makes
// one by simply not writing it -- and reads as zeros.
bool Yaffs2Reader::Impl::stream_file(const std::string& path, std::uint32_t obj_id,
                                     std::uint64_t size, const Pos& cutoff, Walk& w,
                                     bool& truncated, std::vector<Diagnostic>& diags,
                                     bool* fell_back) {
    if (w.zeros.size() != geo.page) w.zeros.assign(geo.page, 0);
    const std::uint64_t cap = std::min<std::uint64_t>(size, w.opts->limits.max_file_bytes);
    if (cap < size) truncated = true;
    bool reported = false;
    for (std::uint64_t pos = 0; pos < cap;) {
        const auto bno = static_cast<std::uint32_t>(pos / geo.page);
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(geo.page, cap - pos));
        const std::uint8_t* src = w.zeros.data();
        std::size_t have = want;
        const auto it = blocks.find({obj_id, bno});
        const Chunk* c = it == blocks.end() ? nullptr : newest(it->second, cutoff, fell_back);
        if (c != nullptr) {
            // n_bytes is how much of the page the file uses; the rest is
            // whatever was in the buffer when it was written.
            const std::size_t valid =
                static_cast<std::size_t>(std::min<std::uint64_t>(c->n_bytes, geo.page));
            w.page.resize(geo.page);
            const std::size_t got =
                span.read(chunk_at(c->pos), std::span<std::uint8_t>(w.page.data(), valid));
            if (got == valid) {
                src = w.page.data();
                have = std::min(want, valid);
            } else {
                truncated = true;
                if (!reported) {
                    diags.push_back({Severity::Warning, kCodeMissingChunk,
                                     "'" + path + "': block " + dec(bno) +
                                         " could not be read; zero-filled"});
                    reported = true;
                }
            }
        }
        if (Status st = w.sink->write(std::span<const std::uint8_t>(src, have)); !st) return false;
        if (have < want) {
            if (Status st =
                    w.sink->write(std::span<const std::uint8_t>(w.zeros.data(), want - have));
                !st)
                return false;
        }
        pos += want;
    }
    return true;
}

// A hard link is an object of its own whose header names the object that
// holds the content; everything a listing shows comes from there.
Resolved Yaffs2Reader::Impl::resolve(std::uint32_t obj_id, const Pos& cutoff,
                                     WalkResult& out) const {
    Resolved r;
    const auto it = headers.find(obj_id);
    if (it == headers.end()) return r;
    const Chunk* c = newest(it->second, cutoff);
    if (c == nullptr || !header_at(c->pos, r.hdr)) return r;
    r.inode = obj_id;
    r.ok = true;
    if (r.hdr.type != ObjType::Hardlink) return r;

    const auto target = static_cast<std::uint32_t>(r.hdr.equiv_id);
    const auto ti = headers.find(target);
    ObjHeader th;
    const Chunk* tc = ti == headers.end() ? nullptr : newest(ti->second, cutoff);
    if (r.hdr.equiv_id < 0 || tc == nullptr || !header_at(tc->pos, th)) {
        out.diagnostics.push_back(
            {Severity::Warning, kCodeBrokenLink,
             "object " + dec(obj_id) + " is a hard link to object " +
                 std::to_string(r.hdr.equiv_id) +
                 ", which is not on the medium; it is listed empty"});
        r.hdr.type = ObjType::File;
        r.hdr.size = 0;
        return r;
    }
    const std::string name = r.hdr.name;
    r.hdr = th;
    r.hdr.name = name;  // the link's own name, the target's everything else
    r.inode = target;
    return r;
}

// ------------------------------------------------------------------ walk

void Yaffs2Reader::Impl::emit_object(const std::string& path, std::uint32_t obj_id,
                                     const Pos& cutoff, bool deleted, bool superseded,
                                     std::uint64_t version, Walk& w,
                                     std::map<std::string, std::string> extra) {
    const Resolved r = resolve(obj_id, cutoff, *w.out);
    if (!r.ok) {
        diag(*w.out, Severity::Warning, kCodeBadHeader,
             "'" + path + "': object " + dec(obj_id) + " has no readable header");
        return;
    }
    const ObjHeader& h = r.hdr;

    FileMeta m;
    m.path = path;
    m.kind = kind_of(h.type, h.mode);
    m.inode = r.inode;
    m.mode = h.mode & 0xFFFFu;
    m.uid = h.uid;
    m.gid = h.gid;
    m.atime = h.atime;
    m.ctime = h.ctime;
    m.mtime = h.mtime;
    m.deleted = deleted;
    m.superseded = superseded;
    m.version = version;
    m.size = h.type == ObjType::File ? h.size : 0;
    for (auto& [k, v] : extra) m.extra[k] = std::move(v);
    if (h.is_shrink) m.extra["shrink_header"] = "true";
    if (obj_id != r.inode) m.extra["hardlink_to"] = dec(r.inode);
    // The name itself, plus every object that is a hard link to it.
    if (const auto lc = link_count.find(r.inode); lc != link_count.end())
        m.nlink = 1 + lc->second;
    // A second name for the same object is a hard link to the first.
    if (!deleted && !superseded && !w.seen_ino.insert(r.inode).second)
        m.extra["hardlink"] = "true";

    if (m.kind == EntryKind::Symlink) {
        std::string target = h.alias;
        if (target.size() > kMaxSymlinkTarget)
            target.resize(static_cast<std::size_t>(kMaxSymlinkTarget));
        m.link_target = target;
        m.size = target.size();
    } else if (m.kind == EntryKind::BlockDevice || m.kind == EntryKind::CharDevice) {
        // The header stores what mknod was given, in Linux's old dev_t.
        m.rdev_major = (h.rdev >> 8) & 0xFFFu;
        m.rdev_minor = (h.rdev & 0xFFu) | ((h.rdev >> 12) & 0xFFF00u);
    }

    std::vector<Diagnostic> diags;
    bool truncated = false;
    if (m.kind == EntryKind::Regular) {
        // A file may legitimately be larger than the flash it is on -- holes
        // cost nothing -- so the size is not clamped. But a header claiming
        // more than every chunk in the image put together is worth saying out
        // loud: the bytes past the last chunk are zeros this reader infers,
        // not zeros it read, and extracting them is bounded only by
        // --max-file-bytes and the run-wide --max-bytes.
        if (m.size > chunks_seen * geo.page) {
            diags.push_back({Severity::Warning, kCodeSizeBeyondImage,
                             "'" + path + "' claims " + dec(m.size) +
                                 " bytes, more than the " + dec(chunks_seen) +
                                 " chunks of this image could hold; everything past its last "
                                 "data chunk is zero-filled"});
        }
        if (const Status st = w.sink->begin_file(m); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            return;
        }
        bool sink_ok = true;
        bool fell_back = false;
        if (w.opts->extract_data)
            sink_ok = stream_file(path, r.inode, m.size, cutoff, w, truncated, diags, &fell_back);
        EntryResult res;
        if (const Status st = w.sink->end_file(res); !st) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
            if (res.meta.path.empty()) return;
        }
        if (!sink_ok || truncated) res.truncated = true;
        if (res.truncated) w.out->truncated = true;
        if (fell_back) res.meta.extra["content_from_first_write"] = "true";
        for (Diagnostic& d : diags) res.diagnostics.push_back(std::move(d));
        w.out->bytes += res.digests.bytes;
        count_entry(*w.out, res.meta);
        if (deleted) ++w.out->deleted;
        if (superseded) ++w.out->superseded;
        w.out->entries_out.push_back(std::move(res));
        return;
    }
    EntryResult res;
    if (const Status st = w.sink->entry(m, res); !st) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error);
        return;
    }
    count_entry(*w.out, res.meta);
    if (deleted) ++w.out->deleted;
    if (superseded) ++w.out->superseded;
    w.out->entries_out.push_back(std::move(res));
}

void Yaffs2Reader::Impl::emit_tree(std::uint32_t obj_id, const std::string& prefix, unsigned depth,
                                   Walk& w) {
    if (w.stop || depth > kMaxDepth) return;
    if (!w.on_path.insert(obj_id).second) {
        diag(*w.out, Severity::Warning, kCodeLoop,
             "directory object " + dec(obj_id) + " is its own ancestor at '" + prefix +
                 "'; the branch stops there");
        return;
    }
    // YAFFS2 has no directory blocks: a name belongs to a directory because
    // its own header says so, so the children are found by asking every
    // object who its parent is.
    struct Child {
        std::uint32_t id;
        std::string name;
        ObjType type;
    };
    std::vector<Child> here;
    for (const auto& [id, v] : headers) {
        if (id == obj_id || v.empty()) continue;
        ObjHeader h;
        if (!header_at(v.back().pos, h)) continue;
        if (h.parent_id != obj_id) continue;
        here.push_back({id, sanitize_utf8(h.name), h.type});
    }
    std::sort(here.begin(), here.end(),
              [](const Child& a, const Child& b) { return a.name < b.name; });

    for (const Child& c : here) {
        if (w.out->entries >= w.opts->limits.max_nodes_per_fs) {
            if (!w.stop) {
                diag(*w.out, Severity::Warning, kCodeLimitNodes,
                     "the entry limit (" + dec(w.opts->limits.max_nodes_per_fs) +
                         ") stopped the walk");
                w.out->truncated = true;
            }
            w.stop = true;
            break;
        }
        if (c.name.empty()) {
            diag(*w.out, Severity::Warning, kCodeBadHeader,
                 "object " + dec(c.id) + " in '" + prefix + "' has no name; it is not listed");
            continue;
        }
        const std::string path = prefix.empty() ? c.name : prefix + "/" + c.name;
        emit_object(path, c.id, Pos{}, false, false, 0, w, {});
        w.live_path.emplace(c.id, path);
        if (c.type == ObjType::Directory) emit_tree(c.id, path, depth + 1, w);
    }
    w.on_path.erase(obj_id);
}

// ------------------------------------------------------------------ history

namespace {

// One historical entry, before its version number is known.
struct Historical {
    std::string path;
    std::uint32_t obj_id = 0;
    Pos pos;
    bool deleted = false;
    bool superseded = false;
    std::map<std::string, std::string> extra;
};

}  // namespace

void Yaffs2Reader::Impl::emit_history(Walk& w) {
    std::vector<Historical> work;
    for (const auto& [id, versions] : headers) {
        if (versions.empty() || id == yaffs::kRootId) continue;
        ObjHeader newest_hdr;
        if (!header_at(versions.back().pos, newest_hdr)) continue;
        // A deleted or unlinked object is one whose newest header names one
        // of the two parents YAFFS2 reserves for them. Its data chunks are
        // still exactly where they were written.
        const bool gone = newest_hdr.parent_id == yaffs::kDeletedId ||
                          newest_hdr.parent_id == yaffs::kUnlinkedId;
        const auto live = w.live_path.find(id);
        const bool named = live != w.live_path.end();
        // A live object with a single header has no past to report. An
        // object with no live name has one whatever its header count: nothing
        // reachable from the root points at it, so the live tree cannot show
        // it and this pass is the only way its contents come out.
        if (named && versions.size() < 2) continue;

        std::string path;
        if (named) {
            path = live->second;
        } else {
            // Deleting is writing a header whose parent is one of the two
            // reserved ids, so the header before it still says which
            // directory the file was in and what it was called. That is the
            // name a listing should show, not a lost+found placeholder.
            for (auto it = versions.rbegin(); it != versions.rend() && path.empty(); ++it) {
                ObjHeader h;
                if (!header_at(it->pos, h)) continue;
                if (h.parent_id == yaffs::kDeletedId || h.parent_id == yaffs::kUnlinkedId)
                    continue;
                const auto dir = w.live_path.find(h.parent_id);
                const std::string name = sanitize_utf8(h.name);
                if (dir == w.live_path.end() || name.empty()) continue;
                path = dir->second.empty() ? name : dir->second + "/" + name;
            }
            if (path.empty()) {
                const std::string name = sanitize_utf8(newest_hdr.name);
                path = "lost+found/#" + dec(id) + (name.empty() ? "" : "-" + name);
            }
        }
        for (std::size_t i = 0; i < versions.size(); ++i) {
            const bool last = i + 1 == versions.size();
            if (named && last) continue;  // that state is the live entry
            Historical h;
            h.path = path;
            h.obj_id = id;
            h.pos = versions[i].pos;
            h.deleted = gone || !named;
            h.superseded = !last;
            h.extra["seq"] = dec(versions[i].pos.seq);
            h.extra["chunk"] = dec(versions[i].pos.index);
            if (!named && path.rfind("lost+found/", 0) == 0) h.extra["name_lost"] = "true";
            if (gone) h.extra["parent"] = newest_hdr.parent_id == yaffs::kDeletedId
                                              ? "deleted"
                                              : "unlinked";
            work.push_back(std::move(h));
        }
    }

    // Version numbers are path-scoped and start at 1, oldest first, so
    // (path, version) is unique and DiskSink's .omnitrace-versions/<path>/v<n>
    // never collides. The live entry keeps 0, which is what makes the live
    // tree byte-identical with and without --history.
    std::sort(work.begin(), work.end(), [](const Historical& a, const Historical& b) {
        return a.path != b.path ? a.path < b.path : a.pos < b.pos;
    });
    std::map<std::string, std::uint64_t> version;
    for (Historical& h : work) {
        if (w.stop) break;
        if (w.out->entries >= w.opts->limits.max_nodes_per_fs) {
            diag(*w.out, Severity::Warning, kCodeLimitNodes,
                 "the entry limit (" + dec(w.opts->limits.max_nodes_per_fs) +
                     ") stopped the history pass");
            w.out->truncated = true;
            w.stop = true;
            break;
        }
        emit_object(h.path, h.obj_id, h.pos, h.deleted, h.superseded, ++version[h.path], w,
                    std::move(h.extra));
    }

    diag(*w.out, Severity::Info, kCodeHistoryScan,
         dec(used_chunks) + " written chunk(s) on the medium; " + dec(w.out->superseded) +
             " superseded and " + dec(w.out->deleted) + " deleted entr(ies) recovered");
}

Status Yaffs2Reader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& m = *impl_;
    if (!m.opened) return Status::fail("yaffs2-not-open: walk before a successful open");

    if (m.bad_ecc != 0) {
        m.diag(out, Severity::Warning, kCodeBadChunk,
               dec(m.bad_ecc) + " chunk(s) fail their tag checksum and were skipped; whatever "
               "they held is missing from its file");
        out.truncated = true;
    }
    if (m.hit_chunk_cap) {
        m.diag(out, Severity::Warning, kCodeLimitChunks,
               "the scan stopped after " + dec(kMaxChunks) + " chunks; the rest of the image was "
               "not read");
        out.truncated = true;
    }

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;
    w.live_path[yaffs::kRootId] = "";
    m.emit_tree(yaffs::kRootId, "", 0, w);
    if (opts.history && !w.stop) m.emit_history(w);
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("yaffs2", Yaffs2Reader);

}  // namespace omnitrace::fs
