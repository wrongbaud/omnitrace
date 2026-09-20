// SevenZipReader.cpp — 7z archives.
//
// The structure is parsed by omnitrace::sevenzip
// (include/omnitrace/core/SevenZip.h), which src/discovery/validators/sevenzip.cpp
// shares; this decodes what it points at.
//
// The shape to keep in mind: files do not own bytes here. The archive holds
// folders, each a coder chain (LZMA2, BCJ, Copy, ...) turning packed streams
// into one output, and that output is cut into substreams, one per file. So
// the walk is a loop over folders, each decoded once and then sliced -- which
// is also why a folder is decoded whole even when only one file in it is
// wanted, and why a solid block bigger than max_file_bytes is skipped rather
// than streamed.
//
// Reference: the 7-Zip source's `DOC/7zFormat.txt`, read for understanding;
// nothing copied. Output checked byte for byte against `7z x`.
#include "SevenZipReader.h"

#include <algorithm>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <zlib.h>

#include "../common.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

// Stable codes; literal so scripts/gen_docs.py can catalogue them.
constexpr const char* kCodeUnsupportedCoder = "7z-unsupported-coder";
constexpr const char* kCodeFolderTooBig = "7z-folder-too-big";
constexpr const char* kCodeDecodeFailed = "7z-folder-decode-failed";
constexpr const char* kCodeCrcMismatch = "7z-crc-mismatch";
constexpr const char* kCodeBadEntry = "7z-bad-entry";
constexpr const char* kCodeFilterNotApplied = "7z-filter-not-applied";
constexpr const char* kCodeSinkError = "container-sink-error";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

/// 7z records Windows-style paths on archives made there; the Sink wants one
/// shape, and the rest of its safety checks do the rest.
std::string clean_path(std::string p) {
    std::replace(p.begin(), p.end(), '\\', '/');
    while (p.rfind("./", 0) == 0) p.erase(0, 2);
    while (!p.empty() && p.front() == '/') p.erase(0, 1);
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

std::uint32_t crc32_of(std::span<const std::uint8_t> d) {
    return static_cast<std::uint32_t>(::crc32(0UL, d.data(), static_cast<uInt>(d.size())));
}

}  // namespace

Status SevenZipReader::open(const Span& span) {
    span_ = span;
    opened_ = false;
    bad_crcs_ = skipped_folders_ = 0;
    if (span.empty()) return Status::fail("container-empty: no bytes at the container's start");
    if (const Status st = sevenzip::read_archive(span, 0, archive_); !st) return st;
    opened_ = true;
    return Status::success();
}

ContainerInfo SevenZipReader::info() const {
    ContainerInfo i;
    i.format = "7z";
    i.size = archive_.size;
    i.attrs["version"] =
        dec(archive_.version_major) + "." + dec(archive_.version_minor);
    i.attrs["header_encoded"] = archive_.header_was_encoded ? "true" : "false";
    i.attrs["folders"] = dec(archive_.streams.folders.size());
    i.attrs["entries"] = dec(archive_.files.size());

    std::vector<std::string> coders;
    for (const sevenzip::Folder& f : archive_.streams.folders) {
        for (const sevenzip::Coder& c : f.coders) {
            const std::string n = c.name();
            if (std::find(coders.begin(), coders.end(), n) == coders.end()) coders.push_back(n);
        }
    }
    std::sort(coders.begin(), coders.end());
    std::string list;
    for (const std::string& c : coders) {
        if (!list.empty()) list.push_back(',');
        list += c;
    }
    i.attrs["coders"] = list;
    if (!coders.empty()) i.compression = list;
    if (bad_crcs_ != 0) i.attrs["bad_crcs"] = dec(bad_crcs_);
    if (skipped_folders_ != 0) i.attrs["skipped_folders"] = dec(skipped_folders_);
    return i;
}

Status SevenZipReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");
    const sevenzip::StreamsInfo& si = archive_.streams;

    // A file with a stream takes the next substream, in file order; entries
    // without one are directories or empty files and take none.
    std::vector<std::size_t> with_stream;
    for (std::size_t i = 0; i < archive_.files.size(); ++i) {
        if (archive_.files[i].has_stream) with_stream.push_back(i);
    }
    if (with_stream.size() != si.substream_sizes.size()) {
        out.diagnostics.push_back(
            {Severity::Warning, kCodeBadEntry,
             dec(with_stream.size()) + " entr(ies) have a data stream but the archive describes " +
                 dec(si.substream_sizes.size()) +
                 "; only the entries both agree on are extracted"});
        out.truncated = true;
    }

    auto emit_meta = [&](const sevenzip::FileEntry& e, EntryKind kind, std::uint64_t size) {
        FileMeta m;
        m.path = clean_path(sanitize_utf8(e.name));
        m.kind = kind;
        m.size = size;
        const std::uint32_t mode = e.unix_mode();
        m.mode = mode != 0 ? mode : (kind == EntryKind::Directory ? 0755u : 0644u);
        if (e.has_mtime) m.mtime = static_cast<std::int64_t>(e.mtime);
        if (e.has_attributes) m.extra["win_attributes"] = dec(e.attributes);
        return m;
    };

    // Directories and empty files first: they own no bytes, so they do not
    // depend on any folder decoding.
    for (const sevenzip::FileEntry& e : archive_.files) {
        if (e.has_stream) continue;
        if (out.entries >= opts.limits.max_nodes_per_fs) break;
        FileMeta m = emit_meta(e, e.is_dir ? EntryKind::Directory : EntryKind::Regular, 0);
        if (m.path.empty()) continue;
        EntryResult r;
        if (e.is_dir) {
            if (const Status st = sink.entry(m, r); !st) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeSinkError, "'" + m.path + "': " + st.error});
                continue;
            }
        } else {
            if (const Status st = sink.begin_file(m); !st) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeSinkError, "'" + m.path + "': " + st.error});
                continue;
            }
            if (const Status st = sink.end_file(r); !st) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeSinkError, "'" + m.path + "': " + st.error});
                continue;
            }
        }
        count_entry(out, r);
        out.entries_out.push_back(std::move(r));
    }

    // Then folder by folder: decode once, slice into its substreams.
    std::vector<std::uint8_t> folder_data;
    std::string unfiltered_folder_;
    std::size_t substream = 0;
    std::uint64_t pack_at = sevenzip::kSignatureHeaderSize + si.pack_pos;
    for (std::size_t fi = 0; fi < si.folders.size(); ++fi) {
        const sevenzip::Folder& f = si.folders[fi];
        const std::uint64_t n = fi < si.substreams_per_folder.size()
                                    ? si.substreams_per_folder[fi]
                                    : 0;
        unfiltered_folder_.clear();
        // Where this folder's packed bytes start, and where the next one's do.
        std::uint64_t folder_pack = pack_at;
        for (std::size_t k = 0; k < f.packed.size(); ++k) {
            const std::size_t idx = static_cast<std::size_t>(f.first_pack_index) + k;
            if (idx < si.pack_sizes.size()) pack_at += si.pack_sizes[idx];
        }

        if (n == 0) continue;
        std::string why;
        const bool decodable = sevenzip::folder_decodable(f, &why);
        const bool too_big = f.unpacked_size() > opts.limits.max_file_bytes;
        std::string stored_filter;
        // A folder that stores its bytes and then only runs a byte filter
        // over them cannot go through liblzma -- a raw chain has to end in a
        // compressor -- but the bytes are all there, and a BCJ pass only
        // rewrites the relative jump targets in executable code. Handing
        // those over, labelled, beats handing over nothing.
        const bool filtered_store =
            !decodable && sevenzip::folder_is_filtered_store(f, &stored_filter);
        bool have_data = false;
        if (!opts.extract_data) {
            // Listing only: the sizes and names are in the header.
        } else if (filtered_store && !too_big) {
            const std::size_t idx = static_cast<std::size_t>(f.first_pack_index);
            const auto raw = idx < si.pack_sizes.size()
                                 ? span_.bytes(folder_pack, static_cast<std::size_t>(
                                                                si.pack_sizes[idx]))
                                 : std::nullopt;
            if (raw && raw->size() == f.unpacked_size()) {
                folder_data = *raw;
                have_data = true;
                unfiltered_folder_ = stored_filter;
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeFilterNotApplied,
                     "folder " + dec(fi) + " is stored with a " + stored_filter +
                         " filter over it, which needs a compressor under it to run through "
                         "liblzma; its " + dec(n) +
                         " entr(ies) are emitted with the filter still applied"});
                out.truncated = true;
            } else {
                ++skipped_folders_;
                out.truncated = true;
            }
        } else if (!decodable) {
            ++skipped_folders_;
            out.diagnostics.push_back(
                {Severity::Warning, kCodeUnsupportedCoder,
                 "folder " + dec(fi) + " uses " + why +
                     ", which this build does not decode; its " + dec(n) +
                     " entr(ies) are listed with no contents"});
            out.truncated = true;
        } else if (too_big) {
            ++skipped_folders_;
            out.diagnostics.push_back(
                {Severity::Warning, kCodeFolderTooBig,
                 "folder " + dec(fi) + " decodes to " + dec(f.unpacked_size()) +
                     " bytes, past max_file_bytes (" + dec(opts.limits.max_file_bytes) +
                     "); a 7z folder has to be decoded whole, so its " + dec(n) +
                     " entr(ies) are listed with no contents"});
            out.truncated = true;
        } else if (const Status st = sevenzip::decode_folder(span_, f, folder_pack, si.pack_sizes,
                                                             folder_data);
                   !st) {
            ++skipped_folders_;
            out.diagnostics.push_back({Severity::Warning, kCodeDecodeFailed,
                                       "folder " + dec(fi) + " did not decode (" + st.error +
                                           "); its " + dec(n) + " entr(ies) have no contents"});
            out.truncated = true;
        } else {
            have_data = true;
        }

        std::uint64_t at = 0;
        for (std::uint64_t k = 0; k < n; ++k, ++substream) {
            const std::string filter_note = unfiltered_folder_;
            if (out.entries >= opts.limits.max_nodes_per_fs) {
                out.diagnostics.push_back({Severity::Warning, "7z-limit-entries",
                                           "the entry limit (" +
                                               dec(opts.limits.max_nodes_per_fs) +
                                               ") stopped the walk"});
                out.truncated = true;
                return Status::success();
            }
            if (substream >= si.substream_sizes.size() || substream >= with_stream.size()) break;
            const std::uint64_t size = si.substream_sizes[substream];
            const sevenzip::FileEntry& e = archive_.files[with_stream[substream]];
            FileMeta m = emit_meta(e, EntryKind::Regular, size);
            if (m.path.empty()) {
                at += size;
                continue;
            }

            if (const Status st = sink.begin_file(m); !st) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeSinkError, "'" + m.path + "': " + st.error});
                at += size;
                continue;
            }
            bool bad_crc = false, short_data = false;
            if (have_data) {
                if (at + size > folder_data.size()) {
                    short_data = true;
                } else {
                    const std::span<const std::uint8_t> view(folder_data.data() + at,
                                                             static_cast<std::size_t>(size));
                    if (substream < si.substream_crc_defined.size() &&
                        si.substream_crc_defined[substream] &&
                        crc32_of(view) != si.substream_crcs[substream]) {
                        bad_crc = true;
                        ++bad_crcs_;
                    }
                    if (const Status st = sink.write(view); !st) {
                        out.diagnostics.push_back({Severity::Warning, kCodeSinkError,
                                                   "'" + m.path + "': " + st.error});
                    }
                }
            }
            at += size;

            EntryResult r;
            if (const Status st = sink.end_file(r); !st) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeSinkError, "'" + m.path + "': " + st.error});
                if (r.meta.path.empty()) continue;
            }
            if (bad_crc && filter_note.empty()) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeCrcMismatch,
                     "'" + m.path + "' does not match the CRC the archive stored for it; the "
                     "bytes are emitted as decoded"});
            }
            if (!have_data || short_data) r.truncated = true;
            if (!filter_note.empty()) {
                // The CRC is over the unfiltered bytes, so it cannot match
                // what was emitted; saying "mismatch" would blame the data.
                r.meta.extra["filter_not_applied"] = filter_note;
                r.meta.extra["crc"] = "unchecked";
                r.truncated = true;
            } else {
                r.meta.extra["crc"] = !have_data ? "unchecked"
                                      : bad_crc  ? "mismatch"
                                      : (substream < si.substream_crc_defined.size() &&
                                         si.substream_crc_defined[substream])
                                                 ? "ok"
                                                 : "none";
            }
            count_entry(out, r);
            out.entries_out.push_back(std::move(r));
        }
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("7z", SevenZipReader);

namespace detail {
void omnitrace_container_anchor_sevenzip() {}
}  // namespace detail

}  // namespace omnitrace::container
