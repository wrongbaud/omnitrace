// common.h — helpers shared by the container readers.
//
// Everything here reads through Span accessors and writes through the Sink:
// no reader ever touches the host filesystem (docs/ARCHITECTURE.md rule 2).
#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// I/O buffer for streaming an entry out of a Span. Not a limit: the Sink's
/// `max_file_bytes` bounds the entry, this only bounds the copy.
inline constexpr std::size_t kCopyChunk = 1u << 20;

/// Stream `[off, off+len)` of `span` into `sink` as one entry.
///
/// The payload is never held in one piece, so a 2 GiB ramdisk costs one 1 MiB
/// buffer. A short read (the image is truncated under the section the header
/// promised) ends the entry where the data ends and reports `short_read`,
/// which the caller turns into its own diagnostic: the reader knows the entry
/// is incomplete, only the caller knows what to call it.
///
/// With `WalkOptions::extract_data` false the entry is announced and closed
/// without any write, so a listing still names it and its size.
inline Status emit_span_file(Sink& sink, const WalkOptions& opts, const FileMeta& meta,
                             const Span& span, std::uint64_t off, std::uint64_t len,
                             EntryResult& out, bool& short_read) {
    short_read = false;
    if (Status st = sink.begin_file(meta); !st) return st;
    if (opts.extract_data && len != 0) {
        std::vector<std::uint8_t> buf(
            static_cast<std::size_t>(std::min<std::uint64_t>(kCopyChunk, len)));
        std::uint64_t done = 0;
        while (done < len) {
            const std::size_t want =
                static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
            const std::size_t got = span.read(off + done, std::span<std::uint8_t>(buf.data(), want));
            if (got == 0) {
                short_read = true;
                break;
            }
            if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), got)); !st) {
                // A tripped Sink limit still closes the entry, so the listing
                // shows what was recovered (Sink.h).
                EntryResult partial;
                static_cast<void>(sink.end_file(partial));
                out = std::move(partial);
                out.truncated = true;
                return st;
            }
            done += got;
            if (got < want) {
                short_read = true;
                break;
            }
        }
    }
    return sink.end_file(out);
}

/// Count one emitted entry into `out`, by kind.
inline void count_entry(WalkResult& out, const EntryResult& r) {
    ++out.entries;
    switch (r.meta.kind) {
        case EntryKind::Regular:
            ++out.files;
            break;
        case EntryKind::Directory:
            ++out.dirs;
            break;
        case EntryKind::Symlink:
            ++out.symlinks;
            break;
        default:
            ++out.others;
            break;
    }
    out.bytes += r.digests.bytes != 0 ? r.digests.bytes : r.meta.size;
}

}  // namespace omnitrace::container
