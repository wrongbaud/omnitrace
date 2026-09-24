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
    // A refused `begin_file` is the one failure with no entry behind it:
    // nothing was opened and nothing landed, so there is nothing to report but
    // the Status.
    if (Status st = sink.begin_file(meta); !st) return st;
    bool limited = false;
    if (opts.extract_data && len != 0) {
        std::vector<std::uint8_t> buf(
            static_cast<std::size_t>(std::min<std::uint64_t>(kCopyChunk, len)));
        std::uint64_t done = 0;
        while (done < len) {
            const std::size_t want =
                static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
            const std::size_t got =
                span.read(off + done, std::span<std::uint8_t>(buf.data(), want));
            if (got == 0) {
                short_read = true;
                break;
            }
            if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), got)); !st) {
                limited = true;
                break;
            }
            done += got;
            if (got < want) {
                short_read = true;
                break;
            }
        }
    }
    // A tripped Sink limit still closes the entry (Sink.h), and the bytes that
    // landed are on the disk whether or not the caller hears about it. So this
    // returns *success*: `out` names a real file, and a caller that treats a
    // failed Status as "skip this entry" -- which every one of them did --
    // leaves the case directory holding a file the listing does not mention.
    // The Sink has already attached its own `sink-limit-*` diagnostic to the
    // entry and set `truncated`, so nothing is lost by saying the entry
    // happened; `count_entry` carries the flag up to the WalkResult.
    const Status st = sink.end_file(out);
    if (limited) out.truncated = true;
    return st;
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
    if (r.truncated) out.truncated = true;
}

}  // namespace omnitrace::container
