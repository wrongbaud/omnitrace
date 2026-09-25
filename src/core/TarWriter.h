// TarWriter.h — a deterministic POSIX tar stream, written as entries arrive.
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "omnitrace/core/Node.h"
#include "omnitrace/core/Status.h"

namespace omnitrace::detail {

/// Writes a `ustar`/`pax` archive, one entry at a time, to a file.
///
/// It exists so a case can be *handed over*. An extracted tree carries
/// symlinks, permission bits that deny their own owner read, device nodes and
/// names that are not valid UTF-8; copy that onto exFAT, a Windows share or
/// cloud storage and every one of those is silently dropped. A tar is the only
/// container that survives the trip, and this writes it from the same entries
/// the DiskSink writes to disk, so it is faithful even on a host whose own
/// filesystem could not represent the tree.
///
/// **Deterministic.** Entries land in the order the reader emitted them, which
/// is already deterministic; nothing here reads a clock, invents an mtime, or
/// records a uname. Two runs over the same image produce byte-identical
/// archives.
///
/// The size of an entry is not known when its header must be written -- the
/// Sink protocol is `begin` then `write`* then `end` -- so the header goes out
/// with a placeholder and is rewritten in place once the data has been
/// counted. That needs a seekable file, which is what this always writes to.
class TarWriter {
   public:
    static Status open(const std::string& path, std::unique_ptr<TarWriter>& out);
    ~TarWriter();

    /// Start a regular file. `meta.size` is not trusted; what is written is.
    Status begin_file(const FileMeta& meta);
    Status write(std::span<const std::uint8_t> data);
    Status end_file();
    /// A directory, symlink, device, fifo or socket: header only, no data.
    Status entry(const FileMeta& meta);
    /// Two zero blocks and close. Called once; the destructor does it if not.
    Status finish();

   private:
    TarWriter() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace omnitrace::detail
