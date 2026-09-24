// Sink.h — where extracted entries go.
//
// Filesystem and container readers never touch the host filesystem directly;
// they emit entries into a Sink. DiskSink writes them under a root directory
// with a safe path walk (no absolute paths, no "..", never follows a symlink)
// and hashes as it writes. ListingSink records metadata (and optional hashes)
// without writing anything. Both produce an EntryResult per entry so the
// caller can build File Nodes.
/// @file Sink.h
/// @brief `Sink`, the only way a reader emits an entry (docs/ARCHITECTURE.md
/// rule 2), its two implementations `DiskSink` and `ListingSink`, the
/// `EntryResult` they return, and `normalize_entry_path`.
///
/// Error behaviour: every method returns a `Status` whose `error` starts with
/// a stable code. Codes a reader will meet: `sink-unsafe-path`,
/// `sink-limit-files`, `sink-limit-file-bytes`, `sink-limit-bytes`,
/// `sink-io-error`, `sink-symlink-component`, `sink-not-directory`,
/// `sink-duplicate-path`, `sink-protocol` (calls out of order),
/// `sink-root-invalid` (DiskSink::open). A refusal applies to that entry only:
/// the reader records the Status as a Diagnostic and continues with the next
/// entry. Diagnostics the sink attaches to an EntryResult: `sink-duplicate-path`,
/// `sink-version-skipped`, `sink-special-skipped`, `sink-symlink-unsupported`,
/// `sink-limit-file-bytes`, `sink-limit-bytes`, `sink-io-error`.
///
/// Thread-safety: none. A Sink has one in-flight file and is driven by one
/// reader at a time.
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Limits.h"
#include "omnitrace/core/Node.h"
#include "omnitrace/core/Status.h"

namespace omnitrace {

/// What the Sink did with one entry. Readers copy these into `WalkResult::entries_out`;
/// `discovery::analyze` turns them into File nodes and `output::listing_to_yaml`
/// writes them.
struct EntryResult {
    FileMeta
        meta;  ///< As given by the reader, with `path` normalized ('/' separators, no leading '/').
    Digests digests;  ///< Regular files only, when hashing is enabled; `bytes` is what was actually
                      ///< received.
    std::string host_path;  ///< DiskSink: where it landed (root + placement path); empty otherwise.
    bool written = false;   ///< DiskSink: bytes or the directory/symlink landed on disk.
    bool truncated = false;               ///< A Limit stopped the data early.
    std::vector<Diagnostic> diagnostics;  ///< Sink caveats for this entry (see the file comment).
};

/// Destination for extracted entries. Readers see only this interface.
///
/// **A truncated entry is still an entry.** Only `begin_file` can refuse an
/// entry outright; once it succeeds, bytes may already have landed on disk, so
/// a limit tripping mid-`write` is not a reason to skip the entry. Break out
/// of the write loop, always call `end_file`, and push the `EntryResult`: it
/// carries the digests of what was recovered, `truncated`, and the
/// `sink-limit-*` diagnostic naming the cap. Dropping it leaves the case
/// directory holding a file the listing never names, which is the one thing a
/// forensic output may not do.
///
/// Protocol for a regular file: `begin_file` -> `write`* -> `end_file`.
/// Non-regular entries (directories, symlinks, devices, fifos, sockets) go
/// through `entry()` alone; a Regular kind passed to `entry()` is an empty
/// file. Only one file may be open at a time (`sink-protocol` otherwise).
/// When a `write` trips a limit it returns a failed Status and drops the rest
/// of that entry, but `end_file` still succeeds and returns the truncated
/// EntryResult, so the listing shows what was recovered.
///
/// ```cpp
/// omnitrace::FileMeta meta;
/// meta.path = "etc/passwd";
/// meta.mode = 0644;
/// meta.mtime = 1700000000;
/// omnitrace::EntryResult r;
/// if (omnitrace::Status st = sink.begin_file(meta); !st) { record(st); return; }
/// for (const auto& block : blocks) {
///     if (omnitrace::Status st = sink.write(block); !st) break;  // limit hit; end_file still runs
/// }
/// if (sink.end_file(r)) out.entries_out.push_back(r);            // r.digests, r.truncated,
/// r.host_path
/// ```
class Sink {
   public:
    /// Virtual destructor for owning pointers.
    virtual ~Sink() = default;

    // Regular file protocol: begin -> write* -> end. Non-regular entries use
    // entry() alone. Returns a failed Status on refusal (unsafe path, limit hit);
    // readers record it and continue with the next entry.
    /// Open a regular file. Fails with `sink-unsafe-path`, `sink-limit-files`,
    /// `sink-protocol` (a file is already open) or an I/O code; on failure no
    /// file is open and `end_file` must not be called.
    virtual Status begin_file(const FileMeta& meta) = 0;
    /// Append data to the open file. Fails with `sink-limit-file-bytes` /
    /// `sink-limit-bytes` (the allowed prefix was kept, `truncated` set) or
    /// `sink-io-error`; a later `write` on a truncated entry fails again.
    virtual Status write(std::span<const std::uint8_t> data) = 0;
    /// Close the open file and fill `out` (digests, host_path, truncated,
    /// diagnostics). Succeeds even after a limit tripped.
    virtual Status end_file(EntryResult& out) = 0;
    // Directories, symlinks, devices, fifos, sockets.
    /// Emit a non-regular entry (directories, symlinks, devices, fifos,
    /// sockets). Same refusals as `begin_file`.
    virtual Status entry(const FileMeta& meta, EntryResult& out) = 0;

    // Convenience for readers that already have the whole file in memory.
    /// `begin_file` + `write` + `end_file` for a file already in memory.
    /// Fails only when `begin_file` or `end_file` does -- a `write` that trips
    /// a byte limit does **not** fail the call, because the prefix it accepted
    /// is already on the disk and the caller has to record it (see the
    /// truncation rule above). Read `out.truncated` and `out.diagnostics`.
    Status file(const FileMeta& meta, std::span<const std::uint8_t> data, EntryResult& out);

    /// The Limits this sink enforces; readers use the same object for their own caps.
    virtual const Limits& limits() const = 0;
    /// Entries accepted so far (files, directories, symlinks and recorded specials).
    virtual std::uint64_t files_emitted() const = 0;
    /// Bytes accepted so far (DiskSink: bytes landed on disk; ListingSink: bytes seen).
    virtual std::uint64_t bytes_emitted() const = 0;
};

// Superseded/deleted versions land under <root>/.omnitrace-versions/<path>/v<version>
// so the live tree stays a faithful copy of the filesystem.
/// Writes entries under a root directory with a safe path walk. This is one of
/// the three files allowed to touch the host OS (docs/ARCHITECTURE.md rule 8).
///
/// What "safe" means here: every path goes through `normalize_entry_path`;
/// directories are entered with `O_NOFOLLOW` (a reparse-point check on
/// Windows) so a symlink planted by an earlier entry is never crossed; files
/// are created `O_EXCL`, and a name that already exists is written as
/// `name~1`, `name~2`, ... with a `sink-duplicate-path` warning; symlink
/// targets are stored verbatim and never resolved; devices, fifos and sockets
/// are recorded but not created (`sink-special-skipped`); mode is applied as
/// permission bits only, never setuid/setgid/sticky, and directories keep
/// owner rwx. Superseded and deleted versions land under
/// `<root>/.omnitrace-versions/<path>/v<version>` so the live tree stays a
/// faithful copy of what the filesystem currently shows.
class DiskSink final : public Sink {
   public:
    /// Behaviour switches for `open()`.
    struct Options {
        bool hash = true;  ///< Compute MD5/SHA-1/SHA-256 while writing.
        bool preserve_times =
            true;  ///< Set mtime on written files and symlinks when known (never on directories).
        bool preserve_mode = true;  ///< chmod permission bits (never setuid/setgid/sticky).
        bool write_versions =
            true;  ///< Write superseded/deleted entries under `.omnitrace-versions`; false records
                   ///< them (hashed, counted) without writing.
        Limits limits;  ///< Caps enforced by this sink.
    };
    /// Create the sink over `root_dir`, creating that one directory if it is
    /// missing (parents must exist). Fails with `sink-root-invalid`.
    static Status open(const std::string& root_dir, Options opts, std::unique_ptr<DiskSink>& out);
    /// Closes any still-open file and the root directory handle.
    ~DiskSink() override;

    Status begin_file(const FileMeta& meta) override;
    Status write(std::span<const std::uint8_t> data) override;
    Status end_file(EntryResult& out) override;
    Status entry(const FileMeta& meta, EntryResult& out) override;
    const Limits& limits() const override;
    std::uint64_t files_emitted() const override;
    std::uint64_t bytes_emitted() const override;
    /// The root directory as given to `open()`.
    const std::string& root() const;

   private:
    DiskSink() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Records every entry in memory and writes nothing. Used for `--no-extract`
/// and in reader tests. `EntryResult::written` is always false and
/// `host_path` empty; data is still counted against Limits and hashed when
/// `hash` is set.
class ListingSink final : public Sink {
   public:
    /// @param hash compute digests of regular-file data as it streams past.
    /// @param limits caps to enforce (defaults from `Limits`).
    explicit ListingSink(bool hash = false, Limits limits = {});
    ~ListingSink() override;

    Status begin_file(const FileMeta& meta) override;
    Status write(std::span<const std::uint8_t> data) override;
    Status end_file(EntryResult& out) override;
    Status entry(const FileMeta& meta, EntryResult& out) override;
    const Limits& limits() const override;
    std::uint64_t files_emitted() const override;
    std::uint64_t bytes_emitted() const override;

    /// Every accepted entry in emission order.
    const std::vector<EntryResult>& entries() const;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Path normalization shared by all sinks. Returns false if the path is unsafe
// (absolute, contains "..", empty component, NUL, or (on Windows) a drive/UNC
// prefix or reserved device name). Output uses '/' separators, no leading '/'.
/// Normalize an entry path the way every Sink does. Both '/' and '\\' are
/// separators; "." components and empty components are dropped.
/// @return false, with `why` set when given, for an absolute path, a ".."
/// component, a NUL byte, an empty result, a drive prefix ("C:") anywhere, or
/// a Windows reserved device name (CON, NUL, COM1, ...) in any component. The
/// Windows rules apply on every host so a listing is portable.
bool normalize_entry_path(const std::string& in, std::string& out, std::string* why = nullptr);

}  // namespace omnitrace
