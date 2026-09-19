// Sink.h — where extracted entries go.
//
// Filesystem and container readers never touch the host filesystem directly;
// they emit entries into a Sink. DiskSink writes them under a root directory
// with a safe path walk (no absolute paths, no "..", never follows a symlink)
// and hashes as it writes. ListingSink records metadata (and optional hashes)
// without writing anything. Both produce an EntryResult per entry so the
// caller can build File Nodes.
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

struct EntryResult {
    FileMeta meta;          // as given, path normalized
    Digests digests;        // regular files only (when hashing enabled)
    std::string host_path;  // DiskSink: where it landed; empty otherwise
    bool written = false;   // DiskSink: bytes landed on disk
    bool truncated = false; // a Limit stopped the data early
    std::vector<Diagnostic> diagnostics;
};

class Sink {
public:
    virtual ~Sink() = default;

    // Regular file protocol: begin -> write* -> end. Non-regular entries use
    // entry() alone. Returns a failed Status on refusal (unsafe path, limit hit);
    // readers record it and continue with the next entry.
    virtual Status begin_file(const FileMeta& meta) = 0;
    virtual Status write(std::span<const std::uint8_t> data) = 0;
    virtual Status end_file(EntryResult& out) = 0;
    // Directories, symlinks, devices, fifos, sockets.
    virtual Status entry(const FileMeta& meta, EntryResult& out) = 0;

    // Convenience for readers that already have the whole file in memory.
    Status file(const FileMeta& meta, std::span<const std::uint8_t> data, EntryResult& out);

    virtual const Limits& limits() const = 0;
    virtual std::uint64_t files_emitted() const = 0;
    virtual std::uint64_t bytes_emitted() const = 0;
};

// Superseded/deleted versions land under <root>/.omnitrace-versions/<path>/v<version>
// so the live tree stays a faithful copy of the filesystem.
class DiskSink final : public Sink {
public:
    struct Options {
        bool hash = true;
        bool preserve_times = true;   // set mtime on written files when known
        bool preserve_mode = true;    // chmod (never setuid/setgid/sticky)
        bool write_versions = true;   // superseded/deleted entries under .omnitrace-versions
        Limits limits;
    };
    static Status open(const std::string& root_dir, Options opts, std::unique_ptr<DiskSink>& out);
    ~DiskSink() override;

    Status begin_file(const FileMeta& meta) override;
    Status write(std::span<const std::uint8_t> data) override;
    Status end_file(EntryResult& out) override;
    Status entry(const FileMeta& meta, EntryResult& out) override;
    const Limits& limits() const override;
    std::uint64_t files_emitted() const override;
    std::uint64_t bytes_emitted() const override;
    const std::string& root() const;

private:
    DiskSink() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class ListingSink final : public Sink {
public:
    explicit ListingSink(bool hash = false, Limits limits = {});
    ~ListingSink() override;

    Status begin_file(const FileMeta& meta) override;
    Status write(std::span<const std::uint8_t> data) override;
    Status end_file(EntryResult& out) override;
    Status entry(const FileMeta& meta, EntryResult& out) override;
    const Limits& limits() const override;
    std::uint64_t files_emitted() const override;
    std::uint64_t bytes_emitted() const override;

    const std::vector<EntryResult>& entries() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Path normalization shared by all sinks. Returns false if the path is unsafe
// (absolute, contains "..", empty component, NUL, or (on Windows) a drive/UNC
// prefix or reserved device name). Output uses '/' separators, no leading '/'.
bool normalize_entry_path(const std::string& in, std::string& out, std::string* why = nullptr);

}  // namespace omnitrace
