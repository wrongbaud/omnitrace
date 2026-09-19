// Filesystem.h — the filesystem reader contract.
//
// A reader is constructed over a Span that starts at the filesystem's first byte
// (the scanner already found it). It exposes: probe (cheap header check),
// walk (emit every entry to a Sink), and optional history. Readers work entirely
// through Span and Sink: no host FS, no clock, no globals.
/// @file Filesystem.h
/// @brief `fs::FilesystemReader`, the contract every filesystem reader
/// implements, with its options, results and the `FilesystemRegistry`.
///
/// Registered readers today: "squashfs" (src/filesystems/squashfs/). Adding
/// one is the recipe in docs/ARCHITECTURE.md "Adding a filesystem reader".
/// Thread-safety: the registry is populated at static initialization by
/// `OMNITRACE_REGISTER_FILESYSTEM` and read-only afterwards; a reader
/// instance is single-threaded.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Limits.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/core/Status.h"

/// @namespace omnitrace::fs
/// @brief Filesystem readers (SquashFS today) and their registry.
namespace omnitrace::fs {

/// How to walk.
struct WalkOptions {
    bool extract_data =
        true;  ///< false: metadata only (the Sink still gets begin/end with no writes).
    bool history =
        false;      ///< Emit superseded versions and deletion records when the format keeps them.
    Limits limits;  ///< Reader-side caps (`max_nodes_per_fs`, ...); the Sink has its own copy.
};

/// What a walk produced. Counts cover every emitted entry.
struct WalkResult {
    std::uint64_t entries = 0, files = 0, dirs = 0, symlinks = 0,
                  others = 0;  ///< Emitted entries by kind.
    std::uint64_t superseded = 0,
                  deleted = 0;  ///< Historical entries emitted (with `WalkOptions::history`).
    std::uint64_t bytes = 0;    ///< Bytes handed to the Sink.
    bool truncated = false;     ///< A limit stopped the walk early.
    std::vector<Diagnostic> diagnostics;   ///< Walk-level caveats ("squashfs-limit-nodes", ...).
    std::vector<EntryResult> entries_out;  ///< Every emitted entry, in emission order.
};

/// Superblock-level facts, available after `open()` succeeded.
struct FilesystemInfo {
    std::string format;              ///< Canonical format id ("squashfs").
    std::string label;               ///< Volume name if any.
    std::uint64_t size = 0;          ///< Bytes the filesystem claims to occupy.
    std::uint32_t block_size = 0;    ///< Data block size.
    std::string compression;         ///< Codec name, or empty.
    Endian endian = Endian::Little;  ///< Byte order of the on-disk structures.
    std::map<std::string, std::string>
        attrs;  ///< Format-specific (version, flags, ...); copied onto the Node.
};

/// A filesystem reader. Construct (via the registry), `open()` over the Span
/// that starts at the filesystem's first byte, then `info()` and `walk()`.
///
/// Rules: read evidence only through `span` accessors; emit only through the
/// Sink; never touch the host filesystem or the clock; never throw on bad
/// input. `open()` fails with a Status for anything that is not a valid
/// instance; `walk()` records per-entry problems as Diagnostics and keeps
/// going, returning a failed Status only when nothing useful can be done.
///
/// ```cpp
/// auto reader = omnitrace::fs::FilesystemRegistry::instance().create("squashfs");
/// if (!reader) { /* Coverage row: unsupported */ }
/// if (auto st = reader->open(fs_span); !st) { /* not a valid instance */ }
/// std::unique_ptr<omnitrace::DiskSink> sink;
/// omnitrace::DiskSink::open("case/filesystems/n000004/files", {}, sink);
/// omnitrace::fs::WalkResult result;
/// omnitrace::Status st = reader->walk(*sink, {}, result);
/// // result.entries_out -> File nodes and listing.yaml; result.truncated -> "partial" coverage
/// ```
class FilesystemReader {
   public:
    /// Virtual destructor for `unique_ptr<FilesystemReader>`.
    virtual ~FilesystemReader() = default;
    /// Canonical format id this reader handles.
    virtual std::string format() const = 0;
    // Parse superblock/headers. Fails (with Status) if this is not a valid instance.
    /// Parse the superblock and headers. Fails, with a stable code in
    /// `Status::error`, when `span` is not a valid instance. Must be called
    /// before `info()` or `walk()`.
    virtual Status open(const Span& span) = 0;
    /// Facts from `open()`.
    virtual FilesystemInfo info() const = 0;
    /// Emit every entry into `sink` and fill `out`. Per-entry Sink refusals
    /// become Diagnostics on that entry; a tripped limit sets `out.truncated`.
    virtual Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) = 0;
};

/// Makes a fresh reader.
using ReaderFactory = std::function<std::unique_ptr<FilesystemReader>()>;

/// Format id -> reader factory. `instance()` force-links the built-in readers
/// (src/filesystems/Registry.cpp) so static linking keeps their registrars.
class FilesystemRegistry {
   public:
    /// The process-wide registry.
    static FilesystemRegistry& instance();
    /// Register or replace `format`. Static-init time only; not synchronized.
    void add(const std::string& format, ReaderFactory f);
    /// A new reader for `format`, or `nullptr` when none is registered.
    std::unique_ptr<FilesystemReader> create(const std::string& format) const;
    /// Every registered format id, sorted.
    std::vector<std::string> formats() const;

   private:
    std::map<std::string, ReaderFactory> factories_;
};

/// Constructing one registers `f` under `format` (see the macro below).
struct FilesystemRegistrar {
    /// Registers immediately.
    FilesystemRegistrar(const char* format, ReaderFactory f) {
        FilesystemRegistry::instance().add(format, std::move(f));
    }
};
/// Register `ReaderType` (default-constructible, derived from
/// `FilesystemReader`) under `format`. Put it at namespace scope in the
/// reader's .cpp and add the reader's anchor to src/filesystems/Registry.cpp.
#define OMNITRACE_REGISTER_FILESYSTEM(format, ReaderType)                                       \
    static ::omnitrace::fs::FilesystemRegistrar _omnitrace_fs_##ReaderType {                    \
        format,                                                                                 \
            [] { return std::unique_ptr<::omnitrace::fs::FilesystemReader>(new ReaderType()); } \
    }

}  // namespace omnitrace::fs
