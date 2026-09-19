// Filesystem.h — the filesystem reader contract.
//
// A reader is constructed over a Span that starts at the filesystem's first byte
// (the scanner already found it). It exposes: probe (cheap header check),
// walk (emit every entry to a Sink), and optional history. Readers work entirely
// through Span and Sink: no host FS, no clock, no globals.
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

namespace omnitrace::fs {

struct WalkOptions {
    bool extract_data = true;  // false: metadata only (Sink still gets begin/end with no writes)
    bool history = false;      // emit superseded versions and deletion records
    Limits limits;
};

struct WalkResult {
    std::uint64_t entries = 0, files = 0, dirs = 0, symlinks = 0, others = 0;
    std::uint64_t superseded = 0, deleted = 0;
    std::uint64_t bytes = 0;
    bool truncated = false;  // a limit stopped the walk early
    std::vector<Diagnostic> diagnostics;
    std::vector<EntryResult> entries_out;  // every emitted entry, in emission order
};

struct FilesystemInfo {
    std::string format;
    std::string label;     // volume name if any
    std::uint64_t size = 0;  // bytes the filesystem claims to occupy
    std::uint32_t block_size = 0;
    std::string compression;
    Endian endian = Endian::Little;
    std::map<std::string, std::string> attrs;
};

class FilesystemReader {
public:
    virtual ~FilesystemReader() = default;
    virtual std::string format() const = 0;
    // Parse superblock/headers. Fails (with Status) if this is not a valid instance.
    virtual Status open(const Span& span) = 0;
    virtual FilesystemInfo info() const = 0;
    virtual Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) = 0;
};

using ReaderFactory = std::function<std::unique_ptr<FilesystemReader>()>;

class FilesystemRegistry {
public:
    static FilesystemRegistry& instance();
    void add(const std::string& format, ReaderFactory f);
    std::unique_ptr<FilesystemReader> create(const std::string& format) const;
    std::vector<std::string> formats() const;

private:
    std::map<std::string, ReaderFactory> factories_;
};

struct FilesystemRegistrar {
    FilesystemRegistrar(const char* format, ReaderFactory f) { FilesystemRegistry::instance().add(format, std::move(f)); }
};
#define OMNITRACE_REGISTER_FILESYSTEM(format, ReaderType)                       \
    static ::omnitrace::fs::FilesystemRegistrar _omnitrace_fs_##ReaderType{ \
        format, [] { return std::unique_ptr<::omnitrace::fs::FilesystemReader>(new ReaderType()); }}

}  // namespace omnitrace::fs
