// Container.h — archives, compressed streams, and wrapper formats (tar, zip,
// cpio, gzip/bzip2/xz/lzma/lz4/zstd, uImage, FIT, Android sparse/boot). Same
// shape as FilesystemReader: open over a Span, walk into a Sink. Single-payload
// wrappers (gzip, uImage) emit exactly one entry named by the format
// ("payload").
/// @file Container.h
/// @brief `container::ContainerReader`, the contract for archive, compressed
/// stream and wrapper readers, and its registry.
///
/// Readers are registered from src/containers/ and linked in by
/// `link_builtin_containers()` (src/containers/Registry.cpp); a Container node
/// whose format has none is an "unsupported" Coverage row from
/// `discovery::analyze`. The shape mirrors `fs::FilesystemReader`;
/// thread-safety rules are the same.
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

/// @namespace omnitrace::container
/// @brief Container readers and their registry.
namespace omnitrace::container {

using omnitrace::fs::WalkOptions;
using omnitrace::fs::WalkResult;

/// Header-level facts, available after `open()` succeeded.
struct ContainerInfo {
    std::string format;                        ///< Canonical format id.
    std::uint64_t size = 0;                    ///< Bytes consumed from the Span (0 = unknown).
    std::string compression;                   ///< Codec name, or empty.
    std::map<std::string, std::string> attrs;  ///< Format-specific.
};

/// A container reader: `open()` over the Span at the container's first byte,
/// then `walk()` every member into a Sink. Single-payload wrappers (gzip,
/// uImage) emit exactly one entry named "payload". Same rules as
/// `fs::FilesystemReader`: Span in, Sink out, no host FS, no throwing.
class ContainerReader {
   public:
    /// Virtual destructor for `unique_ptr<ContainerReader>`.
    virtual ~ContainerReader() = default;
    /// Canonical format id this reader handles.
    virtual std::string format() const = 0;
    /// Parse the header; fails when `span` is not a valid instance.
    virtual Status open(const Span& span) = 0;
    /// Facts from `open()`.
    virtual ContainerInfo info() const = 0;
    /// Emit every member into `sink` and fill `out`.
    virtual Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) = 0;
};

/// Makes a fresh reader.
using ReaderFactory = std::function<std::unique_ptr<ContainerReader>()>;

/// Format id -> reader factory; populated at static initialization by
/// `OMNITRACE_REGISTER_CONTAINER`, read-only afterwards.
class ContainerRegistry {
   public:
    /// The process-wide registry.
    static ContainerRegistry& instance();
    /// Register or replace `format`. Static-init time only; not synchronized.
    void add(const std::string& format, ReaderFactory f);
    /// A new reader for `format`, or `nullptr` when none is registered.
    std::unique_ptr<ContainerReader> create(const std::string& format) const;
    /// Every registered format id, sorted.
    std::vector<std::string> formats() const;

   private:
    std::map<std::string, ReaderFactory> factories_;
};

/// Constructing one registers `f` under `format` (see the macro below).
struct ContainerRegistrar {
    /// Registers immediately.
    ContainerRegistrar(const char* format, ReaderFactory f) {
        ContainerRegistry::instance().add(format, std::move(f));
    }
};
/// Register `ReaderType` under `format`. Also give the reader an anchor
/// function and call it from `link_builtin_containers()` in
/// src/containers/Registry.cpp so static linking keeps the registrar.
#define OMNITRACE_REGISTER_CONTAINER(format, ReaderType)                                       \
    static ::omnitrace::container::ContainerRegistrar _omnitrace_container_##ReaderType {      \
        format, [] {                                                                           \
            return std::unique_ptr<::omnitrace::container::ContainerReader>(new ReaderType()); \
        }                                                                                      \
    }

}  // namespace omnitrace::container
