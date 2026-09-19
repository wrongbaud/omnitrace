// Container.h — archives, compressed streams, and wrapper formats (tar, zip,
// cpio, gzip/xz/lz4/zstd, uImage, FIT, Android sparse/boot). Same shape as
// FilesystemReader: open over a Span, walk into a Sink. Single-payload wrappers
// (gzip, uImage) emit exactly one entry named by the format ("payload").
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::container {

using omnitrace::fs::WalkOptions;
using omnitrace::fs::WalkResult;

struct ContainerInfo {
    std::string format;
    std::uint64_t size = 0;  // bytes consumed from the Span (0 = unknown)
    std::string compression;
    std::map<std::string, std::string> attrs;
};

class ContainerReader {
   public:
    virtual ~ContainerReader() = default;
    virtual std::string format() const = 0;
    virtual Status open(const Span& span) = 0;
    virtual ContainerInfo info() const = 0;
    virtual Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) = 0;
};

using ReaderFactory = std::function<std::unique_ptr<ContainerReader>()>;

class ContainerRegistry {
   public:
    static ContainerRegistry& instance();
    void add(const std::string& format, ReaderFactory f);
    std::unique_ptr<ContainerReader> create(const std::string& format) const;
    std::vector<std::string> formats() const;

   private:
    std::map<std::string, ReaderFactory> factories_;
};

struct ContainerRegistrar {
    ContainerRegistrar(const char* format, ReaderFactory f) {
        ContainerRegistry::instance().add(format, std::move(f));
    }
};
#define OMNITRACE_REGISTER_CONTAINER(format, ReaderType)                                       \
    static ::omnitrace::container::ContainerRegistrar _omnitrace_container_##ReaderType {      \
        format, [] {                                                                           \
            return std::unique_ptr<::omnitrace::container::ContainerReader>(new ReaderType()); \
        }                                                                                      \
    }

}  // namespace omnitrace::container
