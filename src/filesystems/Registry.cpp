// Registry.cpp — fs::FilesystemRegistry.
//
// Readers register themselves from a static object's constructor
// (OMNITRACE_REGISTER_FILESYSTEM). In a static library the linker drops that
// object file, and with it the registration, when nothing references it, so
// every reader also defines an empty anchor function and link_builtin_readers()
// below calls each one. Add a line here when you add a reader.
#include "omnitrace/filesystems/Filesystem.h"

#include <utility>

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_squashfs();
void omnitrace_fs_anchor_ext();
void omnitrace_fs_anchor_jffs2();
void omnitrace_fs_anchor_qnx6();
void omnitrace_fs_anchor_qnxifs();

void link_builtin_readers() {
    // Calling each (empty) anchor is enough to make the linker keep its object
    // file and therefore its registrar.
    omnitrace_fs_anchor_squashfs();
    omnitrace_fs_anchor_ext();
    omnitrace_fs_anchor_jffs2();
    omnitrace_fs_anchor_qnx6();
    omnitrace_fs_anchor_qnxifs();
}
}  // namespace detail

FilesystemRegistry& FilesystemRegistry::instance() {
    static FilesystemRegistry registry;
    detail::link_builtin_readers();
    return registry;
}

void FilesystemRegistry::add(const std::string& format, ReaderFactory f) {
    factories_[format] = std::move(f);
}

std::unique_ptr<FilesystemReader> FilesystemRegistry::create(const std::string& format) const {
    const auto it = factories_.find(format);
    if (it == factories_.end() || !it->second) return nullptr;
    return it->second();
}

std::vector<std::string> FilesystemRegistry::formats() const {
    std::vector<std::string> out;
    out.reserve(factories_.size());
    for (const auto& [name, factory] : factories_) out.push_back(name);
    return out;  // std::map keeps them sorted: deterministic
}

}  // namespace omnitrace::fs
