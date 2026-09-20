// Registry.cpp — container::ContainerRegistry.
//
// Same shape as fs::FilesystemRegistry. Container readers register from a
// static object's constructor (OMNITRACE_REGISTER_CONTAINER); when the first
// reader lands, give it an anchor function and call it from
// link_builtin_containers() so static linking keeps the registrar.
#include "omnitrace/containers/Container.h"

#include <utility>

namespace omnitrace::container {

namespace detail {
void omnitrace_container_anchor_stream();
void omnitrace_container_anchor_uimage();
void omnitrace_container_anchor_androidboot();
void omnitrace_container_anchor_cpio();
void omnitrace_container_anchor_tar();
void omnitrace_container_anchor_zip();
void omnitrace_container_anchor_sparse();
void omnitrace_container_anchor_fit();
void omnitrace_container_anchor_ubi();
void omnitrace_container_anchor_lzop();
void omnitrace_container_anchor_sevenzip();

void link_builtin_containers() {
    // Calling each (empty) anchor is enough to make the linker keep its object
    // file and therefore its registrar. Add a line here per reader.
    omnitrace_container_anchor_stream();
    omnitrace_container_anchor_uimage();
    omnitrace_container_anchor_androidboot();
    omnitrace_container_anchor_cpio();
    omnitrace_container_anchor_tar();
    omnitrace_container_anchor_zip();
    omnitrace_container_anchor_sparse();
    omnitrace_container_anchor_fit();
    omnitrace_container_anchor_ubi();
    omnitrace_container_anchor_lzop();
    omnitrace_container_anchor_sevenzip();
}
}  // namespace detail

ContainerRegistry& ContainerRegistry::instance() {
    static ContainerRegistry registry;
    detail::link_builtin_containers();
    return registry;
}

void ContainerRegistry::add(const std::string& format, ReaderFactory f) {
    factories_[format] = std::move(f);
}

std::unique_ptr<ContainerReader> ContainerRegistry::create(const std::string& format) const {
    const auto it = factories_.find(format);
    if (it == factories_.end() || !it->second) return nullptr;
    return it->second();
}

std::vector<std::string> ContainerRegistry::formats() const {
    std::vector<std::string> out;
    out.reserve(factories_.size());
    for (const auto& [name, factory] : factories_) out.push_back(name);
    return out;
}

}  // namespace omnitrace::container
