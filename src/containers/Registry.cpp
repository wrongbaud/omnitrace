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
void link_builtin_containers() {
    // No built-in container readers yet. Add anchor calls here as they land.
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
