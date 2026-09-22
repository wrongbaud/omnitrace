// Registry.cpp — link the built-in platform analyzers in.
//
// Same shape as the container and validator registries: each analyzer
// registers from a static object's constructor, and the linker drops that
// object file unless something references it. Calling the (empty) anchor is
// enough. Add a line here when you add an analyzer.
#include "omnitrace/analyzers/Platform.h"

namespace omnitrace::analyzers::detail {

void omnitrace_analyzer_anchor_linux();

void link_builtin_analyzers() {
    omnitrace_analyzer_anchor_linux();
}

}  // namespace omnitrace::analyzers::detail
