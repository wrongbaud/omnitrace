// Registry.cpp — link the built-in extractors in. See Artifact.h.
#include "omnitrace/artifacts/Artifact.h"

namespace omnitrace::artifacts::detail {

void omnitrace_extractor_anchor_certificates();
void omnitrace_extractor_anchor_kmodule();
void omnitrace_extractor_anchor_linux_kernel();

void link_builtin_extractors() {
    omnitrace_extractor_anchor_certificates();
    omnitrace_extractor_anchor_kmodule();
    omnitrace_extractor_anchor_linux_kernel();
}

}  // namespace omnitrace::artifacts::detail
