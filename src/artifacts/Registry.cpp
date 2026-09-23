// Registry.cpp — link the built-in extractors in. See Artifact.h.
#include "omnitrace/artifacts/Artifact.h"

namespace omnitrace::artifacts::detail {

void omnitrace_extractor_anchor_certificates();

void link_builtin_extractors() {
    omnitrace_extractor_anchor_certificates();
}

}  // namespace omnitrace::artifacts::detail
