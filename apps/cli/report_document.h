// report_document.h — build a report::Document from a finished case.
#pragma once
#include <string>

#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/artifacts/Artifact.h"
#include "omnitrace/core/Manifest.h"
#include "omnitrace/report/Document.h"
#include "omnitrace/rules/Sweep.h"

namespace omnitrace::cli {

/// Assemble a report. Every input but the Manifest is optional: `omnitrace
/// report` on a case directory rebuilds what the manifest holds, and the
/// platform, artifact and search sections are left out entirely when that data
/// was not produced. A missing section says less than an empty one claiming
/// nothing was found.
report::Document build_report(const Manifest& m, const report::IntegrityResult* integrity,
                              const analyzers::Survey* survey,
                              const artifacts::Collection* extracted,
                              const rules::SweepResult* hits, const std::string& case_name);

}  // namespace omnitrace::cli
