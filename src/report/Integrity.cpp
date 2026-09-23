// Integrity.cpp — re-hash the evidence a report stands on. See Document.h.
//
// A report is a claim about specific bytes: every offset in it means something
// only if the evidence is still the evidence. If the file has changed since
// the case was made, or is no longer where it was, the report describes bytes
// that are somewhere else now, and the only honest thing is to say so in the
// report itself rather than to fail quietly or not look.
#include <filesystem>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/report/Document.h"

namespace omnitrace::report {

namespace {
constexpr const char* kCodeMismatch = "report-integrity-mismatch";
constexpr const char* kCodeMissing = "report-evidence-missing";
constexpr const char* kCodeUnhashed = "report-evidence-unhashed";
}  // namespace

IntegrityResult verify_evidence(const std::vector<EvidenceRef>& refs) {
    IntegrityResult r;
    r.verified = !refs.empty();
    for (const EvidenceRef& e : refs) {
        const std::string label = e.label.empty() ? e.path : e.label;

        // Nothing recorded to check against. Not a failure -- an older case or
        // one made with hashing off -- but not a verification either.
        if (e.sha256.empty()) {
            r.verified = false;
            r.states.emplace_back(label, "no recorded hash");
            r.diagnostics.push_back({Severity::Info, kCodeUnhashed,
                                     "'" + label +
                                         "' has no recorded sha256, so the report cannot say "
                                         "whether the evidence is unchanged"});
            continue;
        }

        std::error_code ec;
        if (!std::filesystem::exists(e.path, ec)) {
            r.verified = false;
            r.states.emplace_back(label, "missing");
            r.diagnostics.push_back(
                {Severity::Warning, kCodeMissing,
                 "'" + e.path +
                     "' is not where the case recorded it, so nothing in this report could be "
                     "checked against the evidence it describes"});
            continue;
        }

        std::shared_ptr<MappedFile> file;
        if (const Status st = MappedFile::open(e.path, file); !st) {
            r.verified = false;
            r.states.emplace_back(label, "unreadable");
            r.diagnostics.push_back({Severity::Warning, kCodeMissing,
                                     "'" + e.path + "' could not be read: " + st.error});
            continue;
        }
        const Digests now = hash_span(Span::whole(file));
        if (now.sha256 == e.sha256) {
            r.states.emplace_back(label, "verified");
            continue;
        }
        r.verified = false;
        r.states.emplace_back(label, "MISMATCH");
        r.diagnostics.push_back(
            {Severity::Error, kCodeMismatch,
             "'" + e.path + "' no longer hashes to what the case recorded. Recorded " +
                 e.sha256.substr(0, 16) + "..., found " + now.sha256.substr(0, 16) +
                 "...; every offset in this report refers to the recorded bytes, not these"});
    }
    return r;
}

}  // namespace omnitrace::report
