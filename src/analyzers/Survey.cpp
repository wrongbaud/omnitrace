// Survey.cpp — run the analyzers over a finished case. See Platform.h.
#include <algorithm>
#include <map>

#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Text.h"
#include "omnitrace/output/Markdown.h"

namespace omnitrace::analyzers {

namespace {

constexpr const char* kCodeUnclaimed = "platform-unrecognised";

std::string yaml_quote(const std::string& s) {
    std::string out = "\"";
    for (const char c : s) {
        if (c == '"' || c == '\\')
            out += '\\';
        else if (c == '\n') {
            out += "\\n";
            continue;
        }
        out += c;
    }
    return out + "\"";
}

}  // namespace

AnalyzerRegistry& AnalyzerRegistry::instance() {
    static AnalyzerRegistry r;
    return r;
}

void AnalyzerRegistry::add(Platform p, AnalyzerFactory f) {
    factories_[p] = std::move(f);
}

std::vector<std::unique_ptr<Analyzer>> AnalyzerRegistry::all() const {
    std::vector<std::unique_ptr<Analyzer>> out;
    out.reserve(factories_.size());
    for (const auto& [p, f] : factories_) out.push_back(f());
    return out;
}

std::unique_ptr<Analyzer> AnalyzerRegistry::create(Platform p) const {
    const auto it = factories_.find(p);
    return it == factories_.end() ? nullptr : it->second();
}

Status survey(const FilesystemEntries& filesystems, Survey& out) {
    out = Survey{};
    detail::link_builtin_analyzers();
    const std::vector<std::unique_ptr<Analyzer>> analyzers = AnalyzerRegistry::instance().all();
    if (analyzers.empty()) return Status::success();

    for (const auto& [node_id, entries] : filesystems) {
        if (entries.empty()) continue;
        ++out.trees_examined;
        const Tree tree(entries);

        // Highest rank first, then highest score. Rank is what makes Android
        // beat Linux on an Android tree: a Linux analyzer matches one too, and
        // counting markers would not settle it.
        const Analyzer* best = nullptr;
        unsigned best_score = 0;
        for (const std::unique_ptr<Analyzer>& a : analyzers) {
            const unsigned score = a->detect(tree);
            if (score == 0) continue;
            if (best == nullptr || a->rank() > best->rank() ||
                (a->rank() == best->rank() && score > best_score)) {
                best = a.get();
                best_score = score;
            }
        }
        if (best == nullptr) {
            ++out.trees_unclaimed;
            continue;
        }

        Report r;
        r.node = node_id;
        r.platform = best->platform();
        r.score = best_score;
        best->describe(tree, r);
        if (r.evidence.empty())
            r.evidence = std::to_string(best_score) + " marker(s) over " +
                         std::to_string(tree.size()) + " live entries";
        out.reports.push_back(std::move(r));
    }

    if (out.trees_unclaimed != 0)
        out.diagnostics.push_back(
            {Severity::Info, kCodeUnclaimed,
             std::to_string(out.trees_unclaimed) +
                 " extracted filesystem(s) matched no platform model. That is a finding in "
                 "itself: a data partition has no platform, and a system this build does not "
                 "model is worth knowing about"});
    return Status::success();
}

std::string platform_to_yaml(const Survey& s) {
    std::string y = "schema: omnitrace-platform/1\n";
    y += "summary:\n";
    y += "  filesystems_examined: " + std::to_string(s.trees_examined) + "\n";
    y += "  filesystems_recognised: " + std::to_string(s.reports.size()) + "\n";
    y += "  filesystems_unrecognised: " + std::to_string(s.trees_unclaimed) + "\n";

    std::map<std::string, std::size_t> by_platform;
    for (const Report& r : s.reports) ++by_platform[platform_name(r.platform)];
    y += "  by_platform:\n";
    if (by_platform.empty()) y += "    {}\n";
    for (const auto& [k, v] : by_platform) y += "    " + k + ": " + std::to_string(v) + "\n";

    y += "diagnostics:\n";
    if (s.diagnostics.empty()) y += "  []\n";
    for (const Diagnostic& d : s.diagnostics) {
        y += "  - severity: " + std::string(severity_name(d.severity)) + "\n";
        y += "    code: " + d.code + "\n";
        y += "    message: " + yaml_quote(sanitize_utf8(d.message)) + "\n";
    }

    y += "filesystems:\n";
    if (s.reports.empty()) y += "  []\n";
    for (const Report& r : s.reports) {
        y += "  - node: " + r.node + "\n";
        y += "    platform: " + std::string(platform_name(r.platform)) + "\n";
        y += "    markers: " + std::to_string(r.score) + "\n";
        y += "    evidence: " + yaml_quote(sanitize_utf8(r.evidence)) + "\n";
        y += "    facts:\n";
        if (r.facts.empty()) y += "      []\n";
        for (const Fact& f : r.facts) {
            y += "      - key: " + f.key + "\n";
            y += "        value: " + yaml_quote(sanitize_utf8(f.value)) + "\n";
            y += "        source: " + yaml_quote(sanitize_utf8(f.source)) + "\n";
        }
        if (!r.diagnostics.empty()) {
            y += "    diagnostics:\n";
            for (const Diagnostic& d : r.diagnostics) {
                y += "      - severity: " + std::string(severity_name(d.severity)) + "\n";
                y += "        code: " + d.code + "\n";
                y += "        message: " + yaml_quote(sanitize_utf8(d.message)) + "\n";
            }
        }
    }
    return y;
}

std::string platform_to_markdown(const Survey& s) {
    std::string out = "# Platforms\n\n";
    out +=
        "What each extracted filesystem says about itself. Every line names the file it was "
        "read from, so it can be opened in this case directory and checked.\n\n";

    out += "| | |\n|---|---|\n";
    out += "| Filesystems examined | " + std::to_string(s.trees_examined) + " |\n";
    out += "| Recognised | " + std::to_string(s.reports.size()) + " |\n";
    out += "| Unrecognised | " + std::to_string(s.trees_unclaimed) + " |\n\n";

    if (s.reports.empty()) {
        out += "No extracted filesystem matched a platform model.\n";
        return out;
    }

    for (const Report& r : s.reports) {
        out += "## " + output::md_escape(r.node) + " — " +
               output::md_escape(platform_name(r.platform)) + "\n\n";
        out += output::md_escape(r.evidence) + "\n\n";
        std::vector<std::vector<std::string>> rows;
        rows.reserve(r.facts.size());
        for (const Fact& f : r.facts)
            rows.push_back({output::md_escape(f.key), output::md_escape(sanitize_utf8(f.value)),
                            output::md_escape(sanitize_utf8(f.source))});
        out += output::md_table({"Fact", "Value", "From"}, rows);
        for (const Diagnostic& d : r.diagnostics)
            out += "\n> **" + std::string(severity_name(d.severity)) + "** `" + d.code + "` — " +
                   output::md_escape(sanitize_utf8(d.message)) + "\n";
        out += "\n";
    }
    return out;
}

}  // namespace omnitrace::analyzers
