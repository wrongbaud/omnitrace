// Collect.cpp — run the extractors over a finished case. See Artifact.h.
#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <tuple>

#include "omnitrace/artifacts/Artifact.h"
#include "omnitrace/core/Text.h"
#include "omnitrace/output/Markdown.h"

namespace omnitrace::artifacts {

namespace {

constexpr const char* kCodeUnreadable = "artifact-file-unreadable";
constexpr const char* kCodeLimit = "artifact-limit-reached";

// The first bytes of a file, for the cheap `applies` screen. A path test needs
// none of the file at all, so this is only read when an extractor asks for it.
constexpr std::size_t kHeadBytes = 256;

bool read_capped(const std::string& path, std::uint64_t cap, std::vector<std::uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.clear();
    out.resize(static_cast<std::size_t>(cap));
    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(cap));
    out.resize(static_cast<std::size_t>(f.gcount()));
    return true;
}

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

ExtractorRegistry& ExtractorRegistry::instance() {
    static ExtractorRegistry r;
    return r;
}

void ExtractorRegistry::add(const std::string& name, ExtractorFactory f) {
    factories_[name] = std::move(f);
}

std::vector<std::unique_ptr<Extractor>> ExtractorRegistry::all() const {
    std::vector<std::unique_ptr<Extractor>> out;
    out.reserve(factories_.size());
    for (const auto& [n, f] : factories_) out.push_back(f());
    return out;
}

std::unique_ptr<Extractor> ExtractorRegistry::create(const std::string& name) const {
    const auto it = factories_.find(name);
    return it == factories_.end() ? nullptr : it->second();
}

Status collect(const FilesystemEntries& filesystems, const CollectLimits& limits, Collection& out) {
    out = Collection{};
    detail::link_builtin_extractors();
    const std::vector<std::unique_ptr<Extractor>> extractors = ExtractorRegistry::instance().all();
    if (extractors.empty()) return Status::success();

    std::vector<std::uint8_t> head, body;
    for (const auto& [node_id, entries] : filesystems) {
        for (const EntryResult& e : entries) {
            if (out.artifacts.size() >= limits.max_artifacts) break;
            if (e.meta.kind != EntryKind::Regular || e.host_path.empty() || !e.written) continue;
            // History is not the running system; a deleted file's contents are
            // recoverable evidence but belong to a different question.
            if (e.meta.deleted || e.meta.superseded) continue;

            // One read of the head serves every extractor's screen.
            bool have_head = false;
            for (const std::unique_ptr<Extractor>& x : extractors) {
                if (!have_head) {
                    if (!read_capped(e.host_path, kHeadBytes, head)) {
                        out.diagnostics.push_back(
                            {Severity::Warning, kCodeUnreadable,
                             "'" + sanitize_utf8(e.meta.path) +
                                 "' was extracted but could not be read back for artifact "
                                 "extraction"});
                        break;
                    }
                    have_head = true;
                }
                if (!x->applies(e.meta.path, head)) continue;
                if (!read_capped(e.host_path, limits.max_bytes_per_file, body)) continue;
                ++out.files_examined;

                Yield y;
                x->extract(FileRef{node_id, e.meta.path, body}, y);
                out.summarised += y.summarised;
                for (Diagnostic& d : y.diagnostics) out.diagnostics.push_back(std::move(d));
                for (Artifact& a : y.artifacts) out.artifacts.push_back(std::move(a));
            }
        }
    }

    if (out.artifacts.size() >= limits.max_artifacts) {
        out.truncated = true;
        out.artifacts.resize(static_cast<std::size_t>(limits.max_artifacts));
        out.diagnostics.push_back({Severity::Warning, kCodeLimit,
                                   "the extractors reached max_artifacts (" +
                                       std::to_string(limits.max_artifacts) + ") and stopped"});
    }

    // Records that describe the same thing are merged. An extractor that
    // summarises -- a CA trust store, a log directory -- emits one record per
    // file it saw, keyed on the thing rather than the file, and they add up
    // here: a numeric field sums, anything else keeps the first value. Without
    // this the corpus router's trust store is 127 rows that each say "one CA
    // certificate".
    const auto all_digits = [](const std::string& v) {
        return !v.empty() && std::all_of(v.begin(), v.end(),
                                         [](unsigned char c) { return std::isdigit(c) != 0; });
    };
    std::map<std::tuple<std::string, std::string, std::string>, std::size_t> seen;
    std::vector<Artifact> merged;
    merged.reserve(out.artifacts.size());
    for (Artifact& a : out.artifacts) {
        const auto key = std::make_tuple(a.kind, a.node, a.path);
        const auto it = seen.find(key);
        if (it == seen.end()) {
            seen.emplace(key, merged.size());
            merged.push_back(std::move(a));
            continue;
        }
        Artifact& into = merged[it->second];
        for (const auto& [k, v] : a.fields) {
            const auto f = into.fields.find(k);
            if (f == into.fields.end()) {
                into.fields[k] = v;
            } else if (all_digits(f->second) && all_digits(v)) {
                f->second = std::to_string(std::stoull(f->second) + std::stoull(v));
            }
        }
        if (a.severity > into.severity) into.severity = a.severity;
    }
    out.artifacts = std::move(merged);

    // Deterministic: by kind, then where it was found.
    std::stable_sort(out.artifacts.begin(), out.artifacts.end(),
                     [](const Artifact& a, const Artifact& b) {
                         if (a.kind != b.kind) return a.kind < b.kind;
                         if (a.node != b.node) return a.node < b.node;
                         return a.path < b.path;
                     });
    return Status::success();
}

std::string to_yaml(const Collection& c) {
    std::string y = "schema: omnitrace-artifacts-extracted/1\n";
    y += "summary:\n";
    y += "  records: " + std::to_string(c.artifacts.size()) + "\n";
    y += "  files_examined: " + std::to_string(c.files_examined) + "\n";
    y += "  summarised: " + std::to_string(c.summarised) + "\n";
    y += std::string("  truncated: ") + (c.truncated ? "true" : "false") + "\n";

    std::map<std::string, std::size_t> by_kind;
    for (const Artifact& a : c.artifacts) ++by_kind[a.kind];
    y += "  by_kind:\n";
    if (by_kind.empty()) y += "    {}\n";
    for (const auto& [k, n] : by_kind) y += "    " + k + ": " + std::to_string(n) + "\n";

    y += "diagnostics:\n";
    if (c.diagnostics.empty()) y += "  []\n";
    for (const Diagnostic& d : c.diagnostics) {
        y += "  - severity: " + std::string(severity_name(d.severity)) + "\n";
        y += "    code: " + d.code + "\n";
        y += "    message: " + yaml_quote(sanitize_utf8(d.message)) + "\n";
    }

    y += "records:\n";
    if (c.artifacts.empty()) y += "  []\n";
    for (const Artifact& a : c.artifacts) {
        y += "  - kind: " + a.kind + "\n";
        y += "    node: " + a.node + "\n";
        y += "    path: " + yaml_quote(sanitize_utf8(a.path)) + "\n";
        y += "    severity: " + std::string(severity_name(a.severity)) + "\n";
        y += "    fields:\n";
        if (a.fields.empty()) y += "      {}\n";
        for (const auto& [k, v] : a.fields)
            y += "      " + k + ": " + yaml_quote(sanitize_utf8(v)) + "\n";
    }
    return y;
}

std::string to_markdown(const Collection& c) {
    std::string out = "# Extracted artifacts\n\n";
    out +=
        "Files the extractors recognised and parsed. A search pack can say a certificate is "
        "present; only a parser can say what it is for and when it stops being valid.\n\n";
    out += "| | |\n|---|---|\n";
    out += "| Records | " + std::to_string(c.artifacts.size()) + " |\n";
    out += "| Files parsed | " + std::to_string(c.files_examined) + " |\n";
    out += "| Records summarised rather than listed | " + std::to_string(c.summarised) + " |\n";
    if (c.truncated) out += "| Truncated | a cap stopped the run |\n";
    out += "\n";

    std::map<std::string, std::vector<const Artifact*>> by_kind;
    for (const Artifact& a : c.artifacts) by_kind[a.kind].push_back(&a);
    if (by_kind.empty()) {
        out += "No file matched an extractor.\n";
        return out;
    }

    constexpr std::size_t kPerKind = 40;
    for (const auto& [kind, list] : by_kind) {
        out += "## " + output::md_escape(kind) + " (" + std::to_string(list.size()) + ")\n\n";
        // Every field any record of this kind carries, so the table is square.
        std::vector<std::string> cols;
        for (const Artifact* a : list)
            for (const auto& [k, v] : a->fields)
                if (std::find(cols.begin(), cols.end(), k) == cols.end()) cols.push_back(k);
        std::sort(cols.begin(), cols.end());

        std::vector<std::string> header{"Where"};
        for (const std::string& k : cols) header.push_back(k);
        std::vector<std::vector<std::string>> rows;
        for (std::size_t i = 0; i < list.size() && i < kPerKind; ++i) {
            std::vector<std::string> row{output::md_escape(sanitize_utf8(list[i]->path))};
            for (const std::string& k : cols) {
                const auto it = list[i]->fields.find(k);
                row.push_back(it == list[i]->fields.end()
                                  ? ""
                                  : output::md_escape(sanitize_utf8(it->second)));
            }
            rows.push_back(std::move(row));
        }
        out += output::md_table(header, rows);
        if (list.size() > kPerKind)
            out +=
                "\n" + std::to_string(list.size() - kPerKind) + " more in `certificates.yaml`.\n";
        out += "\n";
    }

    for (const Diagnostic& d : c.diagnostics) {
        if (d.severity == Severity::Info) continue;
        out += "> **" + std::string(severity_name(d.severity)) + "** `" + d.code + "` — " +
               output::md_escape(sanitize_utf8(d.message)) + "\n\n";
    }
    return out;
}

}  // namespace omnitrace::artifacts
