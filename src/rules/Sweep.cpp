// Sweep.cpp — run the rules over a finished case and render what they found.
#include "omnitrace/rules/Sweep.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <vector>

#include "omnitrace/core/Text.h"
#include "omnitrace/output/Markdown.h"

namespace omnitrace::rules {

namespace {

constexpr const char* kCodeUnreadable = "rules-file-unreadable";
constexpr const char* kCodeLimitHits = "rules-limit-hits";
constexpr const char* kCodeNoImageView = "rules-no-image-view";

// A file is read whole, up to the per-item cap. Reading it twice (once for
// the path rules, once for the content ones) would double the I/O over tens of
// thousands of entries, so the path rules run off the entry's metadata and
// only the content rules touch the disk.
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

Status sweep(const Engine& engine, const Manifest& m, const discovery::Listings& listings,
             const Span& image, const ScanLimits& limits, SweepResult& out) {
    out = SweepResult{};
    if (engine.content_rules() == 0 && engine.path_rules() == 0) return Status::success();

    std::vector<std::uint8_t> buf;
    std::vector<Hit> hits;

    // ---------------------------------------------------------- extracted files
    for (const auto& [node_id, entries] : listings) {
        for (const EntryResult& e : entries) {
            if (out.hits.size() >= limits.max_hits_total) break;

            // Path rules first: they cost nothing and apply even when the
            // entry's bytes were never written (--no-extract, a limit).
            hits.clear();
            engine.scan_path(e.meta.path, hits);
            for (Hit& h : hits)
                out.hits.push_back(ArtifactHit{node_id, e.meta.path, e.host_path, std::move(h)});

            if (e.meta.kind != EntryKind::Regular || e.host_path.empty() || !e.written) continue;
            if (!read_capped(e.host_path, limits.max_bytes_per_item, buf)) {
                out.diagnostics.push_back({omnitrace::Severity::Warning, kCodeUnreadable,
                                           "'" + sanitize_utf8(e.meta.path) +
                                               "' could not be read back for rule "
                                               "matching; it was extracted but is not searchable"});
                continue;
            }
            if (buf.empty()) continue;
            ++out.files_scanned;
            out.bytes_scanned += buf.size();

            hits.clear();
            engine.scan_bytes(buf, /*in_files=*/true, limits, hits);
            for (Hit& h : hits)
                out.hits.push_back(ArtifactHit{node_id, e.meta.path, e.host_path, std::move(h)});
        }
    }

    // -------------------------------------------------------------- regions
    if (image.empty()) {
        bool any_region = false;
        for (const Node& n : m.nodes()) any_region = any_region || n.kind == NodeKind::Region;
        if (any_region)
            out.diagnostics.push_back(
                {omnitrace::Severity::Info, kCodeNoImageView,
                 "no image view was available, so unidentified regions were not searched; only "
                 "extracted files were"});
    } else {
        // Which source ids the given Span stands for. On a word-swapped image
        // the analysis ran through a SwappedSource, so every region's
        // source_id is "<evidence>|swap32" -- but `image` here is the
        // corrected file re-opened from flash/, whose id is its path. Testing
        // equality against that one id alone matched nothing, so no region on
        // a word-swapped image was ever searched and the only sign of it was
        // "0 regions scanned". analyze records the id it used.
        std::set<std::string> ours{image.source_id()};
        for (const Node& n : m.nodes()) {
            const auto it = n.attrs.find("corrected_source_id");
            if (it != n.attrs.end() && !it->second.empty()) ours.insert(it->second);
        }

        for (const Node& n : m.nodes()) {
            if (n.kind != NodeKind::Region || n.location.length == 0) continue;
            if (out.hits.size() >= limits.max_hits_total) break;
            if (ours.count(n.location.source_id) == 0) continue;

            // Entropy already said what these bytes are. Fill holds nothing,
            // and uniformly random bytes hold nothing a pattern can find.
            const auto klass = n.attrs.find("entropy_class");
            if (klass != n.attrs.end() &&
                (klass->second == "erased" || klass->second == "random")) {
                ++out.regions_skipped;
                continue;
            }
            const std::uint64_t want = std::min(n.location.length, limits.max_bytes_per_item);
            auto bytes = image.bytes(n.location.offset, static_cast<std::size_t>(want));
            if (!bytes) {
                out.diagnostics.push_back({omnitrace::Severity::Warning, kCodeUnreadable,
                                           "region " + n.id +
                                               " could not be read for rule "
                                               "matching"});
                continue;
            }
            ++out.regions_scanned;
            out.bytes_scanned += bytes->size();

            hits.clear();
            engine.scan_bytes(*bytes, /*in_files=*/false, limits, hits);
            for (Hit& h : hits) out.hits.push_back(ArtifactHit{n.id, {}, {}, std::move(h)});
        }
    }

    if (out.hits.size() >= limits.max_hits_total) {
        out.truncated = true;
        out.hits.resize(static_cast<std::size_t>(limits.max_hits_total));
        out.diagnostics.push_back(
            {omnitrace::Severity::Warning, kCodeLimitHits,
             "the sweep reached max_hits_total (" + std::to_string(limits.max_hits_total) +
                 ") and stopped; raise it, or narrow the packs, to see the rest"});
    }

    // Deterministic: by rule, then where it was found, then offset.
    std::sort(out.hits.begin(), out.hits.end(), [](const ArtifactHit& a, const ArtifactHit& b) {
        if (a.hit.pack != b.hit.pack) return a.hit.pack < b.hit.pack;
        if (a.hit.rule != b.hit.rule) return a.hit.rule < b.hit.rule;
        if (a.node != b.node) return a.node < b.node;
        if (a.path != b.path) return a.path < b.path;
        return a.hit.offset < b.hit.offset;
    });
    return Status::success();
}

std::string artifacts_to_yaml(const Manifest& m, const SweepResult& r) {
    (void)m;
    std::string y = "schema: " + std::string(kArtifactsSchema) + "\n";
    y += "summary:\n";
    y += "  hits: " + std::to_string(r.hits.size()) + "\n";
    y += "  files_scanned: " + std::to_string(r.files_scanned) + "\n";
    y += "  regions_scanned: " + std::to_string(r.regions_scanned) + "\n";
    y += "  regions_skipped: " + std::to_string(r.regions_skipped) + "\n";
    y += "  bytes_scanned: " + std::to_string(r.bytes_scanned) + "\n";
    y += std::string("  truncated: ") + (r.truncated ? "true" : "false") + "\n";

    std::map<std::string, std::size_t> by_rule, by_category, by_severity;
    for (const ArtifactHit& a : r.hits) {
        ++by_rule[a.hit.pack + "/" + a.hit.rule];
        ++by_category[a.hit.category];
        ++by_severity[rules::severity_name(a.hit.severity)];
    }
    const auto counts = [&y](const char* key, const std::map<std::string, std::size_t>& c) {
        y += std::string("  ") + key + ":\n";
        for (const auto& [k, v] : c) y += "    " + k + ": " + std::to_string(v) + "\n";
    };
    counts("by_severity", by_severity);
    counts("by_category", by_category);
    counts("by_rule", by_rule);

    y += "diagnostics:\n";
    if (r.diagnostics.empty()) y += "  []\n";
    for (const Diagnostic& d : r.diagnostics) {
        y += "  - severity: " + std::string(omnitrace::severity_name(d.severity)) + "\n";
        y += "    code: " + d.code + "\n";
        y += "    message: " + yaml_quote(sanitize_utf8(d.message)) + "\n";
    }

    y += "hits:\n";
    if (r.hits.empty()) y += "  []\n";
    for (const ArtifactHit& a : r.hits) {
        y += "  - rule: " + a.hit.rule + "\n";
        y += "    pack: " + a.hit.pack + "\n";
        y += "    category: " + a.hit.category + "\n";
        y += "    severity: " + std::string(rules::severity_name(a.hit.severity)) + "\n";
        y += "    node: " + a.node + "\n";
        if (!a.path.empty()) y += "    path: " + yaml_quote(sanitize_utf8(a.path)) + "\n";
        y += "    offset: " + std::to_string(a.hit.offset) + "\n";
        y += "    match: " + yaml_quote(a.hit.match) + "\n";
        if (!a.hit.context.empty()) y += "    context: " + yaml_quote(a.hit.context) + "\n";
    }
    return y;
}

std::string artifacts_to_markdown(const Manifest& m, const SweepResult& r) {
    (void)m;
    std::string out = "# Artifacts\n\n";
    out +=
        "Matches from the search packs, over every extracted file and every region no "
        "signature claimed. A hit is a lead, not a conclusion: the rule that found it is "
        "named so its reasoning can be checked.\n\n";

    out += "| | |\n|---|---|\n";
    out += "| Hits | " + std::to_string(r.hits.size()) + " |\n";
    out += "| Files searched | " + std::to_string(r.files_scanned) + " |\n";
    out += "| Regions searched | " + std::to_string(r.regions_scanned) + " |\n";
    out += "| Regions skipped (erased or random) | " + std::to_string(r.regions_skipped) + " |\n";
    out += "| Bytes searched | " + output::human_bytes(r.bytes_scanned) + " |\n";
    if (r.truncated) out += "| Truncated | a cap stopped the sweep early |\n";
    out += "\n";

    // Severity first: it is what decides where an examiner looks.
    std::map<std::string, std::size_t> by_sev, by_cat;
    std::map<std::string, std::vector<const ArtifactHit*>> by_rule;
    for (const ArtifactHit& a : r.hits) {
        ++by_sev[rules::severity_name(a.hit.severity)];
        ++by_cat[a.hit.category];
        by_rule[a.hit.pack + "/" + a.hit.rule].push_back(&a);
    }

    out += "## By severity\n\n";
    std::vector<std::vector<std::string>> rows;
    for (const char* s : {"critical", "high", "medium", "low", "info"})
        if (by_sev.count(s) != 0) rows.push_back({s, std::to_string(by_sev[s])});
    out += output::md_table({"Severity", "Hits"}, rows);

    out += "\n## By category\n\n";
    rows.clear();
    for (const auto& [k, v] : by_cat) rows.push_back({output::md_escape(k), std::to_string(v)});
    out += output::md_table({"Category", "Hits"}, rows);

    out += "\n## By rule\n\n";
    rows.clear();
    for (const auto& [k, v] : by_rule) {
        const ArtifactHit* first = v.front();
        rows.push_back(
            {output::md_escape(k), rules::severity_name(first->hit.severity),
             std::to_string(v.size()),
             output::md_escape(sanitize_utf8(first->path.empty() ? first->node : first->path))});
    }
    out += output::md_table({"Rule", "Severity", "Hits", "First seen in"}, rows);

    // The detail, capped: a hundred thousand rows helps nobody.
    constexpr std::size_t kPerRule = 20;
    out += "\n## Hits\n\n";
    for (const auto& [rule, v] : by_rule) {
        out += "### " + output::md_escape(rule) + "\n\n";
        rows.clear();
        for (std::size_t i = 0; i < v.size() && i < kPerRule; ++i) {
            const ArtifactHit* a = v[i];
            rows.push_back({output::md_escape(sanitize_utf8(a->path.empty() ? a->node : a->path)),
                            output::hex(a->hit.offset), output::md_escape(a->hit.match)});
        }
        out += output::md_table({"Where", "Offset", "Match"}, rows);
        if (v.size() > kPerRule)
            out += "\n" + std::to_string(v.size() - kPerRule) + " more in `artifacts.yaml`.\n";
        out += "\n";
    }
    return out;
}

namespace {

// artifacts.yaml is written by hand above rather than through an emitter, so
// it is read back by hand too. The schema is small and flat; what matters is
// that a field this cannot parse is an error rather than a default, because
// every default here is a number a report would print as fact.
struct ReadCtx {
    std::string error;
    bool fail(const std::string& what) {
        error = "artifacts: " + what;
        return false;
    }
};

bool want_map(const YAML::Node& n, const char* key, YAML::Node& out, ReadCtx& c) {
    out = n[key];
    if (!out.IsDefined() || out.IsNull()) {
        out = YAML::Node();
        return true;  // absent is allowed; the caller decides whether it matters
    }
    if (!out.IsMap()) return c.fail(std::string(key) + " must be a map");
    return true;
}

bool want_u64(const YAML::Node& n, const char* key, std::uint64_t& out, ReadCtx& c) {
    const YAML::Node v = n[key];
    if (!v.IsDefined() || v.IsNull()) return true;  // keep the default
    if (!v.IsScalar()) return c.fail(std::string(key) + " must be a number");
    try {
        out = v.as<std::uint64_t>();
    } catch (const YAML::Exception&) {
        return c.fail(std::string(key) + " is not a number");
    }
    return true;
}

bool want_str(const YAML::Node& n, const char* key, std::string& out, ReadCtx& c) {
    const YAML::Node v = n[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    if (!v.IsScalar()) return c.fail(std::string(key) + " must be a string");
    out = v.Scalar();
    return true;
}

}  // namespace

Status artifacts_from_yaml(const std::string& text, SweepResult& out) {
    YAML::Node root;
    try {
        root = YAML::Load(text);
    } catch (const YAML::Exception& ex) {
        return Status::fail(std::string("artifacts: yaml parse error: ") + ex.what());
    } catch (const std::exception& ex) {
        return Status::fail(std::string("artifacts: yaml parse error: ") + ex.what());
    }
    if (!root.IsMap()) return Status::fail("artifacts: document must be a map");

    ReadCtx c;
    SweepResult read;
    std::uint64_t claimed_hits = 0;
    try {
        std::string schema;
        if (!want_str(root, "schema", schema, c)) return Status::fail(c.error);
        if (schema != kArtifactsSchema)
            return Status::fail("artifacts: schema is '" + schema + "', expected '" +
                                std::string(kArtifactsSchema) + "'");

        YAML::Node summary;
        if (!want_map(root, "summary", summary, c)) return Status::fail(c.error);
        if (summary.IsMap()) {
            bool truncated = false;
            const YAML::Node t = summary["truncated"];
            if (t.IsDefined() && !t.IsNull()) {
                if (!t.IsScalar()) return Status::fail("artifacts: truncated must be a bool");
                truncated = t.Scalar() == "true";
            }
            read.truncated = truncated;
            if (!want_u64(summary, "hits", claimed_hits, c) ||
                !want_u64(summary, "files_scanned", read.files_scanned, c) ||
                !want_u64(summary, "regions_scanned", read.regions_scanned, c) ||
                !want_u64(summary, "regions_skipped", read.regions_skipped, c) ||
                !want_u64(summary, "bytes_scanned", read.bytes_scanned, c))
                return Status::fail(c.error);
        }

        const YAML::Node diags = root["diagnostics"];
        if (diags.IsDefined() && !diags.IsNull() && diags.IsSequence()) {
            for (const YAML::Node& d : diags) {
                if (!d.IsMap()) return Status::fail("artifacts: a diagnostic must be a map");
                Diagnostic out_d;
                std::string sev;
                if (!want_str(d, "severity", sev, c) || !want_str(d, "code", out_d.code, c) ||
                    !want_str(d, "message", out_d.message, c))
                    return Status::fail(c.error);
                const auto parsed = omnitrace::severity_from_name(sev);
                if (!parsed)
                    return Status::fail("artifacts: a diagnostic has severity '" + sev +
                                        "', which is not a severity");
                out_d.severity = *parsed;
                read.diagnostics.push_back(std::move(out_d));
            }
        }

        const YAML::Node hits = root["hits"];
        if (hits.IsDefined() && !hits.IsNull() && hits.IsSequence()) {
            std::size_t i = 0;
            for (const YAML::Node& h : hits) {
                if (!h.IsMap())
                    return Status::fail("artifacts: hits item " + std::to_string(i) +
                                        " must be a map");
                ArtifactHit a;
                std::string sev;
                if (!want_str(h, "rule", a.hit.rule, c) || !want_str(h, "pack", a.hit.pack, c) ||
                    !want_str(h, "category", a.hit.category, c) ||
                    !want_str(h, "severity", sev, c) || !want_str(h, "node", a.node, c) ||
                    !want_str(h, "path", a.path, c) || !want_u64(h, "offset", a.hit.offset, c) ||
                    !want_str(h, "match", a.hit.match, c) ||
                    !want_str(h, "context", a.hit.context, c))
                    return Status::fail(c.error);
                if (!sev.empty() && !parse_severity(sev, a.hit.severity))
                    return Status::fail("artifacts: hits item " + std::to_string(i) +
                                        " has severity '" + sev + "', which is not a severity");
                read.hits.push_back(std::move(a));
                ++i;
            }
        }
    } catch (const YAML::Exception& ex) {
        return Status::fail(std::string("artifacts: yaml error: ") + ex.what());
    }

    // The guard that makes this worth trusting. A file cut short while being
    // written parses cleanly and yields fewer hits than it claims, and the
    // report would print the smaller number as a finding.
    if (claimed_hits != read.hits.size())
        return Status::fail("artifacts: summary claims " + std::to_string(claimed_hits) +
                            " hit(s) but the document holds " + std::to_string(read.hits.size()) +
                            "; the file is incomplete");

    out = std::move(read);
    return Status::success();
}

}  // namespace omnitrace::rules
