// report_document.cpp — turn a finished case into a report::Document.
//
// This is where the domain knowledge lives, deliberately. The report layer
// knows about sections, tables and callouts and nothing about filesystems,
// platforms or certificates; if it did, it could not be lifted out as a
// standalone renderer the way §7 of the plan wants. So the CLI, which already
// holds all four results of a run, is what decides what a report says.
//
// Optional inputs are pointers rather than values: `omnitrace report` on a
// case directory can rebuild everything the manifest holds, and the platform,
// artifact and search sections simply do not appear when that data was not
// produced. A missing section is better than an empty one claiming nothing
// was found.
#include "report_document.h"

#include <algorithm>
#include <map>

#include "omnitrace/output/Markdown.h"

namespace omnitrace::cli {

namespace {

using report::Block;
using report::BulletList;
using report::Callout;
using report::KeyValues;
using report::Paragraph;
using report::Section;
using report::Table;
using report::Tone;

Tone tone_of(Severity s) {
    switch (s) {
        case Severity::Error:
            return Tone::Bad;
        case Severity::Warning:
            return Tone::Warn;
        case Severity::Info:
            break;
    }
    return Tone::Neutral;
}

std::string human(std::uint64_t bytes) {
    return output::human_bytes(bytes) + " (" + std::to_string(bytes) + ")";
}

// The evidence, and whether it is still the evidence. First section of every
// report because everything after it is a claim about these bytes.
Section evidence_section(const Manifest& m, const report::IntegrityResult* integrity) {
    Section s;
    s.title = "Evidence";
    s.anchor = "evidence";
    for (const Evidence& e : m.evidence) {
        KeyValues kv;
        kv.caption = e.id;
        kv.rows.emplace_back("Path", e.path);
        kv.rows.emplace_back("Size", human(e.size));
        if (!e.digests.md5.empty()) kv.rows.emplace_back("MD5", e.digests.md5);
        if (!e.digests.sha1.empty()) kv.rows.emplace_back("SHA-1", e.digests.sha1);
        if (!e.digests.sha256.empty()) kv.rows.emplace_back("SHA-256", e.digests.sha256);
        if (!e.acquired_at.empty()) kv.rows.emplace_back("Acquired", e.acquired_at);
        if (!e.note.empty()) kv.rows.emplace_back("Note", e.note);
        s.blocks.emplace_back(std::move(kv));
    }

    if (integrity == nullptr) {
        s.blocks.emplace_back(
            Callout{Tone::Neutral, "Integrity not checked",
                    "The evidence was not re-hashed when this report was produced, so it says "
                    "only what the case recorded."});
        return s;
    }
    Table t;
    t.caption = "Re-hashed when this report was produced";
    t.headers = {"Evidence", "State"};
    for (const auto& [label, state] : integrity->states) t.rows.push_back({label, state});
    s.blocks.emplace_back(std::move(t));
    if (integrity->verified) {
        s.blocks.emplace_back(Callout{Tone::Good, "Evidence verified",
                                      "Every file still hashes to what the case recorded, so "
                                      "every offset below refers to the bytes described."});
    } else {
        s.blocks.emplace_back(
            Callout{Tone::Bad, "Evidence could not be verified",
                    "At least one file is missing, unreadable, or no longer hashes to what the "
                    "case recorded. Offsets below refer to the bytes as they were, not as they "
                    "are now."});
    }
    for (const Diagnostic& d : integrity->diagnostics)
        s.blocks.emplace_back(Callout{tone_of(d.severity), d.code, d.message});
    return s;
}

// What is in the image, as a map rather than a list of nodes: an examiner
// reads a report to find out where things are.
Section structure_section(const Manifest& m) {
    Section s;
    s.title = "Structure";
    s.anchor = "structure";

    std::map<std::string, std::size_t> by_format;
    std::size_t regions = 0, files = 0;
    for (const Node& n : m.nodes()) {
        switch (n.kind) {
            case NodeKind::Region:
                ++regions;
                break;
            case NodeKind::File:
                ++files;
                break;
            default:
                if (!n.format.empty()) ++by_format[n.format];
        }
    }
    KeyValues kv;
    kv.rows.emplace_back("Nodes", std::to_string(m.nodes().size()));
    kv.rows.emplace_back("Extracted files", std::to_string(files));
    kv.rows.emplace_back("Unidentified regions", std::to_string(regions));
    s.blocks.emplace_back(std::move(kv));

    if (!by_format.empty()) {
        Table t;
        t.caption = "Structures identified";
        t.headers = {"Format", "Count"};
        for (const auto& [f, n] : by_format) t.rows.push_back({f, std::to_string(n)});
        s.blocks.emplace_back(std::move(t));
    }

    // The partition map: what an examiner would mount.
    Table parts;
    parts.caption = "Partitions and filesystems";
    parts.headers = {"Offset", "Size", "Format", "Confidence", "Name"};
    for (const Node& n : m.nodes()) {
        if (n.kind != NodeKind::Partition && n.kind != NodeKind::Filesystem) continue;
        if (parts.rows.size() >= 200) break;
        parts.rows.push_back({output::hex(n.location.offset),
                              output::human_bytes(n.location.length),
                              n.format.empty() ? "-" : n.format,
                              std::to_string(static_cast<unsigned>(n.confidence)), n.name});
    }
    if (!parts.rows.empty()) s.blocks.emplace_back(std::move(parts));
    return s;
}

// What was not done, which a forensic report has to state as plainly as what
// was. A coverage row is the tool admitting a limit.
Section coverage_section(const Manifest& m) {
    Section s;
    s.title = "Coverage and limits";
    s.anchor = "coverage";
    bool any_gap = false;
    Table t;
    t.headers = {"Format", "Status", "Detail"};
    for (const Coverage& c : m.coverage) {
        t.rows.push_back({c.format, c.status, c.detail});
        any_gap = any_gap || c.status != "supported";
    }
    if (t.rows.empty()) {
        s.blocks.emplace_back(Paragraph{"No format reported a limit."});
        return s;
    }
    s.blocks.emplace_back(
        Paragraph{"Every format met during the analysis, and whether anything was left behind."});
    s.blocks.emplace_back(std::move(t));
    if (any_gap)
        s.blocks.emplace_back(Callout{
            Tone::Warn, "Not everything was extracted",
            "At least one format was read partially or not at all. The rows above say which and "
            "why; what they describe is absent from this report, not absent from the device."});
    return s;
}

Section diagnostics_section(const Manifest& m) {
    Section s;
    s.title = "Diagnostics";
    s.anchor = "diagnostics";
    std::map<std::string, std::size_t> by_code;
    std::size_t errors = 0, warnings = 0;
    for (const Node& n : m.nodes())
        for (const Diagnostic& d : n.diagnostics) {
            ++by_code[d.code];
            if (d.severity == Severity::Error) ++errors;
            if (d.severity == Severity::Warning) ++warnings;
        }
    for (const Diagnostic& d : m.diagnostics) {
        ++by_code[d.code];
        if (d.severity == Severity::Error) ++errors;
        if (d.severity == Severity::Warning) ++warnings;
    }
    if (by_code.empty()) {
        s.blocks.emplace_back(Paragraph{"The run produced no diagnostics."});
        return s;
    }
    KeyValues kv;
    kv.rows.emplace_back("Errors", std::to_string(errors));
    kv.rows.emplace_back("Warnings", std::to_string(warnings));
    kv.rows.emplace_back("Distinct codes", std::to_string(by_code.size()));
    s.blocks.emplace_back(std::move(kv));

    Table t;
    t.caption = "By code; every code is catalogued in docs/reference/DIAGNOSTICS.md";
    t.headers = {"Code", "Count"};
    std::vector<std::pair<std::string, std::size_t>> sorted(by_code.begin(), by_code.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    for (const auto& [code, n] : sorted) {
        if (t.rows.size() >= 60) break;
        t.rows.push_back({code, std::to_string(n)});
    }
    s.blocks.emplace_back(std::move(t));
    return s;
}

Section platform_section(const analyzers::Survey& survey) {
    Section s;
    s.title = "Platforms";
    s.anchor = "platforms";
    s.blocks.emplace_back(Paragraph{
        "What each extracted filesystem says about itself. Every value names the file it was "
        "read from, so it can be opened in the case directory and checked."});
    KeyValues kv;
    kv.rows.emplace_back("Filesystems examined", std::to_string(survey.trees_examined));
    kv.rows.emplace_back("Recognised", std::to_string(survey.reports.size()));
    kv.rows.emplace_back("Unrecognised", std::to_string(survey.trees_unclaimed));
    s.blocks.emplace_back(std::move(kv));

    for (const analyzers::Report& r : survey.reports) {
        Section sub;
        sub.title = r.node + " — " + analyzers::platform_name(r.platform);
        sub.anchor = "platform-" + r.node;
        sub.blocks.emplace_back(Paragraph{r.evidence});
        Table t;
        t.headers = {"Fact", "Value", "From"};
        for (const analyzers::Fact& f : r.facts) t.rows.push_back({f.key, f.value, f.source});
        if (!t.rows.empty()) sub.blocks.emplace_back(std::move(t));
        for (const Diagnostic& d : r.diagnostics)
            if (d.severity != Severity::Info)
                sub.blocks.emplace_back(Callout{tone_of(d.severity), d.code, d.message});
        s.subsections.push_back(std::move(sub));
    }
    return s;
}

Section artifacts_section(const artifacts::Collection& c) {
    Section s;
    s.title = "Extracted artifacts";
    s.anchor = "artifacts";
    s.blocks.emplace_back(
        Paragraph{"Files a parser recognised. A search pack can say a certificate is present; "
                  "only a parser can say what it is for and when it stops being valid."});
    KeyValues kv;
    kv.rows.emplace_back("Records", std::to_string(c.artifacts.size()));
    kv.rows.emplace_back("Files parsed", std::to_string(c.files_examined));
    kv.rows.emplace_back("Summarised rather than listed", std::to_string(c.summarised));
    s.blocks.emplace_back(std::move(kv));

    std::map<std::string, std::vector<const artifacts::Artifact*>> by_kind;
    for (const artifacts::Artifact& a : c.artifacts) by_kind[a.kind].push_back(&a);
    for (const auto& [kind, list] : by_kind) {
        Section sub;
        sub.title = kind + " (" + std::to_string(list.size()) + ")";
        sub.anchor = "artifact-" + kind;
        std::vector<std::string> cols;
        for (const artifacts::Artifact* a : list)
            for (const auto& [k, v] : a->fields)
                if (std::find(cols.begin(), cols.end(), k) == cols.end()) cols.push_back(k);
        std::sort(cols.begin(), cols.end());
        Table t;
        t.headers.push_back("Where");
        for (const std::string& k : cols) t.headers.push_back(k);
        for (std::size_t i = 0; i < list.size() && i < 40; ++i) {
            std::vector<std::string> row{list[i]->path};
            for (const std::string& k : cols) {
                const auto it = list[i]->fields.find(k);
                row.push_back(it == list[i]->fields.end() ? "" : it->second);
            }
            t.rows.push_back(std::move(row));
        }
        sub.blocks.emplace_back(std::move(t));
        s.subsections.push_back(std::move(sub));
    }
    for (const Diagnostic& d : c.diagnostics)
        if (d.severity != Severity::Info)
            s.blocks.emplace_back(Callout{tone_of(d.severity), d.code, d.message});
    return s;
}

Section search_section(const rules::SweepResult& r) {
    Section s;
    s.title = "Search hits";
    s.anchor = "search";
    s.blocks.emplace_back(Paragraph{
        "Matches from the search packs over every extracted file and every region no signature "
        "claimed. A hit is a lead, not a conclusion: the rule that found it is named so its "
        "reasoning can be checked."});
    KeyValues kv;
    kv.rows.emplace_back("Hits", std::to_string(r.hits.size()));
    kv.rows.emplace_back("Files searched", std::to_string(r.files_scanned));
    kv.rows.emplace_back("Regions searched", std::to_string(r.regions_scanned));
    kv.rows.emplace_back("Regions skipped (erased or random)", std::to_string(r.regions_skipped));
    s.blocks.emplace_back(std::move(kv));

    std::map<std::string, std::size_t> by_rule;
    std::map<std::string, std::size_t> by_severity;
    for (const rules::ArtifactHit& h : r.hits) {
        ++by_rule[h.hit.pack + "/" + h.hit.rule];
        ++by_severity[rules::severity_name(h.hit.severity)];
    }
    if (!by_severity.empty()) {
        Table t;
        t.caption = "By severity";
        t.headers = {"Severity", "Hits"};
        for (const char* name : {"critical", "high", "medium", "low", "info"})
            if (by_severity.count(name) != 0)
                t.rows.push_back({name, std::to_string(by_severity[name])});
        s.blocks.emplace_back(std::move(t));
    }
    Table t;
    t.caption = "By rule; the full list with offsets is in artifacts.yaml";
    t.headers = {"Rule", "Hits"};
    std::vector<std::pair<std::string, std::size_t>> sorted(by_rule.begin(), by_rule.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    for (const auto& [rule, n] : sorted) {
        if (t.rows.size() >= 60) break;
        t.rows.push_back({rule, std::to_string(n)});
    }
    if (!t.rows.empty()) s.blocks.emplace_back(std::move(t));
    return s;
}

}  // namespace

report::Document build_report(const Manifest& m, const report::IntegrityResult* integrity,
                              const analyzers::Survey* survey,
                              const artifacts::Collection* extracted,
                              const rules::SweepResult* hits, const std::string& case_name) {
    report::Document doc;
    doc.meta.title = "Forensic analysis";
    doc.meta.subtitle =
        m.evidence.empty() ? case_name : m.evidence.front().path + " — " + case_name;
    if (!m.case_info.id.empty()) doc.meta.fields.emplace_back("Case", m.case_info.id);
    if (!m.case_info.examiner.empty())
        doc.meta.fields.emplace_back("Examiner", m.case_info.examiner);
    if (!m.run.tool.empty()) doc.meta.fields.emplace_back("Tool", m.run.tool + " " + m.run.version);
    if (!m.run.git_sha.empty()) doc.meta.fields.emplace_back("Build", m.run.git_sha);
    if (!m.run.started_at.empty()) doc.meta.fields.emplace_back("Analysed", m.run.started_at);
    if (!m.evidence.empty()) {
        doc.meta.fields.emplace_back("Evidence", m.evidence.front().path);
        doc.meta.fields.emplace_back("SHA-256", m.evidence.front().digests.sha256);
    }

    if (!m.case_info.notes.empty()) {
        report::Section notes;
        notes.title = "Examiner's notes";
        notes.anchor = "notes";
        notes.blocks.emplace_back(report::Paragraph{m.case_info.notes});
        doc.sections.push_back(std::move(notes));
    }

    doc.sections.push_back(evidence_section(m, integrity));
    doc.sections.push_back(structure_section(m));
    if (survey != nullptr && survey->trees_examined != 0)
        doc.sections.push_back(platform_section(*survey));
    if (extracted != nullptr && !extracted->artifacts.empty())
        doc.sections.push_back(artifacts_section(*extracted));
    if (hits != nullptr && !hits->hits.empty()) doc.sections.push_back(search_section(*hits));
    doc.sections.push_back(coverage_section(m));
    doc.sections.push_back(diagnostics_section(m));
    return doc;
}

}  // namespace omnitrace::cli
