// analyze_commands.cpp — `omnitrace scan` and `omnitrace analyze`.
//
// scan:    findings only, as an aligned table or JSON.
// analyze: the case directory (docs/CASE_LAYOUT.md). Default "corpus" layout:
//          INFO.yaml (+ manifest.yaml alias), INFO.md, flash/SOURCE.yaml,
//          partitions/{<name>.bin,mount.sh}, filesystems/<id>/ and
//          containers/<id>/ each holding {listing.yaml,
//          listing.md,files/}, plus summary.md / partitions.md for
//          compatibility. "flat" is the Phase 0 layout: manifest.yaml,
//          summary.md, partitions.md, filesystems/, containers/ and nothing
//          carved.
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "commands.h"
#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/artifacts/Artifact.h"
#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Clock.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/core/Text.h"
#include "omnitrace/diff/Diff.h"
#include "omnitrace/discovery/Recurse.h"
#include "omnitrace/discovery/Signature.h"
#include "omnitrace/filesystems/Filesystem.h"
#include "omnitrace/output/Markdown.h"
#include "omnitrace/output/Yaml.h"
#include "omnitrace/report/Document.h"
#include "omnitrace/rules/Sweep.h"
#include "report_document.h"

#include "omnitrace_gitsha.h"  // generated; see cmake/GitSha.cmake

#ifndef OMNITRACE_VERSION
#define OMNITRACE_VERSION "0.0.0"
#endif

using namespace omnitrace;

namespace {

std::vector<std::string> g_argv;

std::string dec(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
    return buf;
}

const char* host_os() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#elif defined(__unix__)
    return "unix";
#else
    return "unknown";
#endif
}

[[noreturn]] void fail(const std::string& msg) {
    spdlog::error("{}", msg);
    throw CLI::RuntimeError(1);
}

std::shared_ptr<MappedFile> open_image(const std::string& path) {
    std::shared_ptr<MappedFile> file;
    if (const Status st = MappedFile::open(path, file); !st) fail(st.error);
    return file;
}

// File mtime as ISO-8601, or empty when the clock cannot be read.
std::string file_mtime_iso(const std::string& path) {
    std::error_code ec;
    const auto t = std::filesystem::last_write_time(path, ec);
    if (ec) return {};
    const auto sys = std::chrono::clock_cast<std::chrono::system_clock>(t);
    const auto secs =
        std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count();
    return Clock::iso8601(static_cast<std::int64_t>(secs));
}

void write_text(const std::filesystem::path& p, const std::string& text) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) fail("cannot write '" + p.string() + "'");
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!f) fail("short write to '" + p.string() + "'");
}

// Files the extractors composed but did not write: this layer never touches
// the host filesystem (docs/ARCHITECTURE.md rule 2), so the caller places
// them. `collect` has already checked every path is inside the case.
void write_extracted_files(const std::filesystem::path& root,
                           const std::vector<artifacts::ExtractedFile>& files) {
    for (const artifacts::ExtractedFile& f : files) {
        const std::filesystem::path dest = root / std::filesystem::path(f.path);
        std::error_code ec;
        std::filesystem::create_directories(dest.parent_path(), ec);
        if (ec) fail("cannot create '" + dest.parent_path().string() + "': " + ec.message());
        write_text(dest, f.content);
    }
}

// Column-aligned plain-text table for stdout.
std::string text_table(const std::vector<std::string>& header,
                       const std::vector<std::vector<std::string>>& rows) {
    std::vector<std::size_t> width(header.size(), 0);
    for (std::size_t i = 0; i < header.size(); ++i) width[i] = header[i].size();
    for (const auto& r : rows)
        for (std::size_t i = 0; i < header.size() && i < r.size(); ++i)
            width[i] = std::max(width[i], r[i].size());
    auto line = [&](const std::vector<std::string>& cells) {
        std::string s;
        for (std::size_t i = 0; i < header.size(); ++i) {
            const std::string& c = i < cells.size() ? cells[i] : std::string{};
            s += c;
            if (i + 1 < header.size()) s += std::string(width[i] - c.size() + 2, ' ');
        }
        while (!s.empty() && s.back() == ' ') s.pop_back();
        return s + "\n";
    };
    std::string out = line(header);
    std::vector<std::string> rule;
    for (const std::size_t w : width) rule.push_back(std::string(w, '-'));
    out += line(rule);
    for (const auto& r : rows) out += line(r);
    return out;
}

std::string attrs_text(const std::map<std::string, std::string>& attrs) {
    std::string s;
    for (const auto& [k, v] : attrs) {
        if (!s.empty()) s += ' ';
        s += sanitize_utf8(k) + "=" + sanitize_utf8(v);
    }
    return s;
}

// ------------------------------------------------------------------- scan

nlohmann::json finding_json(const discovery::Finding& f) {
    nlohmann::json j;
    j["offset"] = f.offset;
    j["offset_hex"] = output::hex(f.offset);
    j["size"] = f.size;
    j["format"] = sanitize_utf8(f.format);
    j["category"] = sanitize_utf8(f.category);
    j["signature"] = sanitize_utf8(f.signature);
    j["confidence"] = static_cast<int>(f.confidence);
    j["tier"] = confidence_tier(f.confidence);
    j["evidence"] = sanitize_utf8(f.evidence);
    j["endian"] = endian_name(f.endian);
    j["attrs"] = nlohmann::json::object();
    for (const auto& [k, v] : f.attrs) j["attrs"][sanitize_utf8(k)] = sanitize_utf8(v);
    j["diagnostics"] = nlohmann::json::array();
    for (const Diagnostic& d : f.diagnostics)
        j["diagnostics"].push_back({{"severity", severity_name(d.severity)},
                                    {"code", sanitize_utf8(d.code)},
                                    {"message", sanitize_utf8(d.message)}});
    j["also_matched"] = nlohmann::json::array();
    for (const discovery::Finding& alt : f.also_matched)
        j["also_matched"].push_back(finding_json(alt));
    return j;
}

void cmd_scan(const std::string& path, bool json) {
    const auto file = open_image(path);
    const auto findings = discovery::scan(Span::whole(file), discovery::SignatureSet::builtin());
    if (json) {
        nlohmann::json out;
        out["image"] = sanitize_utf8(path);
        out["size"] = file->size();
        out["findings"] = nlohmann::json::array();
        for (const auto& f : findings) out["findings"].push_back(finding_json(f));
        std::printf("%s\n", out.dump(2).c_str());
        return;
    }
    std::vector<std::vector<std::string>> rows;
    for (const auto& f : findings) {
        rows.push_back({output::hex(f.offset), f.size ? dec(f.size) : "?", sanitize_utf8(f.format),
                        confidence_tier(f.confidence), sanitize_utf8(f.evidence),
                        attrs_text(f.attrs)});
    }
    std::printf("%s: %s, %zu finding(s)\n\n", path.c_str(),
                output::human_bytes(file->size()).c_str(), findings.size());
    std::fputs(text_table({"Offset", "Size", "Format", "Tier", "Evidence", "Attrs"}, rows).c_str(),
               stdout);
}

// ---------------------------------------------------------------- analyze

struct AnalyzeArgs {
    std::string image, out;
    std::string layout = "corpus";  // corpus | flat
    std::string carve = "all";      // none | table | all
    std::uint64_t max_carve_bytes = 32ull << 30;
    bool copy_image = false;
    bool no_rules = false;
    std::vector<std::string> rule_packs;
    std::uint64_t max_hits = 100'000;
    bool no_extract = false, history = false, tar_filesystems = false;
    CaseInfo case_info;
    Limits limits;
};

discovery::Carve carve_from(const std::string& s) {
    if (s == "none") return discovery::Carve::None;
    if (s == "table") return discovery::Carve::Table;
    return discovery::Carve::All;
}

// YAML double-quoted scalar: always valid UTF-8, never breaks the document.
std::string yaml_quote(const std::string& raw) {
    std::string s = sanitize_utf8(raw);
    std::string out = "\"";
    for (const char ch : s) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out.push_back(ch);
        }
    }
    return out + "\"";
}

// The Image node's record of a corrected view, when analyze() wrote one:
// {transform, path, sha256}. Empty `path` means there is none.
struct CorrectedView {
    std::string transform, path, sha256;
};
CorrectedView corrected_view_of(const Manifest& m) {
    CorrectedView c;
    for (const Node& n : m.nodes()) {
        if (n.kind != NodeKind::Image) continue;
        const auto path = n.attrs.find("corrected_path");
        if (path == n.attrs.end()) continue;
        c.path = path->second;
        const auto sha = n.attrs.find("corrected_sha256");
        if (sha != n.attrs.end()) c.sha256 = sha->second;
        const auto swap = n.attrs.find("word_swap");
        c.transform = swap != n.attrs.end() ? swap->second : "corrected";
        break;
    }
    return c;
}

std::string corrected_skipped(const Manifest& m) {
    for (const Node& n : m.nodes()) {
        if (n.kind != NodeKind::Image) continue;
        const auto it = n.attrs.find("corrected_skipped");
        if (it != n.attrs.end()) return it->second;
    }
    return {};
}

// flash/SOURCE.yaml: where the evidence came from and what it hashes to.
//
// `corrected` is the view the analysis actually read. It is a derived file,
// never the evidence, so it is recorded separately and with its own hashes --
// an examiner who verifies this case has two artefacts to account for, and
// conflating them would be the worst kind of quiet error.
std::string source_yaml(const Evidence& ev, const std::string& copied_to,
                        const CorrectedView& corrected, const std::filesystem::path& out) {
    std::string y = "schema: omnitrace-source/1\n";
    y += "path: " + yaml_quote(ev.path) + "\n";
    y += "name: " + yaml_quote(std::filesystem::path(ev.path).filename().string()) + "\n";
    y += "size: " + dec(ev.size) + "\n";
    y += "md5: " + ev.digests.md5 + "\n";
    y += "sha1: " + ev.digests.sha1 + "\n";
    y += "sha256: " + ev.digests.sha256 + "\n";
    y += "acquired_at: " + yaml_quote(ev.acquired_at) + "\n";
    y += "copy: " + (copied_to.empty() ? std::string("null") : yaml_quote(copied_to)) + "\n";
    if (corrected.path.empty()) {
        y += "corrected: null\n";
    } else {
        Digests d;
        const Status st = hash_file((out / corrected.path).string(), d);
        y += "corrected:\n";
        y += "  transform: " + yaml_quote(corrected.transform) + "\n";
        y += "  path: " + yaml_quote(corrected.path) + "\n";
        y += "  md5: " + (st ? d.md5 : std::string()) + "\n";
        y += "  sha1: " + (st ? d.sha1 : std::string()) + "\n";
        y += "  sha256: " + (st ? d.sha256 : corrected.sha256) + "\n";
    }
    return y;
}

// INFO.md: the summary, the partition map, what was carved, and coverage.
std::string info_markdown(const Manifest& m) {
    std::string out = output::summary_markdown(m);
    out += "\n" + output::partitions_markdown(m);
    out += "\n# Partitions carved\n\n";
    std::vector<std::vector<std::string>> rows;
    for (const Node& n : m.nodes()) {
        const auto carved = n.attrs.find("carved_path");
        const auto skipped = n.attrs.find("carve_skipped");
        if (carved == n.attrs.end() && skipped == n.attrs.end()) continue;
        const std::string kind =
            std::string(node_kind_name(n.kind)) + (n.format.empty() ? "" : "/" + n.format);
        rows.push_back(
            {carved != n.attrs.end() ? output::md_escape(sanitize_utf8(carved->second)) : "-",
             output::hex(n.location.offset),
             output::human_bytes(n.location.length) + " (" + dec(n.location.length) + ")",
             output::md_escape(sanitize_utf8(kind)),
             n.digests.sha256.empty() ? "-" : n.digests.sha256,
             output::md_escape(sanitize_utf8(n.name)),
             skipped != n.attrs.end() ? "skipped: " + skipped->second : ""});
    }
    out += output::md_table({"File", "Offset", "Size", "Kind", "SHA-256", "Node", "Note"}, rows);
    out += "\n# Coverage\n\n";
    std::vector<std::vector<std::string>> cov;
    for (const Coverage& c : m.coverage)
        cov.push_back({output::md_escape(sanitize_utf8(c.format)),
                       output::md_escape(sanitize_utf8(c.status)),
                       output::md_escape(sanitize_utf8(c.detail))});
    out += output::md_table({"Format", "Status", "Detail"}, cov);
    return out;
}

// manifest.yaml beside INFO.yaml: a symlink where the host allows it, a copy
// otherwise (Windows, or a filesystem without symlinks).
void alias_manifest(const std::filesystem::path& out, const std::string& yaml) {
    const std::filesystem::path alias = out / "manifest.yaml";
    std::error_code ec;
    std::filesystem::remove(alias, ec);
#ifndef _WIN32
    std::filesystem::create_symlink("INFO.yaml", alias, ec);
    if (!ec) return;
    spdlog::debug("symlink manifest.yaml -> INFO.yaml failed ({}); writing a copy", ec.message());
#endif
    write_text(alias, yaml);
}

// --copy-image: flash/<name> is a verified byte copy of the evidence.
std::string copy_image_into(const std::filesystem::path& flash, const std::string& image,
                            const Evidence& ev) {
    const std::string name =
        safe_filename_component(std::filesystem::path(image).filename().string(), 255);
    const std::filesystem::path dst = flash / name;
    std::error_code ec;
    std::filesystem::copy_file(image, dst, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) fail("cannot copy image to '" + dst.string() + "': " + ec.message());
    Digests d;
    if (const Status st = hash_file(dst.string(), d); !st)
        fail("cannot hash the copy: " + st.error);
    if (d.sha256 != ev.digests.sha256) fail("the copy in flash/ does not hash like the evidence");
    return "flash/" + name;
}

// The search packs, over everything the analysis produced. Runs after the
// graph exists rather than during it: `discovery` has no business knowing what
// an examiner is looking for, and a hit has to be able to name the node it
// came from, which only exists once the graph is built.
rules::SweepResult run_rules(const AnalyzeArgs& a, const Manifest& m,
                             const discovery::Listings& listings,
                             const std::shared_ptr<const Source>& image,
                             const std::filesystem::path& out) {
    std::vector<rules::RulePack> packs = rules::RulePack::builtin();
    for (const std::string& path : a.rule_packs) {
        rules::RulePack p;
        if (const Status st = rules::RulePack::load_file(path, p); !st) fail(st.error);
        packs.push_back(std::move(p));
    }
    rules::Engine engine;
    // A pack that does not compile is the examiner's own file being wrong, and
    // they need to hear about it rather than get a case with nothing in it.
    if (const Status st = rules::Engine::build(packs, engine); !st) fail(st.error);

    // Regions are read through the view the analysis ran on. For a
    // word-swapped image that is the corrected one, which analyze already
    // wrote to flash/ precisely so other things can use it; when it was too
    // large to write, regions are skipped and the sweep says so.
    std::shared_ptr<const Source> view = image;
    const CorrectedView corrected = corrected_view_of(m);
    if (!corrected.path.empty()) {
        std::shared_ptr<MappedFile> f;
        if (const Status st = MappedFile::open((out / corrected.path).string(), f); st)
            view = f;
        else
            view.reset();
    } else if (!corrected_skipped(m).empty()) {
        view.reset();
    }

    rules::ScanLimits limits;
    limits.max_hits_total = a.max_hits;
    rules::SweepResult r;
    if (const Status st =
            rules::sweep(engine, m, listings, view ? Span::whole(view) : Span{}, limits, r);
        !st)
        fail(st.error);

    write_text(out / "artifacts.yaml", rules::artifacts_to_yaml(m, r));
    write_text(out / "artifacts.md", rules::artifacts_to_markdown(m, r));
    spdlog::info("rules: {} hit(s) from {} rule(s) over {} file(s) and {} region(s)", r.hits.size(),
                 engine.content_rules() + engine.path_rules(), r.files_scanned, r.regions_scanned);
    return r;
}

void cmd_analyze(const AnalyzeArgs& a) {
    const auto file = open_image(a.image);
    const bool corpus = a.layout != "flat";
    std::error_code ec;
    std::filesystem::create_directories(a.out, ec);
    if (ec) fail("cannot create '" + a.out + "': " + ec.message());

    Manifest m;
    m.run.version = OMNITRACE_VERSION;
    // Which build, not just which version. A report shows it as "Build", and a
    // case made by a modified tree says so with a `-dirty` suffix.
    m.run.git_sha = OMNITRACE_GIT_SHA;
    m.run.started_at = Clock::now_iso8601();
    m.run.host_os = host_os();
    m.run.argv = g_argv;
    m.case_info = a.case_info;

    discovery::AnalyzeOptions opts;
    opts.out_dir = a.out;
    opts.extract = !a.no_extract;
    opts.history = a.history;
    opts.tar_filesystems = a.tar_filesystems;
    opts.limits = a.limits;
    opts.carve = corpus ? carve_from(a.carve) : discovery::Carve::None;
    opts.max_carve_bytes = a.max_carve_bytes;
    // flash/ only exists in the corpus layout, and that is where a corrected
    // view belongs: it is the image the analysis read, not something carved
    // out of it.
    opts.write_corrected_view = corpus;
    opts.open_reader = [](const std::string& format) {
        return fs::FilesystemRegistry::instance().create(format);
    };
    opts.open_container = [](const std::string& format) {
        return container::ContainerRegistry::instance().create(format);
    };
    if (!corpus && a.carve != "none")
        spdlog::debug("--layout flat: nothing is carved (--carve {} ignored)", a.carve);

    discovery::Listings listings;
    if (const Status st = discovery::analyze(file, a.image, opts, m, listings); !st) fail(st.error);
    if (!m.evidence.empty()) m.evidence.back().acquired_at = file_mtime_iso(a.image);
    m.run.finished_at = Clock::now_iso8601();

    const std::filesystem::path out(a.out);
    const std::string yaml = output::manifest_to_yaml(m);
    if (corpus) {
        write_text(out / "INFO.yaml", yaml);
        alias_manifest(out, yaml);
        write_text(out / "INFO.md", info_markdown(m));
        const std::filesystem::path flash = out / "flash";
        std::filesystem::create_directories(flash, ec);
        if (ec) fail("cannot create '" + flash.string() + "': " + ec.message());
        std::string copied;
        if (a.copy_image && !m.evidence.empty())
            copied = copy_image_into(flash, a.image, m.evidence.back());
        if (!m.evidence.empty())
            write_text(flash / "SOURCE.yaml",
                       source_yaml(m.evidence.back(), copied, corrected_view_of(m), out));
        // What kind of system each extracted filesystem is. Before the
        // rules, because a platform report is the context an examiner reads
        // the hits in.
        analyzers::Survey survey;
        if (const Status st = analyzers::survey(listings, survey); !st) fail(st.error);
        write_text(out / "platform.yaml", analyzers::platform_to_yaml(survey));
        write_text(out / "platform.md", analyzers::platform_to_markdown(survey));
        spdlog::info("platforms: {} of {} filesystem(s) recognised", survey.reports.size(),
                     survey.trees_examined);

        // Files a parser recognises, turned into named records. After the
        // platform report and before the search packs: what a file *is*
        // frames the hits found inside it.
        artifacts::Collection extracted;
        if (const Status st = artifacts::collect(listings, {}, extracted); !st) fail(st.error);
        write_text(out / "certificates.yaml", artifacts::to_yaml(extracted));
        write_text(out / "certificates.md", artifacts::to_markdown(extracted));
        write_extracted_files(out, extracted.files);
        spdlog::info("artifacts: {} record(s) from {} parsed file(s){}", extracted.artifacts.size(),
                     extracted.files_examined,
                     extracted.files.empty()
                         ? std::string{}
                         : ", " + std::to_string(extracted.files.size()) + " table(s) written");

        rules::SweepResult swept;
        if (!a.no_rules) swept = run_rules(a, m, listings, file, out);

        // The report last: it is the only thing that sees all of the run at
        // once. The evidence is re-hashed here rather than trusted, because a
        // report is a claim about specific bytes and saying so is cheap
        // compared with being wrong about it.
        std::vector<report::EvidenceRef> refs;
        for (const Evidence& ev : m.evidence)
            refs.push_back({ev.id, ev.path, ev.digests.sha256, ev.size});
        const report::IntegrityResult integrity = report::verify_evidence(refs);
        if (!integrity.verified)
            spdlog::warn(
                "report: the evidence could not be verified; see the report's first "
                "section");
        const report::Document doc =
            cli::build_report(m, &integrity, &survey, &extracted, a.no_rules ? nullptr : &swept,
                              out.filename().string());
        write_text(out / "report.html", report::to_html(doc));
        write_text(out / "report.md", report::to_markdown(doc));
        spdlog::info("report: {} section(s) written to report.html and report.md",
                     doc.sections.size());
    } else {
        write_text(out / "manifest.yaml", yaml);
    }
    write_text(out / "summary.md", output::summary_markdown(m));
    write_text(out / "partitions.md", output::partitions_markdown(m));
    // A listing lands beside the tree its walk wrote: filesystems/<id> for a
    // Filesystem node, containers/<id> for a Container one (Recurse.h).
    for (const auto& [fs_id, entries] : listings) {
        const Node* owner = m.find(fs_id);
        const char* group =
            owner != nullptr && owner->kind == NodeKind::Container ? "containers" : "filesystems";
        const std::filesystem::path dir = out / group / fs_id;
        std::filesystem::create_directories(dir, ec);
        if (ec) fail("cannot create '" + dir.string() + "': " + ec.message());
        write_text(dir / "listing.yaml", output::listing_to_yaml(fs_id, entries));
        write_text(dir / "listing.md", output::listing_markdown(fs_id, entries));
    }

    // Integrity: what we wrote must read back as the same graph.
    Manifest back;
    if (const Status st = output::manifest_from_yaml(yaml, back); !st)
        fail(std::string(corpus ? "INFO.yaml" : "manifest.yaml") +
             " does not re-parse: " + st.error);
    if (output::manifest_to_yaml(back) != yaml)
        fail(std::string(corpus ? "INFO.yaml" : "manifest.yaml") +
             " does not round-trip byte-identically");

    std::vector<std::vector<std::string>> rows;
    for (const Node& n : m.nodes()) {
        if (n.kind == NodeKind::File) continue;
        std::string extra;
        for (const char* key : {"entries", "files", "compression", "type", "fill"}) {
            const auto it = n.attrs.find(key);
            if (it != n.attrs.end())
                extra += std::string(extra.empty() ? "" : " ") + key + "=" + it->second;
        }
        rows.push_back({n.id, node_kind_name(n.kind), output::hex(n.location.offset),
                        n.location.length ? output::human_bytes(n.location.length) : "?",
                        n.format.empty() ? "-" : n.format,
                        confidence_tier(confidence_from_score(n.confidence)), sanitize_utf8(n.name),
                        extra});
    }
    std::printf("%s: %s, sha256 %s\n\n", a.image.c_str(), output::human_bytes(file->size()).c_str(),
                m.evidence.empty() ? "-" : m.evidence.back().digests.sha256.c_str());
    std::fputs(
        text_table({"Node", "Kind", "Offset", "Size", "Format", "Tier", "Name", "Details"}, rows)
            .c_str(),
        stdout);
    std::printf(
        "\n%zu node(s): %zu partition(s), %zu container(s), %zu filesystem(s), %zu file(s), %zu "
        "region(s)\n",
        m.nodes().size(), m.count(NodeKind::Partition), m.count(NodeKind::Container),
        m.count(NodeKind::Filesystem), m.count(NodeKind::File), m.count(NodeKind::Region));
    for (const Node& n : m.nodes()) {
        const auto it = n.attrs.find("carved_path");
        if (it != n.attrs.end())
            std::printf("carved: %s (%s, sha256 %s)\n", sanitize_utf8(it->second).c_str(),
                        output::human_bytes(n.location.length).c_str(), n.digests.sha256.c_str());
        const auto sk = n.attrs.find("carve_skipped");
        if (sk != n.attrs.end())
            std::printf("carve skipped: %s %s (%s): %s\n", n.id.c_str(),
                        sanitize_utf8(n.name).c_str(),
                        output::human_bytes(n.location.length).c_str(), sk->second.c_str());
    }
    for (const Coverage& c : m.coverage)  // details may quote reader errors: evidence bytes
        std::printf("coverage: %s %s%s%s\n", sanitize_utf8(c.format).c_str(),
                    sanitize_utf8(c.status).c_str(), c.detail.empty() ? "" : " - ",
                    sanitize_utf8(c.detail).c_str());
    std::printf("case directory: %s (%s layout)\n", out.string().c_str(),
                corpus ? "corpus" : "flat");
}

}  // namespace

void set_process_argv(std::vector<std::string> argv) {
    g_argv = std::move(argv);
}

namespace {

// `omnitrace report <case>` — re-render a finished case.
//
// Reads INFO.yaml and every listing.yaml back, then re-runs the analyzers and
// the extractors over the recovered entries. That is the whole point of those
// layers taking entries and nothing about how extraction happened: a case
// directory is enough to re-examine, and none of the evidence is read again
// except to verify it.
//
// The search packs are the one thing not re-*run* -- a sweep wants the image
// rather than the case -- but they do not need to be: the hits the sweep found
// are in artifacts.yaml, and reading them back is the last of the seven
// sections.
//
// The integrity check is why this is worth having even when nothing has
// changed: re-hashing evidence months later, against a case made then, is the
// question to answer before relying on anything in it.
void run_report(const std::string& case_dir, const std::string& out_dir,
                const CaseInfo& override_case) {
    const std::filesystem::path dir(case_dir);
    const std::filesystem::path info = dir / "INFO.yaml";
    std::error_code ec;
    if (!std::filesystem::exists(info, ec))
        fail("no INFO.yaml in '" + case_dir + "': not a case directory");

    std::ifstream f(info, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (text.empty()) fail("'" + info.string() + "' is empty or unreadable");

    Manifest m;
    if (const Status st = output::manifest_from_yaml(text, m); !st) fail(st.error);

    // The case identity comes from the manifest, so a report re-rendered years
    // later still names whoever ran the analysis. A flag given here overrides
    // one field without clearing the others -- an examiner adding a case
    // number to an old case should not silently drop the examiner's name.
    if (!override_case.id.empty()) m.case_info.id = override_case.id;
    if (!override_case.examiner.empty()) m.case_info.examiner = override_case.examiner;
    if (!override_case.notes.empty()) m.case_info.notes = override_case.notes;

    // The listings are what make this more than a re-render of the manifest.
    // The post-analysis layers take entries and nothing about how extraction
    // happened, so recovering entries from the case recovers all of them.
    std::vector<std::pair<std::string, std::vector<EntryResult>>> listings;
    std::vector<Diagnostic> load_diags;
    if (const Status st = output::load_case_listings(case_dir, listings, load_diags); !st)
        fail(st.error);
    for (const Diagnostic& d : load_diags) {
        if (d.severity == Severity::Warning)
            spdlog::warn("{}: {}", d.code, d.message);
        else
            spdlog::info("{}: {}", d.code, d.message);
    }

    analyzers::Survey survey;
    if (const Status st = analyzers::survey(listings, survey); !st) fail(st.error);
    artifacts::Collection extracted;
    if (const Status st = artifacts::collect(listings, {}, extracted); !st) fail(st.error);
    spdlog::info("re-examined {} filesystem(s): {} platform(s), {} artifact record(s)",
                 listings.size(), survey.reports.size(), extracted.artifacts.size());

    std::vector<report::EvidenceRef> refs;
    for (const Evidence& ev : m.evidence)
        refs.push_back({ev.id, ev.path, ev.digests.sha256, ev.size});
    const report::IntegrityResult integrity = report::verify_evidence(refs);

    // The search packs are not re-run -- a sweep needs the image, not the case,
    // and re-reading a 16 GiB dump to re-find hits the case already lists is
    // work for no gain. They are read back instead, so the section is the one
    // the sweep produced rather than a second opinion about it.
    //
    // A case without artifacts.yaml is normal (no packs ran, or an older
    // build), and the section is simply absent. A file that is *there* and
    // does not parse is not: that is said out loud, because silently dropping
    // a section is how a report comes to understate what was found.
    rules::SweepResult hits;
    bool have_hits = false;
    const std::filesystem::path artifacts_yaml = dir / "artifacts.yaml";
    if (std::filesystem::exists(artifacts_yaml, ec)) {
        std::ifstream af(artifacts_yaml, std::ios::binary);
        const std::string atext((std::istreambuf_iterator<char>(af)),
                                std::istreambuf_iterator<char>());
        if (const Status st = rules::artifacts_from_yaml(atext, hits); !st) {
            spdlog::warn("report-hits-unreadable: {}; the search section is omitted", st.error);
        } else {
            have_hits = true;
            spdlog::info("recovered {} search hit(s) from artifacts.yaml", hits.hits.size());
        }
    }

    const report::Document doc = cli::build_report(
        m, &integrity, &survey, &extracted, have_hits ? &hits : nullptr, dir.filename().string());
    // --out writes the report somewhere else and leaves the case untouched,
    // which is what sending a report on without handing over the evidence
    // directory looks like.
    std::filesystem::path dest = dir;
    if (!out_dir.empty()) {
        dest = std::filesystem::path(out_dir);
        std::filesystem::create_directories(dest, ec);
        if (ec) fail("cannot create '" + out_dir + "': " + ec.message());
    }
    write_text(dest / "report.html", report::to_html(doc));
    write_text(dest / "report.md", report::to_markdown(doc));
    // Beside the report rather than inside the case: with --out the case is
    // not modified, and a symbol table the report points at should be
    // wherever the report is.
    write_extracted_files(dest, extracted.files);
    if (!integrity.verified)
        spdlog::warn("the evidence could not be verified; the report's first section says why");
    spdlog::info("report: {} section(s) written to {}/report.html and report.md",
                 doc.sections.size(), dest.string());
}

// `omnitrace diff <a> <b>` — what changed between two finished cases.
//
// The question is "these are two units of the same model, what is different
// about this one?". It is asked of cases rather than of images, so it works
// months later on evidence that is no longer attached, and it spends the same
// decoupling `report` does: both sides are read back with
// `load_case_listings` and the analyzers re-run over the entries.
//
// Nothing is matched on node id. Those are assigned in discovery order and do
// not survive a byte changing earlier in the image, so the same filesystem is
// n000018 in one case and n000021 in the other.
void run_diff(const std::string& case_a, const std::string& case_b, const std::string& out_dir) {
    const auto load = [](const std::string& dir,
                         std::vector<std::pair<std::string, std::vector<EntryResult>>>& out,
                         analyzers::Survey& survey, artifacts::Collection& records) {
        std::error_code ec;
        if (!std::filesystem::exists(std::filesystem::path(dir) / "INFO.yaml", ec))
            fail("no INFO.yaml in '" + dir + "': not a case directory");
        std::vector<Diagnostic> diags;
        if (const Status st = output::load_case_listings(dir, out, diags); !st) fail(st.error);
        for (const Diagnostic& d : diags)
            if (d.severity == Severity::Warning) spdlog::warn("{}: {}", d.code, d.message);
        if (const Status st = analyzers::survey(out, survey); !st) fail(st.error);
        // The extractors are re-run rather than read out of certificates.yaml:
        // what a record *is* comes from parsing the file, and the file is
        // still in the case.
        if (const Status st = artifacts::collect(out, {}, records); !st) fail(st.error);
    };

    // Every symbol table a case holds, concatenated. A case with two kernels
    // is compared as the union of what they contain, which is the honest
    // answer to "does this unit have that driver" when neither case says
    // which kernel is the one that boots.
    const auto read_symbols = [](const std::string& dir) {
        std::string all;
        std::error_code ec;
        const std::filesystem::path root = std::filesystem::path(dir) / "symbols";
        if (!std::filesystem::is_directory(root, ec)) return all;
        std::vector<std::filesystem::path> files;
        for (const auto& e : std::filesystem::directory_iterator(root, ec))
            if (e.is_regular_file()) files.push_back(e.path());
        std::sort(files.begin(), files.end());  // deterministic
        for (const std::filesystem::path& f : files) {
            std::ifstream in(f, std::ios::binary);
            all.append((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        }
        return all;
    };

    std::vector<std::pair<std::string, std::vector<EntryResult>>> ea, eb;
    analyzers::Survey sa, sb;
    artifacts::Collection ra, rb;
    load(case_a, ea, sa, ra);
    load(case_b, eb, sb, rb);

    diff::CaseDiff d =
        diff::compare(ea, eb, sa, sb, ra, rb, read_symbols(case_a), read_symbols(case_b));
    d.label_a = case_a;
    d.label_b = case_b;

    const std::filesystem::path dest =
        out_dir.empty() ? std::filesystem::current_path() : std::filesystem::path(out_dir);
    if (!out_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(dest, ec);
        if (ec) fail("cannot create '" + out_dir + "': " + ec.message());
    }
    write_text(dest / "diff.md", diff::to_markdown(d));
    write_text(dest / "diff.yaml", diff::to_yaml(d));

    std::printf("files: %llu in A, %llu in B\n", static_cast<unsigned long long>(d.files.files_a),
                static_cast<unsigned long long>(d.files.files_b));
    std::printf("same %llu, changed %llu, only in A %llu, only in B %llu, moved %llu\n",
                static_cast<unsigned long long>(d.files.same),
                static_cast<unsigned long long>(d.files.changed_total),
                static_cast<unsigned long long>(d.files.removed_total),
                static_cast<unsigned long long>(d.files.added_total),
                static_cast<unsigned long long>(d.files.moved));
    if (!d.platform.empty()) std::printf("platform facts that differ: %zu\n", d.platform.size());
    if (d.artifacts.records_a != 0 || d.artifacts.records_b != 0)
        std::printf(
            "parsed records: %llu in A, %llu in B; same %llu, changed %llu, only in A %llu, "
            "only in B %llu\n",
            static_cast<unsigned long long>(d.artifacts.records_a),
            static_cast<unsigned long long>(d.artifacts.records_b),
            static_cast<unsigned long long>(d.artifacts.same),
            static_cast<unsigned long long>(d.artifacts.changed_total),
            static_cast<unsigned long long>(d.artifacts.removed_total),
            static_cast<unsigned long long>(d.artifacts.added_total));
    if (d.symbols.present_a || d.symbols.present_b)
        std::printf("kernel symbols: %llu shared, %llu only in A, %llu only in B\n",
                    static_cast<unsigned long long>(d.symbols.common),
                    static_cast<unsigned long long>(d.symbols.only_a_total),
                    static_cast<unsigned long long>(d.symbols.only_b_total));
    if (d.identical()) std::printf("the two cases are the same in every way this compares\n");
    for (const Diagnostic& g : d.diagnostics)
        spdlog::warn("{}: {}", g.code, sanitize_utf8(g.message));
    std::printf("written: %s/diff.md and diff.yaml\n", dest.string().c_str());
}

}  // namespace

void register_analyze_commands(CLI::App& app) {
    auto* rep = app.add_subcommand("report", "Re-render a finished case directory as a report");
    auto case_dir = std::make_shared<std::string>();
    auto rep_out = std::make_shared<std::string>();
    auto rep_case = std::make_shared<CaseInfo>();
    rep->add_option("case", *case_dir, "Case directory written by analyze")
        ->required()
        ->check(CLI::ExistingDirectory);
    rep->add_option("--out", *rep_out,
                    "Directory to write report.html and report.md to (default: the case "
                    "directory). The case itself is never modified");
    // The examiner's statement about the case, not anything the tool derives.
    // Spelled out on both subcommands rather than shared through a helper
    // because scripts/gen_docs.py resolves a flag to its subcommand through
    // the variable it is registered on, and a helper's parameter resolves to
    // neither. Keep these three identical to the `analyze` copies below.
    rep->add_option("--case-id", rep_case->id, "Case, exhibit or job number, recorded and reported")
        ->group("Case");
    rep->add_option("--examiner", rep_case->examiner, "Who ran the tool, recorded and reported")
        ->group("Case");
    rep->add_option("--notes", rep_case->notes, "Free text carried into the report header")
        ->group("Case");
    rep->callback([case_dir, rep_out, rep_case]() { run_report(*case_dir, *rep_out, *rep_case); });

    auto* dif = app.add_subcommand("diff", "Compare two finished case directories");
    auto diff_a = std::make_shared<std::string>();
    auto diff_b = std::make_shared<std::string>();
    auto diff_out = std::make_shared<std::string>();
    dif->add_option("case-a", *diff_a, "The first case directory")
        ->required()
        ->check(CLI::ExistingDirectory);
    dif->add_option("case-b", *diff_b, "The second case directory")
        ->required()
        ->check(CLI::ExistingDirectory);
    dif->add_option("--out", *diff_out,
                    "Directory to write diff.md and diff.yaml to (default: the working "
                    "directory). Neither case is modified");
    dif->callback([diff_a, diff_b, diff_out]() { run_diff(*diff_a, *diff_b, *diff_out); });

    auto scan_args = std::make_shared<std::pair<std::string, bool>>();
    auto* scan = app.add_subcommand("scan", "Find format signatures in an image");
    scan->add_option("image", scan_args->first, "Path to image")
        ->required()
        ->check(CLI::ExistingFile);
    scan->add_flag("--json", scan_args->second, "Print findings as JSON");
    scan->callback([scan_args] { cmd_scan(scan_args->first, scan_args->second); });

    auto args = std::make_shared<AnalyzeArgs>();
    auto* analyze = app.add_subcommand("analyze", "Analyze an image into a case directory");
    analyze->add_option("image", args->image, "Path to image")
        ->required()
        ->check(CLI::ExistingFile);
    analyze->add_option("-o,--out", args->out, "Case directory (created)")->required();
    analyze
        ->add_option("--layout", args->layout,
                     "corpus: INFO.yaml/INFO.md, flash/, partitions/ (default); flat: "
                     "manifest.yaml, summary.md, partitions.md, filesystems/ and containers/ only")
        ->check(CLI::IsMember({"corpus", "flat"}))
        ->capture_default_str();
    analyze
        ->add_option("--carve", args->carve,
                     "What to carve into partitions/: none, table (partition-table entries) "
                     "or all (entries plus nested finds)")
        ->check(CLI::IsMember({"none", "table", "all"}))
        ->capture_default_str();
    analyze
        ->add_option("--max-carve-bytes", args->max_carve_bytes,
                     "Largest file to carve (bytes; suffixes K/M/G/T are 1024-based); larger "
                     "partitions are skipped with a coverage row, as is a corrected view of a "
                     "word-swapped image. The default is 32 GiB because eMMC and UFS partitions "
                     "reach that; free space is guarded separately and every carve is checked "
                     "against it as it is written")
        ->transform(CLI::AsSizeValue(false))
        ->capture_default_str();
    analyze->add_flag("--no-rules", args->no_rules,
                      "Skip the search packs; the case gets no artifacts.yaml");
    analyze
        ->add_option("--rules", args->rule_packs,
                     "Add a YAML rule pack (repeatable); the built-in packs still run")
        ->check(CLI::ExistingFile);
    analyze->add_option("--max-hits", args->max_hits, "Rule hits to keep per run")
        ->capture_default_str();
    analyze->add_flag("--copy-image", args->copy_image,
                      "Copy the image into flash/ (verified by hash); by default only "
                      "flash/SOURCE.yaml refers to it");
    analyze->add_flag("--no-extract", args->no_extract, "List filesystems without writing files");
    analyze->add_flag(
        "--tar-filesystems", args->tar_filesystems,
        "Also write filesystems/<node>/files.tar and containers/<node>/files.tar: a faithful "
        "archive of each extracted tree, for handing the case to someone else. Copying a tree "
        "onto exFAT, a Windows share or cloud storage silently drops its symlinks, its "
        "permission bits and any name that is not valid UTF-8; a tar keeps them. Roughly "
        "doubles the space a case takes");
    analyze->add_flag("--history", args->history,
                      "Recover superseded and deleted versions when the format keeps them");
    analyze->add_option("--max-depth", args->limits.max_depth, "Nested extraction levels")
        ->capture_default_str();
    analyze->add_option("--max-files", args->limits.max_files, "Entries per run")
        ->capture_default_str();
    // Given explicitly, --max-bytes is the budget exactly: clearing the ratio
    // stops analyze() raising it to track the image size (core/Limits.h).
    CLI::Option* max_bytes =
        analyze
            ->add_option("--max-bytes", args->limits.max_bytes,
                         "Total bytes written per run; the default is the larger of this and "
                         "--max-bytes-ratio x the image, so it tracks the evidence")
            ->transform(CLI::AsSizeValue(false))
            ->capture_default_str();
    CLI::Option* ratio =
        analyze
            ->add_option("--max-bytes-ratio", args->limits.max_bytes_ratio,
                         "Extraction budget as a multiple of the image size; 0 uses --max-bytes "
                         "exactly, which is also what passing --max-bytes alone does")
            ->capture_default_str();
    // Given explicitly, --max-file-bytes is the cap exactly: clearing the
    // ratio stops analyze() raising it to the image size (core/Limits.h).
    CLI::Option* max_file_bytes =
        analyze
            ->add_option("--max-file-bytes", args->limits.max_file_bytes,
                         "Largest single extracted entry (bytes; suffixes K/M/G/T are "
                         "1024-based); a larger entry is cut there with a "
                         "<fmt>-limit-file-bytes warning. The default is the larger of this "
                         "and the image size, since a stored entry cannot exceed the image "
                         "that holds it")
            ->transform(CLI::AsSizeValue(false))
            ->capture_default_str();
    analyze->parse_complete_callback([args, max_bytes, ratio, max_file_bytes]() {
        // --max-bytes alone means "that budget, exactly". Given both, the
        // examiner said what they wanted twice and both are honoured.
        if (max_bytes->count() > 0 && ratio->count() == 0) args->limits.max_bytes_ratio = 0;
        // Same for one entry; there is no --max-file-bytes-ratio to combine
        // with, so naming the cap always means it exactly.
        if (max_file_bytes->count() > 0) args->limits.max_file_bytes_ratio = 0;
    });
    // Keep identical to the `report` copies above; see the note there.
    analyze
        ->add_option("--case-id", args->case_info.id,
                     "Case, exhibit or job number, recorded and reported")
        ->group("Case");
    analyze
        ->add_option("--examiner", args->case_info.examiner,
                     "Who ran the tool, recorded and reported")
        ->group("Case");
    analyze
        ->add_option("--notes", args->case_info.notes, "Free text carried into the report header")
        ->group("Case");
    analyze->callback([args] { cmd_analyze(*args); });
}
