// analyze_commands.cpp — `omnitrace scan` and `omnitrace analyze`.
//
// scan:    findings only, as an aligned table or JSON.
// analyze: the Phase 0 case directory (DEVELOPMENT_PLAN.md §6): manifest.yaml,
//          summary.md, partitions.md, filesystems/<id>/{listing.yaml,listing.md,files/}.
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "commands.h"
#include "omnitrace/core/Clock.h"
#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/discovery/Recurse.h"
#include "omnitrace/discovery/Signature.h"
#include "omnitrace/filesystems/Filesystem.h"
#include "omnitrace/output/Markdown.h"
#include "omnitrace/output/Yaml.h"

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
        s += k + "=" + v;
    }
    return s;
}

// ------------------------------------------------------------------- scan

nlohmann::json finding_json(const discovery::Finding& f) {
    nlohmann::json j;
    j["offset"] = f.offset;
    j["offset_hex"] = output::hex(f.offset);
    j["size"] = f.size;
    j["format"] = f.format;
    j["category"] = f.category;
    j["signature"] = f.signature;
    j["confidence"] = static_cast<int>(f.confidence);
    j["tier"] = confidence_tier(f.confidence);
    j["evidence"] = f.evidence;
    j["endian"] = endian_name(f.endian);
    j["attrs"] = nlohmann::json::object();
    for (const auto& [k, v] : f.attrs) j["attrs"][k] = v;
    j["diagnostics"] = nlohmann::json::array();
    for (const Diagnostic& d : f.diagnostics)
        j["diagnostics"].push_back(
            {{"severity", severity_name(d.severity)}, {"code", d.code}, {"message", d.message}});
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
        out["image"] = path;
        out["size"] = file->size();
        out["findings"] = nlohmann::json::array();
        for (const auto& f : findings) out["findings"].push_back(finding_json(f));
        std::printf("%s\n", out.dump(2).c_str());
        return;
    }
    std::vector<std::vector<std::string>> rows;
    for (const auto& f : findings) {
        rows.push_back({output::hex(f.offset), f.size ? dec(f.size) : "?", f.format,
                        confidence_tier(f.confidence), f.evidence, attrs_text(f.attrs)});
    }
    std::printf("%s: %s, %zu finding(s)\n\n", path.c_str(),
                output::human_bytes(file->size()).c_str(), findings.size());
    std::fputs(text_table({"Offset", "Size", "Format", "Tier", "Evidence", "Attrs"}, rows).c_str(),
               stdout);
}

// ---------------------------------------------------------------- analyze

struct AnalyzeArgs {
    std::string image, out;
    bool no_extract = false, history = false;
    Limits limits;
};

void cmd_analyze(const AnalyzeArgs& a) {
    const auto file = open_image(a.image);
    std::error_code ec;
    std::filesystem::create_directories(a.out, ec);
    if (ec) fail("cannot create '" + a.out + "': " + ec.message());

    Manifest m;
    m.run.version = OMNITRACE_VERSION;
    m.run.started_at = Clock::now_iso8601();
    m.run.host_os = host_os();
    m.run.argv = g_argv;

    discovery::AnalyzeOptions opts;
    opts.out_dir = a.out;
    opts.extract = !a.no_extract;
    opts.history = a.history;
    opts.limits = a.limits;
    opts.open_reader = [](const std::string& format) {
        return fs::FilesystemRegistry::instance().create(format);
    };

    discovery::Listings listings;
    if (const Status st = discovery::analyze(file, a.image, opts, m, listings); !st) fail(st.error);
    if (!m.evidence.empty()) m.evidence.back().acquired_at = file_mtime_iso(a.image);
    m.run.finished_at = Clock::now_iso8601();

    const std::filesystem::path out(a.out);
    const std::string yaml = output::manifest_to_yaml(m);
    write_text(out / "manifest.yaml", yaml);
    write_text(out / "summary.md", output::summary_markdown(m));
    write_text(out / "partitions.md", output::partitions_markdown(m));
    for (const auto& [fs_id, entries] : listings) {
        const std::filesystem::path dir = out / "filesystems" / fs_id;
        std::filesystem::create_directories(dir, ec);
        if (ec) fail("cannot create '" + dir.string() + "': " + ec.message());
        write_text(dir / "listing.yaml", output::listing_to_yaml(fs_id, entries));
        write_text(dir / "listing.md", output::listing_markdown(fs_id, entries));
    }

    // Integrity: what we wrote must read back as the same graph.
    Manifest back;
    if (const Status st = output::manifest_from_yaml(yaml, back); !st)
        fail("manifest.yaml does not re-parse: " + st.error);
    if (output::manifest_to_yaml(back) != yaml)
        fail("manifest.yaml does not round-trip byte-identically");

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
                        confidence_tier(confidence_from_score(n.confidence)), n.name, extra});
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
    for (const Coverage& c : m.coverage)
        std::printf("coverage: %s %s%s%s\n", c.format.c_str(), c.status.c_str(),
                    c.detail.empty() ? "" : " - ", c.detail.c_str());
    std::printf("case directory: %s\n", out.string().c_str());
}

}  // namespace

void set_process_argv(std::vector<std::string> argv) {
    g_argv = std::move(argv);
}

void register_analyze_commands(CLI::App& app) {
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
    analyze->add_flag("--no-extract", args->no_extract, "List filesystems without writing files");
    analyze->add_flag("--history", args->history,
                      "Recover superseded and deleted versions when the format keeps them");
    analyze->add_option("--max-depth", args->limits.max_depth, "Nested extraction levels")
        ->capture_default_str();
    analyze->add_option("--max-files", args->limits.max_files, "Entries per run")
        ->capture_default_str();
    analyze->add_option("--max-bytes", args->limits.max_bytes, "Total bytes written per run")
        ->capture_default_str();
    analyze->callback([args] { cmd_analyze(*args); });
}
