// Markdown.cpp — human/agent readable renderings of the case. Every function
// is a pure function of its input: same Manifest -> same bytes. No clock, no
// locale, no unordered containers.
#include "omnitrace/output/Markdown.h"

#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "Common.h"
#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::output {

namespace {

using detail::dec;

// Every evidence-derived string is sanitized to valid UTF-8 first (Text.h),
// then Markdown-escaped; the two steps compose (an escape's backslash is
// itself escaped) so the document is always valid UTF-8 and valid Markdown.
std::string esc(const std::string& s) {
    return md_escape(sanitize_utf8(s));
}

std::string tier_label(std::uint8_t score) {
    return std::string(confidence_tier(confidence_from_score(score))) + " (" + dec(score) + ")";
}

std::size_t warning_count(const std::vector<Diagnostic>& ds) {
    std::size_t n = 0;
    for (const Diagnostic& d : ds) {
        if (d.severity != Severity::Info) ++n;
    }
    return n;
}

std::string size_cell(std::uint64_t length) {
    if (length == 0) return "unknown";
    return human_bytes(length) + " (" + dec(length) + ")";
}

std::string join_argv(const std::vector<std::string>& argv) {
    std::string out;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        if (i) out += ' ';
        out += argv[i];
    }
    return out;
}

std::string dash_if_empty(const std::string& s) {
    return s.empty() ? "-" : esc(s);
}

std::string diagnostics_table(const std::vector<Diagnostic>& ds) {
    std::vector<std::vector<std::string>> rows;
    for (const Diagnostic& d : ds) {
        rows.push_back({severity_name(d.severity), esc(d.code), esc(d.message)});
    }
    return md_table({"Severity", "Code", "Message"}, rows);
}

// Depth-first walk over the graph in child_ids order, starting at the roots
// (nodes with an empty parent, or whose parent is not in the graph) in
// insertion order. Every node is visited at most once even if links form a
// cycle in a hostile manifest.
void walk(const Manifest& m, const std::function<void(const Node&, std::size_t)>& fn) {
    std::map<std::string, std::size_t> index;
    for (std::size_t i = 0; i < m.nodes().size(); ++i) index.emplace(m.nodes()[i].id, i);
    std::vector<bool> seen(m.nodes().size(), false);
    std::function<void(const std::string&, std::size_t)> visit = [&](const std::string& id,
                                                                     std::size_t depth) {
        const auto it = index.find(id);
        if (it == index.end() || seen[it->second]) return;
        seen[it->second] = true;
        const Node& n = m.nodes()[it->second];
        fn(n, depth);
        for (const std::string& cid : n.child_ids) visit(cid, depth + 1);
    };
    for (const Node& n : m.nodes()) {
        if (n.parent_id.empty() || index.find(n.parent_id) == index.end()) visit(n.id, 0);
    }
    // Nodes only reachable through a cycle (never a root, never reached from
    // one) still get a row so nothing is silently dropped.
    for (std::size_t i = 0; i < m.nodes().size(); ++i) {
        if (!seen[i]) visit(m.nodes()[i].id, 0);
    }
}

bool is_structural(NodeKind k) {
    return k == NodeKind::Image || k == NodeKind::Partition || k == NodeKind::Container ||
           k == NodeKind::Filesystem || k == NodeKind::Region;
}

}  // namespace

std::string md_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        switch (c) {
            case '|':
                out += "\\|";
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
                if (c < 0x20 || c == 0x7f) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\x%02x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(ch);
                }
        }
    }
    return out;
}

std::string md_table(const std::vector<std::string>& header,
                     const std::vector<std::vector<std::string>>& rows) {
    std::string out;
    out += '|';
    for (const std::string& h : header) {
        out += ' ';
        out += h;
        out += " |";
    }
    out += "\n|";
    for (std::size_t i = 0; i < header.size(); ++i) out += "---|";
    out += '\n';
    for (const std::vector<std::string>& row : rows) {
        out += '|';
        for (std::size_t i = 0; i < header.size(); ++i) {
            out += ' ';
            if (i < row.size()) out += row[i];
            out += " |";
        }
        out += '\n';
    }
    return out;
}

std::string human_bytes(std::uint64_t n) {
    static constexpr const char* kUnits[] = {"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    if (n < 1024) return dec(n) + " B";
    // Find the largest unit with a value >= 1, then render one decimal using
    // integer arithmetic so the text never depends on the C locale.
    int unit = 0;
    std::uint64_t divisor = 1024;
    while (unit < 5 && n / divisor >= 1024) {
        divisor <<= 10;
        ++unit;
    }
    // tenths = round(n * 10 / divisor) without overflowing: split into the
    // integer part and the remainder.
    const std::uint64_t whole = n / divisor;
    const std::uint64_t rem = n % divisor;
    std::uint64_t tenths = (rem * 10 + divisor / 2) / divisor;  // rem < 2^60 so rem*10 fits
    std::uint64_t w = whole;
    if (tenths >= 10) {
        tenths -= 10;
        ++w;
    }
    return dec(w) + "." + dec(tenths) + " " + kUnits[unit];
}

std::string hex(std::uint64_t v) {
    char buf[32];
    const int n = std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    if (n <= 0) return "0x0";
    return std::string(buf, static_cast<std::size_t>(n));
}

std::string summary_markdown(const Manifest& m) {
    std::string out = "# OmniTrace summary\n\n";

    out += "## Run\n\n";
    out += md_table({"Field", "Value"}, {{"tool", dash_if_empty(m.run.tool)},
                                         {"version", dash_if_empty(m.run.version)},
                                         {"git_sha", dash_if_empty(m.run.git_sha)},
                                         {"started_at", dash_if_empty(m.run.started_at)},
                                         {"finished_at", dash_if_empty(m.run.finished_at)},
                                         {"host_os", dash_if_empty(m.run.host_os)},
                                         {"argv", dash_if_empty(join_argv(m.run.argv))}});

    out += "\n## Evidence\n\n";
    {
        std::vector<std::vector<std::string>> rows;
        for (const Evidence& ev : m.evidence) {
            rows.push_back({esc(ev.id), esc(ev.path),
                            human_bytes(ev.size) + " (" + dec(ev.size) + ")",
                            dash_if_empty(ev.digests.md5), dash_if_empty(ev.digests.sha1),
                            dash_if_empty(ev.digests.sha256), dash_if_empty(ev.acquired_at),
                            dash_if_empty(ev.note)});
        }
        out +=
            md_table({"Id", "Path", "Size", "MD5", "SHA-1", "SHA-256", "Acquired", "Note"}, rows);
    }

    out += "\n## Nodes by kind\n\n";
    {
        static constexpr NodeKind kKinds[] = {
            NodeKind::Image, NodeKind::Partition, NodeKind::Container, NodeKind::Filesystem,
            NodeKind::File,  NodeKind::Region,    NodeKind::Artifact};
        std::vector<std::vector<std::string>> rows;
        for (const NodeKind k : kKinds) rows.push_back({node_kind_name(k), dec(m.count(k))});
        rows.push_back({"total", dec(m.nodes().size())});
        out += md_table({"Kind", "Count"}, rows);
    }

    out += "\n## Map\n\n";
    {
        std::size_t lines = 0;
        walk(m, [&](const Node& n, std::size_t depth) {
            if (!is_structural(n.kind)) return;
            out += std::string(depth * 2, ' ');
            out += "- `" + esc(n.id) + "` " + node_kind_name(n.kind);
            if (!n.format.empty()) out += " " + esc(n.format);
            if (!n.name.empty()) out += " \"" + esc(n.name) + "\"";
            out += " @ " + hex(n.location.offset) + " " + size_cell(n.location.length);
            out += " [" + tier_label(n.confidence) + "]\n";
            ++lines;
        });
        if (lines == 0) out += "(no structural nodes)\n";
    }

    out += "\n## Coverage\n\n";
    {
        std::vector<std::vector<std::string>> rows;
        for (const Coverage& c : m.coverage) {
            rows.push_back({esc(c.format), esc(c.status), esc(c.detail)});
        }
        out += md_table({"Format", "Status", "Detail"}, rows);
    }

    out += "\n## Diagnostics\n\n";
    out += diagnostics_table(m.diagnostics);
    return out;
}

std::string partitions_markdown(const Manifest& m) {
    std::string out = "# Partitions\n\n";
    std::vector<std::vector<std::string>> rows;
    walk(m, [&](const Node& n, std::size_t depth) {
        if (!is_structural(n.kind)) return;
        rows.push_back({hex(n.location.offset), size_cell(n.location.length),
                        node_kind_name(n.kind), dash_if_empty(n.format), tier_label(n.confidence),
                        std::string(depth * 2, ' ') + "`" + esc(n.id) + "` " + esc(n.name),
                        dec(warning_count(n.diagnostics))});
    });
    out += md_table({"Offset", "Size", "Kind", "Format", "Confidence", "Name", "Warnings"}, rows);
    return out;
}

std::string listing_markdown(const std::string& fs_node_id,
                             const std::vector<EntryResult>& entries) {
    std::string out = "# Listing for `" + esc(fs_node_id) + "`\n\n";
    std::vector<std::vector<std::string>> rows;
    for (const EntryResult& r : entries) {
        const FileMeta& f = r.meta;
        std::string flags;
        if (f.deleted) flags += 'D';
        if (f.superseded) flags += 'S';
        if (flags.empty()) flags = "-";
        std::string mtime = "-";
        if (f.mtime) {
            mtime = detail::iso8601(*f.mtime);
            if (mtime.empty()) mtime = detail::dec_signed(*f.mtime);
        }
        std::string sha = "-";
        if (!r.digests.sha256.empty()) sha = esc(r.digests.sha256.substr(0, 12));
        std::string path = esc(f.path);
        if (!f.link_target.empty()) path += " -> " + esc(f.link_target);
        rows.push_back({path, entry_kind_name(f.kind), dec(f.size), detail::mode_octal(f.mode),
                        dec(f.uid) + ":" + dec(f.gid), mtime, sha, flags, dec(f.version)});
    }
    out += md_table(
        {"Path", "Kind", "Size", "Mode", "Owner", "Mtime", "SHA-256", "Flags", "Version"}, rows);
    return out;
}

}  // namespace omnitrace::output
