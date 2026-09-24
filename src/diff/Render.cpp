// Render.cpp — the comparison, for a person and for a machine.
#include <string>
#include <vector>

#include "omnitrace/core/Text.h"
#include "omnitrace/diff/Diff.h"
#include "omnitrace/output/Markdown.h"

namespace omnitrace::diff {

namespace {

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

std::string esc(const std::string& s) {
    return output::md_escape(sanitize_utf8(s));
}

/// "abcd1234…" — enough of a digest to compare by eye, not enough to pretend
/// the table is the evidence.
std::string shortsha(const std::string& s) {
    return s.size() > 12 ? s.substr(0, 12) : s;
}

std::string yaml_quote(const std::string& raw) {
    const std::string s = sanitize_utf8(raw);
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
    out += '"';
    return out;
}

void listing(std::string& out, const char* title, const std::vector<FileChange>& v,
             std::uint64_t total, bool with_both) {
    if (total == 0) return;
    out += "### " + std::string(title) + " (" + dec(total) + ")\n\n";
    std::vector<std::string> header{"Path", "Size"};
    if (with_both) header = {"Path", "Size in A", "Size in B", "sha256 A", "sha256 B"};
    std::vector<std::vector<std::string>> rows;
    for (const FileChange& c : v) {
        if (with_both)
            rows.push_back({esc(c.path), dec(c.size_a), dec(c.size_b), shortsha(c.sha_a),
                            shortsha(c.sha_b)});
        else
            rows.push_back({esc(c.path), dec(c.size_a != 0 ? c.size_a : c.size_b)});
    }
    out += output::md_table(header, rows);
    if (v.size() < total)
        out += "\n" + dec(total - v.size()) + " more, in `diff.yaml`.\n";
    out += "\n";
}

}  // namespace

std::string to_markdown(const CaseDiff& d) {
    std::string out = "# Case comparison\n\n";
    out += "**A**: `" + esc(d.label_a) + "`  \n**B**: `" + esc(d.label_b) + "`\n\n";
    out +=
        "Files are compared by path and, separately, by content. Nothing is matched on node "
        "id: those are assigned in discovery order and do not survive a byte changing earlier "
        "in the image.\n\n";

    if (d.identical())
        out +=
            "> **The two cases hold the same files, the same platform facts and the same "
            "kernel symbols.**\n\n";

    out += "| | A | B |\n|---|---:|---:|\n";
    out += "| Files | " + dec(d.files.files_a) + " | " + dec(d.files.files_b) + " |\n";
    out += "| Distinct contents | " + dec(d.files.contents_a) + " | " + dec(d.files.contents_b) +
           " |\n\n";

    out += "| | |\n|---|---:|\n";
    out += "| Same path, same contents | " + dec(d.files.same) + " |\n";
    out += "| Same path, different contents | " + dec(d.files.changed_total) + " |\n";
    out += "| Only in A | " + dec(d.files.removed_total) + " |\n";
    out += "| Only in B | " + dec(d.files.added_total) + " |\n";
    out += "| Contents in both | " + dec(d.files.contents_common) + " |\n";
    out += "| Contents in both under no shared path (moved) | " + dec(d.files.moved) + " |\n\n";

    if (!d.platform.empty()) {
        out += "## What each system says about itself\n\n";
        std::vector<std::vector<std::string>> rows;
        for (const FactChange& f : d.platform)
            rows.push_back({esc(f.key), esc(f.a.empty() ? "—" : f.a), esc(f.b.empty() ? "—" : f.b)});
        out += output::md_table({"Fact", "A", "B"}, rows);
        out += "\n";
    }

    if (d.symbols.present_a || d.symbols.present_b) {
        out += "## Kernel symbols\n\n";
        out +=
            "Compared by name. Addresses move whenever anything is recompiled, so comparing "
            "those would report every kernel as entirely different; a name appearing or "
            "disappearing is what says a driver was added or removed.\n\n";
        out += "| | A | B |\n|---|---:|---:|\n";
        out += "| Symbols | " + dec(d.symbols.symbols_a) + " | " + dec(d.symbols.symbols_b) +
               " |\n";
        out += "| In both | " + dec(d.symbols.common) + " | " + dec(d.symbols.common) + " |\n";
        out += "| Only here | " + dec(d.symbols.only_a_total) + " | " +
               dec(d.symbols.only_b_total) + " |\n\n";
        if (d.symbols.present_a != d.symbols.present_b)
            out +=
                "Only one case has a table, so these are counted rather than compared. See the "
                "note at the end.\n\n";
        const auto names = [&](const char* title, const std::vector<std::string>& v,
                               std::uint64_t total) {
            // No names to show is not the same as none to count: with only one
            // table the count stands alone (see `compare`).
            if (total == 0 || v.empty()) return;
            out += "**" + std::string(title) + "** (" + dec(total) + "): ";
            for (std::size_t i = 0; i < v.size(); ++i) {
                if (i != 0) out += ", ";
                out += "`" + esc(v[i]) + "`";
            }
            if (v.size() < total) out += ", … " + dec(total - v.size()) + " more";
            out += "\n\n";
        };
        names("Only in A", d.symbols.only_a, d.symbols.only_a_total);
        names("Only in B", d.symbols.only_b, d.symbols.only_b_total);
    }

    if (d.files.changed_total != 0 || d.files.removed_total != 0 || d.files.added_total != 0) {
        out += "## Files\n\n";
        listing(out, "Same path, different contents", d.files.changed, d.files.changed_total, true);
        listing(out, "Only in A", d.files.removed, d.files.removed_total, false);
        listing(out, "Only in B", d.files.added, d.files.added_total, false);
    }

    for (const Diagnostic& g : d.diagnostics)
        out += "> **" + std::string(severity_name(g.severity)) + "** `" + g.code + "` — " +
               esc(g.message) + "\n\n";
    return out;
}

std::string to_yaml(const CaseDiff& d) {
    std::string y = "schema: omnitrace-diff/1\n";
    y += "a: " + yaml_quote(d.label_a) + "\n";
    y += "b: " + yaml_quote(d.label_b) + "\n";
    y += std::string("identical: ") + (d.identical() ? "true" : "false") + "\n";
    y += "files:\n";
    y += "  files_a: " + dec(d.files.files_a) + "\n";
    y += "  files_b: " + dec(d.files.files_b) + "\n";
    y += "  contents_a: " + dec(d.files.contents_a) + "\n";
    y += "  contents_b: " + dec(d.files.contents_b) + "\n";
    y += "  contents_common: " + dec(d.files.contents_common) + "\n";
    y += "  moved: " + dec(d.files.moved) + "\n";
    y += "  same: " + dec(d.files.same) + "\n";
    y += "  changed: " + dec(d.files.changed_total) + "\n";
    y += "  only_a: " + dec(d.files.removed_total) + "\n";
    y += "  only_b: " + dec(d.files.added_total) + "\n";

    const auto emit = [&](const char* key, const std::vector<FileChange>& v, std::uint64_t total) {
        y += std::string("  ") + key + ":\n";
        y += "    total: " + dec(total) + "\n";
        y += "    listed:\n";
        if (v.empty()) y += "      []\n";
        for (const FileChange& c : v) {
            y += "      - path: " + yaml_quote(c.path) + "\n";
            if (!c.sha_a.empty()) {
                y += "        sha256_a: " + yaml_quote(c.sha_a) + "\n";
                y += "        size_a: " + dec(c.size_a) + "\n";
                y += "        node_a: " + yaml_quote(c.node_a) + "\n";
            }
            if (!c.sha_b.empty()) {
                y += "        sha256_b: " + yaml_quote(c.sha_b) + "\n";
                y += "        size_b: " + dec(c.size_b) + "\n";
                y += "        node_b: " + yaml_quote(c.node_b) + "\n";
            }
        }
    };
    emit("changed_files", d.files.changed, d.files.changed_total);
    emit("only_a_files", d.files.removed, d.files.removed_total);
    emit("only_b_files", d.files.added, d.files.added_total);

    y += "platform:\n";
    if (d.platform.empty()) y += "  []\n";
    for (const FactChange& f : d.platform) {
        y += "  - key: " + yaml_quote(f.key) + "\n";
        y += "    a: " + yaml_quote(f.a) + "\n";
        y += "    b: " + yaml_quote(f.b) + "\n";
    }

    y += "symbols:\n";
    y += std::string("  present_a: ") + (d.symbols.present_a ? "true" : "false") + "\n";
    y += std::string("  present_b: ") + (d.symbols.present_b ? "true" : "false") + "\n";
    y += "  symbols_a: " + dec(d.symbols.symbols_a) + "\n";
    y += "  symbols_b: " + dec(d.symbols.symbols_b) + "\n";
    y += "  common: " + dec(d.symbols.common) + "\n";
    const auto emit_names = [&](const char* key, const std::vector<std::string>& v,
                                std::uint64_t total) {
        y += std::string("  ") + key + ":\n";
        y += "    total: " + dec(total) + "\n";
        y += "    listed:\n";
        if (v.empty()) y += "      []\n";
        for (const std::string& n : v) y += "      - " + yaml_quote(n) + "\n";
    };
    emit_names("only_a", d.symbols.only_a, d.symbols.only_a_total);
    emit_names("only_b", d.symbols.only_b, d.symbols.only_b_total);

    y += "diagnostics:\n";
    if (d.diagnostics.empty()) y += "  []\n";
    for (const Diagnostic& g : d.diagnostics) {
        y += "  - severity: " + std::string(severity_name(g.severity)) + "\n";
        y += "    code: " + g.code + "\n";
        y += "    message: " + yaml_quote(g.message) + "\n";
    }
    return y;
}

}  // namespace omnitrace::diff
