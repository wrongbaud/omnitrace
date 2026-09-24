// Diff.cpp — comparing two finished cases. See the header for why nothing is
// matched by node id.
#include "omnitrace/diff/Diff.h"

#include <algorithm>
#include <map>
#include <set>

#include "omnitrace/core/Text.h"

namespace omnitrace::diff {

namespace {

constexpr const char* kCodeEmpty = "diff-case-empty";
constexpr const char* kCodeNoSymbols = "diff-symbols-one-sided";

/// What one case holds, flattened.
///
/// Flattened on purpose: a path is keyed on its own, not on the filesystem it
/// came from, because the node ids that would identify that filesystem are
/// assigned in discovery order and do not survive a byte changing earlier in
/// the image. A path that occurs in more than one filesystem keeps every
/// digest found at it, so "the same path with the same contents" stays true
/// when a case has two copies of a file.
struct Flat {
    // path -> the digests found at it, and where
    std::map<std::string, std::set<std::string>> by_path;
    std::map<std::string, std::string> node_of;   // path -> first node seen
    std::map<std::string, std::uint64_t> size_of; // path -> first size seen
    std::set<std::string> contents;               // every distinct sha256
    std::uint64_t files = 0;
};

Flat flatten(const analyzers::FilesystemEntries& fs) {
    Flat f;
    for (const auto& [node, entries] : fs) {
        for (const EntryResult& e : entries) {
            if (e.meta.kind != EntryKind::Regular) continue;
            // History is not the system as it was running, and a deleted file
            // present in one case and not the other says something about
            // recovery rather than about the device.
            if (e.meta.deleted || e.meta.superseded) continue;
            if (e.digests.sha256.empty()) continue;
            const std::string path = sanitize_utf8(e.meta.path);
            ++f.files;
            f.by_path[path].insert(e.digests.sha256);
            f.node_of.emplace(path, node);
            f.size_of.emplace(path, e.digests.bytes);
            f.contents.insert(e.digests.sha256);
        }
    }
    return f;
}

std::string first_of(const std::set<std::string>& s) {
    return s.empty() ? std::string{} : *s.begin();
}

/// Symbol names out of an nm-format table: "c0100000 T _stext".
std::set<std::string> symbol_names(const std::string& text) {
    std::set<std::string> out;
    std::size_t at = 0;
    while (at < text.size()) {
        std::size_t nl = text.find('\n', at);
        if (nl == std::string::npos) nl = text.size();
        const std::string_view line(text.data() + at, nl - at);
        at = nl + 1;
        // The name is whatever follows the last space; nm leaves the address
        // column blank when it is unknown, so the line may start with spaces.
        const std::size_t sp = line.rfind(' ');
        if (sp == std::string_view::npos || sp + 1 >= line.size()) continue;
        out.emplace(line.substr(sp + 1));
    }
    return out;
}

void cap(std::vector<std::string>& v, std::size_t max) {
    if (v.size() > max) v.resize(max);
}

}  // namespace

CaseDiff compare(const analyzers::FilesystemEntries& a, const analyzers::FilesystemEntries& b,
                 const analyzers::Survey& survey_a, const analyzers::Survey& survey_b,
                 const std::string& symbols_a, const std::string& symbols_b,
                 const DiffLimits& limits) {
    CaseDiff d;
    const Flat fa = flatten(a);
    const Flat fb = flatten(b);

    d.files.files_a = fa.files;
    d.files.files_b = fb.files;
    d.files.contents_a = fa.contents.size();
    d.files.contents_b = fb.contents.size();

    // An empty side makes every number below meaningless, and a diff that
    // reports "everything was removed" over a case whose files were never
    // extracted is worse than one that refuses to.
    if (fa.files == 0 || fb.files == 0)
        d.diagnostics.push_back(
            {Severity::Warning, kCodeEmpty,
             std::string("one case holds no extracted files (") + std::to_string(fa.files) +
                 " and " + std::to_string(fb.files) +
                 "), so every difference below is an artefact of that rather than of the "
                 "devices; check whether it was analysed with --no-extract"});

    for (const auto& [path, digests] : fa.by_path) {
        const auto it = fb.by_path.find(path);
        if (it == fb.by_path.end()) {
            FileChange c;
            c.path = path;
            c.node_a = fa.node_of.at(path);
            c.sha_a = first_of(digests);
            c.size_a = fa.size_of.at(path);
            d.files.removed.push_back(std::move(c));
            continue;
        }
        if (digests == it->second) {
            ++d.files.same;
            continue;
        }
        FileChange c;
        c.path = path;
        c.node_a = fa.node_of.at(path);
        c.node_b = fb.node_of.at(path);
        c.sha_a = first_of(digests);
        c.sha_b = first_of(it->second);
        c.size_a = fa.size_of.at(path);
        c.size_b = fb.size_of.at(path);
        d.files.changed.push_back(std::move(c));
    }
    for (const auto& [path, digests] : fb.by_path) {
        if (fa.by_path.count(path) != 0) continue;
        FileChange c;
        c.path = path;
        c.node_b = fb.node_of.at(path);
        c.sha_b = first_of(digests);
        c.size_b = fb.size_of.at(path);
        d.files.added.push_back(std::move(c));
    }

    // The content view, which is what survives a rename.
    std::set<std::string> common;
    std::set_intersection(fa.contents.begin(), fa.contents.end(), fb.contents.begin(),
                          fb.contents.end(), std::inserter(common, common.end()));
    d.files.contents_common = common.size();
    // A content in both cases that no *shared* path accounts for has moved.
    std::set<std::string> at_shared_paths;
    for (const auto& [path, digests] : fa.by_path) {
        const auto it = fb.by_path.find(path);
        if (it == fb.by_path.end()) continue;
        for (const std::string& s : digests)
            if (it->second.count(s) != 0) at_shared_paths.insert(s);
    }
    for (const std::string& s : common)
        if (at_shared_paths.count(s) == 0) ++d.files.moved;

    // What each system says about itself. The analyzers are re-run over both
    // cases by the caller; here the facts are keyed on their own name, across
    // every filesystem in a case, because the reports that carry them are
    // identified by node id and those do not survive between cases. A key
    // that a case states more than once keeps every value, so a disagreement
    // inside one case is not mistaken for a difference between them.
    {
        std::map<std::string, std::set<std::string>> ka, kb;
        for (const analyzers::Report& r : survey_a.reports)
            for (const analyzers::Fact& f : r.facts) ka[f.key].insert(f.value);
        for (const analyzers::Report& r : survey_b.reports)
            for (const analyzers::Fact& f : r.facts) kb[f.key].insert(f.value);
        const auto join = [](const std::set<std::string>& v) {
            std::string out;
            for (const std::string& x : v) {
                if (!out.empty()) out += " | ";
                if (out.size() > 300) {
                    out += "...";
                    break;
                }
                out += x;
            }
            return out;
        };
        std::set<std::string> keys;
        for (const auto& [k, v] : ka) keys.insert(k);
        for (const auto& [k, v] : kb) keys.insert(k);
        for (const std::string& k : keys) {
            const auto ia = ka.find(k);
            const auto ib = kb.find(k);
            const std::set<std::string> va = ia == ka.end() ? std::set<std::string>{} : ia->second;
            const std::set<std::string> vb = ib == kb.end() ? std::set<std::string>{} : ib->second;
            if (va == vb) continue;
            d.platform.push_back({k, join(va), join(vb)});
        }
    }

    // Symbols, by name. Addresses move whenever anything is recompiled, so
    // comparing them would report every kernel as entirely different; what
    // says a driver was added or removed is the name.
    d.symbols.present_a = !symbols_a.empty();
    d.symbols.present_b = !symbols_b.empty();
    if (d.symbols.present_a || d.symbols.present_b) {
        const std::set<std::string> sa = symbol_names(symbols_a);
        const std::set<std::string> sb = symbol_names(symbols_b);
        d.symbols.symbols_a = sa.size();
        d.symbols.symbols_b = sb.size();
        for (const std::string& s : sa) {
            if (sb.count(s) != 0) {
                ++d.symbols.common;
            } else {
                ++d.symbols.only_a_total;
                d.symbols.only_a.push_back(s);
            }
        }
        for (const std::string& s : sb) {
            if (sa.count(s) != 0) continue;
            ++d.symbols.only_b_total;
            d.symbols.only_b.push_back(s);
        }
        cap(d.symbols.only_a, limits.max_listed);
        cap(d.symbols.only_b, limits.max_listed);
        if (d.symbols.present_a != d.symbols.present_b) {
            // With nothing to compare against, "14,589 symbols only in A" is
            // every symbol A has, and listing two hundred of them reads like
            // a finding when it is an absence. The counts stay; the names go.
            d.symbols.only_a.clear();
            d.symbols.only_b.clear();
            d.diagnostics.push_back(
                {Severity::Info, kCodeNoSymbols,
                 "only one case has a kernel symbol table, so its symbols are counted rather "
                 "than compared and are not listed: the other kernel may have been built "
                 "without CONFIG_KALLSYMS, or not been found at all"});
        }
    }

    // The totals are taken *before* the lists are capped. A diff of two
    // different models is every file in both, and a report that lists 60,000
    // of them is not a report -- but one that then calls 200 the answer is
    // worse than one that lists nothing.
    d.files.added_total = d.files.added.size();
    d.files.removed_total = d.files.removed.size();
    d.files.changed_total = d.files.changed.size();
    const auto cap_changes = [&](std::vector<FileChange>& v) {
        if (v.size() > limits.max_listed) v.resize(limits.max_listed);
    };
    cap_changes(d.files.added);
    cap_changes(d.files.removed);
    cap_changes(d.files.changed);
    return d;
}

}  // namespace omnitrace::diff
