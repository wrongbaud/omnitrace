// Tree.cpp — the path namespace an analyzer sees. See Platform.h.
//
// Everything here works off the listing a reader produced, never off the host
// filesystem, with one exception: reading a file's *contents* opens the
// `host_path` the Sink recorded. Path resolution never touches the host,
// because a symlink in evidence is attacker-controlled and following it on the
// host is how an extraction escapes its case directory.
#include <algorithm>
#include <fstream>

#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::analyzers {

namespace {

// Link chains are evidence and may be circular or absurdly deep. A real one
// is one or two hops.
constexpr int kMaxLinkHops = 16;

std::string_view strip_slashes(std::string_view p) {
    while (!p.empty() && p.front() == '/') p.remove_prefix(1);
    while (!p.empty() && p.back() == '/') p.remove_suffix(1);
    return p;
}

// Resolve `target` against the directory holding `from`, POSIX-style, and
// normalise `.` and `..` without ever escaping the root: a target of
// `../../../../etc/passwd` from `etc/` lands on `etc/passwd`, which is what
// the filesystem itself would do at its own root.
std::string join_link(std::string_view from, std::string_view target) {
    std::vector<std::string_view> parts;
    if (!target.empty() && target.front() == '/') {
        // Absolute inside the filesystem, so start from its root.
    } else {
        const std::size_t slash = from.rfind('/');
        std::string_view dir =
            slash == std::string_view::npos ? std::string_view{} : from.substr(0, slash);
        while (!dir.empty()) {
            const std::size_t s = dir.find('/');
            if (s == std::string_view::npos) {
                parts.push_back(dir);
                break;
            }
            parts.push_back(dir.substr(0, s));
            dir.remove_prefix(s + 1);
        }
    }
    std::string_view t = strip_slashes(target);
    while (!t.empty()) {
        const std::size_t s = t.find('/');
        const std::string_view seg = s == std::string_view::npos ? t : t.substr(0, s);
        if (seg == "..") {
            if (!parts.empty()) parts.pop_back();
        } else if (!seg.empty() && seg != ".") {
            parts.push_back(seg);
        }
        if (s == std::string_view::npos) break;
        t.remove_prefix(s + 1);
    }
    std::string out;
    for (const std::string_view& p : parts) {
        if (!out.empty()) out += '/';
        out.append(p);
    }
    return out;
}

}  // namespace

const char* platform_name(Platform p) {
    switch (p) {
        case Platform::Linux:
            return "linux";
        case Platform::Android:
            return "android";
        case Platform::Qnx:
            return "qnx";
        case Platform::Rtos:
            return "rtos";
        case Platform::Unknown:
            break;
    }
    return "unknown";
}

Tree::Tree(const std::vector<EntryResult>& entries) {
    for (const EntryResult& e : entries) {
        // History is not the system as it was running. A deleted or superseded
        // version has its own value, but answering "what is this system?" from
        // one would describe a machine that no longer existed.
        if (e.meta.deleted || e.meta.superseded) continue;
        const std::string_view path = strip_slashes(e.meta.path);
        if (path.empty()) continue;
        // First writer wins, so a later duplicate path cannot shadow the entry
        // an examiner would see.
        by_path_.emplace(std::string(path), Entry{&e});
    }
}

std::size_t Tree::size() const {
    return by_path_.size();
}

const EntryResult* Tree::find(std::string_view path) const {
    std::string cur(strip_slashes(path));
    for (int hop = 0; hop < kMaxLinkHops; ++hop) {
        const auto it = by_path_.find(cur);
        if (it == by_path_.end()) return nullptr;
        const EntryResult* e = it->second.e;
        if (e->meta.kind != EntryKind::Symlink) return e;
        if (e->meta.link_target.empty()) return nullptr;
        std::string next = join_link(cur, e->meta.link_target);
        if (next.empty() || next == cur) return nullptr;
        cur = std::move(next);
    }
    return nullptr;  // a link loop, or a chain deeper than any real one
}

bool Tree::has_file(std::string_view path) const {
    const EntryResult* e = find(path);
    return e != nullptr && e->meta.kind == EntryKind::Regular;
}

bool Tree::has_dir(std::string_view path) const {
    const EntryResult* e = find(path);
    return e != nullptr && e->meta.kind == EntryKind::Directory;
}

std::string Tree::first_of(const std::vector<std::string>& paths) const {
    for (const std::string& p : paths)
        if (has_file(p)) return p;
    return {};
}

std::optional<std::string> Tree::read(std::string_view path, std::size_t max) const {
    const EntryResult* e = find(path);
    if (e == nullptr || e->meta.kind != EntryKind::Regular) return std::nullopt;
    if (e->host_path.empty() || !e->written) return std::nullopt;
    std::ifstream f(e->host_path, std::ios::binary);
    if (!f) return std::nullopt;
    std::string buf(max, '\0');
    f.read(buf.data(), static_cast<std::streamsize>(max));
    buf.resize(static_cast<std::size_t>(f.gcount()));
    return sanitize_utf8(buf);
}

std::vector<std::string> Tree::list_dir(std::string_view dir) const {
    std::vector<std::string> out;
    const std::string base(strip_slashes(dir));
    if (!base.empty() && !has_dir(base)) return out;
    const std::string prefix = base.empty() ? std::string{} : base + "/";
    for (auto it = by_path_.lower_bound(prefix); it != by_path_.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        const std::string_view rest(it->first.data() + prefix.size(),
                                    it->first.size() - prefix.size());
        if (rest.empty() || rest.find('/') != std::string_view::npos) continue;  // not direct
        out.emplace_back(rest);
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace omnitrace::analyzers
