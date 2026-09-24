// Yaml.cpp — manifest.yaml / listing.yaml serialization and the JSON Schema
// that describes manifest.yaml.
//
// Key order is fixed and documented in manifest_json_schema(); the emitter
// writes keys in exactly that order so the same Manifest always yields the
// same bytes (ARCHITECTURE.md rule 5). Conventions:
//   * offsets, sizes and counters are decimal integers; `offset_hex` is a
//     quoted "0x..." twin for humans and is ignored on read;
//   * unix timestamps carry an ISO-8601 twin (`mtime` + `mtime_iso`, ...);
//     the twin is ignored on read;
//   * `deleted` / `superseded` are written only when true and `version` only
//     when > 0 so listings of live trees stay small;
//   * strings that would read as another YAML type (numbers, booleans, null,
//     hex/octal) are double-quoted so any YAML 1.1/1.2 consumer sees a string.
#include "omnitrace/output/Yaml.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "Common.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::output {

namespace {

using detail::dec;

// ---------------------------------------------------------------------------
// Emission helpers
// ---------------------------------------------------------------------------

bool looks_like_non_string(const std::string& s) {
    if (s.empty()) return true;
    // Leading/trailing whitespace would be lost by a plain scalar.
    if (s.front() == ' ' || s.back() == ' ' || s.front() == '\t' || s.back() == '\t') return true;
    // YAML 1.1 booleans and null in any capitalisation.
    static constexpr const char* kWords[] = {"true", "false", "yes",   "no",   "on",  "off",
                                             "y",    "n",     "null",  "~",    "nan", "inf",
                                             ".nan", ".inf",  "-.inf", "+.inf"};
    std::string lower;
    lower.reserve(s.size());
    for (const char c : s)
        lower.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    for (const char* w : kWords) {
        if (lower == w) return true;
    }
    // YAML 1.1 timestamps ("2026-01-02T03:04:05Z", "2026-01-02") become
    // datetime objects in some consumers.
    const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    if (s.size() >= 5 && is_digit(s[0]) && is_digit(s[1]) && is_digit(s[2]) && is_digit(s[3]) &&
        s[4] == '-') {
        return true;
    }
    // Anything that starts like a number: digits, sign, dot. Every such
    // string might be a number/hex/octal/float/sexagesimal for some parser.
    const char c0 = s.front();
    if ((c0 >= '0' && c0 <= '9') || c0 == '-' || c0 == '+' || c0 == '.') {
        for (const char c : s) {
            const bool numeric_ish = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                     (c >= 'A' && c <= 'F') || c == 'x' || c == 'X' || c == 'o' ||
                                     c == 'O' || c == '+' || c == '-' || c == '.' || c == '_' ||
                                     c == ':' || c == 'e' || c == 'E';
            if (!numeric_ish) return false;
        }
        return true;
    }
    return false;
}

// Emit a string value, forcing quotes when a plain scalar would be ambiguous.
// Every string scalar (keys included) funnels through here, so evidence bytes
// that are not valid UTF-8 (a gzip original name, a partition label) become
// "\xNN" escapes instead of poisoning the document (Text.h).
YAML::Emitter& str(YAML::Emitter& e, const std::string& raw) {
    const std::string s = sanitize_utf8(raw);
    if (looks_like_non_string(s)) {
        e << YAML::DoubleQuoted << s;
    } else {
        e << s;
    }
    return e;
}

std::string hex_string(std::uint64_t v) {
    char buf[32];
    const int n = std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    if (n <= 0) return "0x0";
    return std::string(buf, static_cast<std::size_t>(n));
}

std::string double_text(double d) {
    if (std::isnan(d)) return ".nan";
    if (std::isinf(d)) return d < 0 ? "-.inf" : ".inf";
    char buf[64];
    const auto r = std::to_chars(buf, buf + sizeof buf, d);
    if (r.ec != std::errc{}) return "0";
    std::string out(buf, r.ptr);
    // Keep the scalar recognisably a float ("5" -> "5.0") so a YAML 1.2 core
    // schema consumer types it as a number, not an integer.
    if (out.find_first_of(".eEn") == std::string::npos) out += ".0";
    return out;
}

void emit_key_u64(YAML::Emitter& e, const char* key, std::uint64_t v) {
    e << YAML::Key << key << YAML::Value << static_cast<unsigned long long>(v);
}

void emit_key_str(YAML::Emitter& e, const char* key, const std::string& v) {
    e << YAML::Key << key << YAML::Value;
    str(e, v);
}

// Empty containers are written in flow style (`[]` / `{}`) on the key's line.
void begin_seq(YAML::Emitter& e, bool empty) {
    if (empty) e << YAML::Flow;
    e << YAML::BeginSeq;
}

void begin_map(YAML::Emitter& e, bool empty) {
    if (empty) e << YAML::Flow;
    e << YAML::BeginMap;
}

void emit_string_seq(YAML::Emitter& e, const char* key, const std::vector<std::string>& v) {
    e << YAML::Key << key << YAML::Value;
    begin_seq(e, v.empty());
    for (const std::string& s : v) str(e, s);
    e << YAML::EndSeq;
}

void emit_string_map(YAML::Emitter& e, const char* key,
                     const std::map<std::string, std::string>& m) {
    // Order by the *sanitized* key, not the raw one, so a manifest read back
    // from disk (whose keys are already escaped text) re-emits byte-identical.
    // Two raw keys that sanitize to the same text would be a duplicate YAML
    // key; the first in raw order wins so the document stays loadable.
    std::map<std::string, std::string> clean;
    for (const auto& [k, v] : m) clean.emplace(sanitize_utf8(k), v);
    e << YAML::Key << key << YAML::Value;
    begin_map(e, clean.empty());
    for (const auto& [k, v] : clean) {
        e << YAML::Key;
        str(e, k);
        e << YAML::Value;
        str(e, v);
    }
    e << YAML::EndMap;
}

void emit_digests(YAML::Emitter& e, const Digests& d) {
    e << YAML::Key << "digests" << YAML::Value << YAML::BeginMap;
    emit_key_str(e, "md5", d.md5);
    emit_key_str(e, "sha1", d.sha1);
    emit_key_str(e, "sha256", d.sha256);
    emit_key_u64(e, "bytes", d.bytes);
    e << YAML::EndMap;
}

void emit_diagnostics(YAML::Emitter& e, const std::vector<Diagnostic>& ds) {
    e << YAML::Key << "diagnostics" << YAML::Value;
    begin_seq(e, ds.empty());
    for (const Diagnostic& d : ds) {
        e << YAML::BeginMap;
        emit_key_str(e, "severity", severity_name(d.severity));
        emit_key_str(e, "code", d.code);
        emit_key_str(e, "message", d.message);
        e << YAML::EndMap;
    }
    e << YAML::EndSeq;
}

void emit_timestamp(YAML::Emitter& e, const char* key, const char* iso_key,
                    const std::optional<std::int64_t>& t) {
    if (!t) return;
    e << YAML::Key << key << YAML::Value << static_cast<long long>(*t);
    const std::string iso = detail::iso8601(*t);
    if (!iso.empty()) emit_key_str(e, iso_key, iso);
}

void emit_nsec(YAML::Emitter& e, const char* key, const std::optional<std::uint32_t>& v) {
    if (v) emit_key_u64(e, key, *v);
}

void emit_file_meta(YAML::Emitter& e, const FileMeta& f) {
    e << YAML::Key << "file" << YAML::Value << YAML::BeginMap;
    emit_key_str(e, "path", f.path);
    emit_key_str(e, "kind", entry_kind_name(f.kind));
    emit_key_u64(e, "mode", f.mode);
    emit_key_str(e, "mode_octal", detail::mode_octal(f.mode));
    emit_key_u64(e, "uid", f.uid);
    emit_key_u64(e, "gid", f.gid);
    emit_key_u64(e, "size", f.size);
    emit_timestamp(e, "mtime", "mtime_iso", f.mtime);
    emit_nsec(e, "mtime_nsec", f.mtime_nsec);
    emit_timestamp(e, "ctime", "ctime_iso", f.ctime);
    emit_nsec(e, "ctime_nsec", f.ctime_nsec);
    emit_timestamp(e, "atime", "atime_iso", f.atime);
    emit_nsec(e, "atime_nsec", f.atime_nsec);
    emit_timestamp(e, "crtime", "crtime_iso", f.crtime);
    emit_key_u64(e, "inode", f.inode);
    emit_key_u64(e, "nlink", f.nlink);
    if (!f.link_target.empty()) emit_key_str(e, "link_target", f.link_target);
    const bool is_device = f.kind == EntryKind::CharDevice || f.kind == EntryKind::BlockDevice;
    if (is_device || f.rdev_major != 0 || f.rdev_minor != 0) {
        emit_key_u64(e, "rdev_major", f.rdev_major);
        emit_key_u64(e, "rdev_minor", f.rdev_minor);
    }
    if (f.deleted) e << YAML::Key << "deleted" << YAML::Value << true;
    if (f.superseded) e << YAML::Key << "superseded" << YAML::Value << true;
    if (f.version > 0) emit_key_u64(e, "version", f.version);
    if (!f.extra.empty()) emit_string_map(e, "extra", f.extra);
    e << YAML::EndMap;
}

void emit_node(YAML::Emitter& e, const Node& n) {
    e << YAML::BeginMap;
    emit_key_str(e, "id", n.id);
    emit_key_str(e, "parent", n.parent_id);
    emit_key_str(e, "kind", node_kind_name(n.kind));
    emit_key_str(e, "name", n.name);
    emit_key_str(e, "format", n.format);
    e << YAML::Key << "location" << YAML::Value << YAML::BeginMap;
    emit_key_str(e, "source", n.location.source_id);
    emit_key_u64(e, "offset", n.location.offset);
    emit_key_str(e, "offset_hex", hex_string(n.location.offset));
    emit_key_u64(e, "length", n.location.length);
    e << YAML::EndMap;
    emit_key_u64(e, "confidence", n.confidence);
    emit_key_str(e, "evidence", n.evidence);
    emit_key_str(e, "endian", endian_name(n.endian));
    emit_string_map(e, "attrs", n.attrs);
    if (n.file) emit_file_meta(e, *n.file);
    if (!n.digests.empty()) emit_digests(e, n.digests);
    emit_diagnostics(e, n.diagnostics);
    emit_string_seq(e, "children", n.child_ids);
    e << YAML::EndMap;
}

std::string finish(YAML::Emitter& e) {
    std::string out = e.c_str() ? e.c_str() : "";
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    return out;
}

// ---------------------------------------------------------------------------
// Parsing helpers. Every accessor reports the context ("node n000003") and the
// key on failure and never throws for bad input.
// ---------------------------------------------------------------------------

struct Ctx {
    std::string where;
    std::string error;  // first error wins
    bool ok() const { return error.empty(); }
    bool fail(const std::string& key, const std::string& what) {
        if (error.empty()) error = where + ": key '" + key + "' " + what;
        return false;
    }
};

bool parse_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty()) return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out, 10);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

bool parse_i64(const std::string& s, std::int64_t& out) {
    if (s.empty()) return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out, 10);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

bool parse_double(const std::string& s, double& out) {
    if (s == ".nan" || s == ".NaN" || s == ".NAN") {
        out = std::nan("");
        return true;
    }
    if (s == ".inf" || s == "+.inf" || s == ".Inf" || s == ".INF") {
        out = INFINITY;
        return true;
    }
    if (s == "-.inf" || s == "-.Inf" || s == "-.INF") {
        out = -INFINITY;
        return true;
    }
    if (s.empty()) return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

// Missing key: leave `out` untouched and succeed (unless required).
bool get_str(const YAML::Node& map, const char* key, std::string& out, Ctx& c,
             bool required = false) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return required ? c.fail(key, "is required") : true;
    if (!v.IsScalar()) return c.fail(key, "must be a string");
    out = v.Scalar();
    return true;
}

template <class T>
bool get_uint(const YAML::Node& map, const char* key, T& out, Ctx& c,
              std::uint64_t max = std::uint64_t{0} - 1) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    std::uint64_t tmp = 0;
    if (!v.IsScalar() || !parse_u64(v.Scalar(), tmp))
        return c.fail(key, "must be a non-negative integer");
    if (tmp > max) return c.fail(key, "is out of range (max " + dec(max) + ")");
    out = static_cast<T>(tmp);
    return true;
}

bool get_opt_i64(const YAML::Node& map, const char* key, std::optional<std::int64_t>& out, Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    std::int64_t tmp = 0;
    if (!v.IsScalar() || !parse_i64(v.Scalar(), tmp)) return c.fail(key, "must be an integer");
    out = tmp;
    return true;
}

bool get_opt_u32(const YAML::Node& map, const char* key, std::optional<std::uint32_t>& out,
                 Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    std::uint32_t tmp = 0;
    if (!get_uint(map, key, tmp, c, 0xFFFFFFFFu)) return false;
    out = tmp;
    return true;
}

bool get_bool(const YAML::Node& map, const char* key, bool& out, Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    if (!v.IsScalar()) return c.fail(key, "must be a boolean");
    const std::string& s = v.Scalar();
    if (s == "true") {
        out = true;
    } else if (s == "false") {
        out = false;
    } else {
        return c.fail(key, "must be a boolean");
    }
    return true;
}

bool get_double(const YAML::Node& map, const char* key, double& out, Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    double tmp = 0;
    if (!v.IsScalar() || !parse_double(v.Scalar(), tmp)) return c.fail(key, "must be a number");
    out = tmp;
    return true;
}

bool get_string_seq(const YAML::Node& map, const char* key, std::vector<std::string>& out, Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    if (!v.IsSequence()) return c.fail(key, "must be a sequence of strings");
    out.clear();
    for (const YAML::Node& item : v) {
        if (!item.IsScalar()) return c.fail(key, "must be a sequence of strings");
        out.push_back(item.Scalar());
    }
    return true;
}

bool get_string_map(const YAML::Node& map, const char* key, std::map<std::string, std::string>& out,
                    Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) return true;
    if (!v.IsMap()) return c.fail(key, "must be a map of strings");
    out.clear();
    for (const auto& kv : v) {
        if (!kv.first.IsScalar() || !kv.second.IsScalar())
            return c.fail(key, "must be a map of strings");
        out[kv.first.Scalar()] = kv.second.Scalar();
    }
    return true;
}

// Returns the sub-map or an undefined node; fails only when present and not a map.
bool get_map(const YAML::Node& map, const char* key, YAML::Node& out, Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) {
        out = YAML::Node(YAML::NodeType::Undefined);
        return true;
    }
    if (!v.IsMap()) return c.fail(key, "must be a map");
    out = v;
    return true;
}

bool get_seq(const YAML::Node& map, const char* key, YAML::Node& out, Ctx& c) {
    const YAML::Node v = map[key];
    if (!v.IsDefined() || v.IsNull()) {
        out = YAML::Node(YAML::NodeType::Undefined);
        return true;
    }
    if (!v.IsSequence()) return c.fail(key, "must be a sequence");
    out = v;
    return true;
}

bool read_digests(const YAML::Node& map, Digests& out, Ctx& c) {
    YAML::Node d;
    if (!get_map(map, "digests", d, c)) return false;
    if (!d.IsDefined()) return true;
    Ctx sub{c.where + " digests", {}};
    const bool ok = get_str(d, "md5", out.md5, sub) && get_str(d, "sha1", out.sha1, sub) &&
                    get_str(d, "sha256", out.sha256, sub) && get_uint(d, "bytes", out.bytes, sub);
    if (!ok) c.error = sub.error;
    return ok;
}

bool read_diagnostics(const YAML::Node& map, std::vector<Diagnostic>& out, Ctx& c) {
    YAML::Node seq;
    if (!get_seq(map, "diagnostics", seq, c)) return false;
    if (!seq.IsDefined()) return true;
    out.clear();
    std::size_t i = 0;
    for (const YAML::Node& item : seq) {
        if (!item.IsMap()) return c.fail("diagnostics", "item " + dec(i) + " must be a map");
        Ctx sub{c.where + " diagnostics[" + dec(i) + "]", {}};
        Diagnostic d;
        std::string sev = "info";
        if (!get_str(item, "severity", sev, sub) || !get_str(item, "code", d.code, sub) ||
            !get_str(item, "message", d.message, sub)) {
            c.error = sub.error;
            return false;
        }
        const auto s = detail::severity_from_name(sev);
        if (!s) {
            sub.fail("severity", "has unknown value '" + sev + "'");
            c.error = sub.error;
            return false;
        }
        d.severity = *s;
        out.push_back(std::move(d));
        ++i;
    }
    return true;
}

bool read_file_meta(const YAML::Node& map, FileMeta& f, Ctx& c) {
    std::string kind = entry_kind_name(f.kind);
    if (!get_str(map, "path", f.path, c) || !get_str(map, "kind", kind, c) ||
        !get_uint(map, "mode", f.mode, c, 0xFFFFFFFFu) ||
        !get_uint(map, "uid", f.uid, c, 0xFFFFFFFFu) ||
        !get_uint(map, "gid", f.gid, c, 0xFFFFFFFFu) || !get_uint(map, "size", f.size, c) ||
        !get_opt_i64(map, "mtime", f.mtime, c) ||
        !get_opt_u32(map, "mtime_nsec", f.mtime_nsec, c) ||
        !get_opt_i64(map, "ctime", f.ctime, c) ||
        !get_opt_u32(map, "ctime_nsec", f.ctime_nsec, c) ||
        !get_opt_i64(map, "atime", f.atime, c) ||
        !get_opt_u32(map, "atime_nsec", f.atime_nsec, c) ||
        !get_opt_i64(map, "crtime", f.crtime, c) || !get_uint(map, "inode", f.inode, c) ||
        !get_uint(map, "nlink", f.nlink, c, 0xFFFFFFFFu) ||
        !get_str(map, "link_target", f.link_target, c) ||
        !get_uint(map, "rdev_major", f.rdev_major, c, 0xFFFFFFFFu) ||
        !get_uint(map, "rdev_minor", f.rdev_minor, c, 0xFFFFFFFFu) ||
        !get_bool(map, "deleted", f.deleted, c) || !get_bool(map, "superseded", f.superseded, c) ||
        !get_uint(map, "version", f.version, c) || !get_string_map(map, "extra", f.extra, c)) {
        return false;
    }
    const auto k = detail::entry_kind_from_name(kind);
    if (!k) return c.fail("kind", "has unknown value '" + kind + "'");
    f.kind = *k;
    return true;
}

bool read_location(const YAML::Node& map, Location& loc, Ctx& c) {
    YAML::Node l;
    if (!get_map(map, "location", l, c)) return false;
    if (!l.IsDefined()) return true;
    Ctx sub{c.where + " location", {}};
    const bool ok = get_str(l, "source", loc.source_id, sub) &&
                    get_uint(l, "offset", loc.offset, sub) &&
                    get_uint(l, "length", loc.length, sub);
    if (!ok) c.error = sub.error;
    return ok;
}

bool read_node(const YAML::Node& map, std::size_t index, Manifest& m, Ctx& c) {
    if (!map.IsMap()) return c.fail("nodes", "item " + dec(index) + " must be a map");
    Node n;
    std::string id;
    Ctx pre{"node #" + dec(index + 1), {}};
    if (!get_str(map, "id", id, pre, true)) {
        c.error = pre.error;
        return false;
    }
    Ctx sub{"node " + id, {}};
    std::string kind, endian = endian_name(n.endian);
    bool ok = get_str(map, "parent", n.parent_id, sub) && get_str(map, "kind", kind, sub, true) &&
              get_str(map, "name", n.name, sub) && get_str(map, "format", n.format, sub) &&
              read_location(map, n.location, sub) &&
              get_uint(map, "confidence", n.confidence, sub, 100) &&
              get_str(map, "evidence", n.evidence, sub) && get_str(map, "endian", endian, sub) &&
              get_string_map(map, "attrs", n.attrs, sub) && read_digests(map, n.digests, sub) &&
              read_diagnostics(map, n.diagnostics, sub);
    if (ok) {
        const auto k = node_kind_from_name(kind);
        if (!k)
            ok = sub.fail("kind", "has unknown value '" + kind + "'");
        else
            n.kind = *k;
    }
    if (ok) {
        const auto en = detail::endian_from_name(endian);
        if (!en)
            ok = sub.fail("endian", "has unknown value '" + endian + "'");
        else
            n.endian = *en;
    }
    YAML::Node file;
    if (ok) ok = get_map(map, "file", file, sub);
    if (ok && file.IsDefined()) {
        FileMeta f;
        Ctx fsub{sub.where + " file", {}};
        ok = read_file_meta(file, f, fsub);
        if (!ok)
            sub.error = fsub.error;
        else
            n.file = std::move(f);
    }
    if (!ok) {
        c.error = sub.error;
        return false;
    }
    // Ids are assigned by the graph in insertion order; the file must agree or
    // every parent/child reference in it would point somewhere else.
    const std::string parent = n.parent_id;
    const std::vector<Diagnostic> diags = n.diagnostics;
    Node& stored = m.add_node(std::move(n));
    if (stored.id != id) {
        sub.fail("id", "is '" + id + "' but position " + dec(index + 1) + " in `nodes` must be '" +
                           stored.id + "' (ids are sequential)");
        c.error = sub.error;
        return false;
    }
    // add_node appends "manifest-parent-missing" when the parent is unknown;
    // the file already records that from the original run. Keep the file's
    // diagnostics, adding the link warning only if it was never recorded.
    stored.diagnostics = diags;
    if (!parent.empty() && m.find(parent) == nullptr) {
        bool have = false;
        for (const Diagnostic& d : stored.diagnostics) {
            if (d.code == "manifest-parent-missing") have = true;
        }
        if (!have) {
            stored.diagnostics.push_back({Severity::Warning, "manifest-parent-missing",
                                          "parent node '" + parent + "' is not in the graph"});
        }
    }
    return true;
}

bool read_run(const YAML::Node& root, RunInfo& r, Ctx& c) {
    YAML::Node run;
    if (!get_map(root, "run", run, c)) return false;
    if (!run.IsDefined()) return true;
    Ctx sub{"run", {}};
    const bool ok =
        get_str(run, "tool", r.tool, sub) && get_str(run, "version", r.version, sub) &&
        get_str(run, "git_sha", r.git_sha, sub) && get_str(run, "started_at", r.started_at, sub) &&
        get_str(run, "finished_at", r.finished_at, sub) &&
        get_str(run, "host_os", r.host_os, sub) && get_string_seq(run, "argv", r.argv, sub);
    if (!ok) c.error = sub.error;
    return ok;
}

bool read_case(const YAML::Node& root, CaseInfo& ci, Ctx& c) {
    YAML::Node n;
    if (!get_map(root, "case", n, c)) return false;
    if (!n.IsDefined()) return true;  // absent: a case made without the flags
    Ctx sub{"case", {}};
    const bool ok = get_str(n, "id", ci.id, sub) && get_str(n, "examiner", ci.examiner, sub) &&
                    get_str(n, "notes", ci.notes, sub);
    if (!ok) c.error = sub.error;
    return ok;
}

bool read_evidence(const YAML::Node& root, std::vector<Evidence>& out, Ctx& c) {
    YAML::Node seq;
    if (!get_seq(root, "evidence", seq, c)) return false;
    if (!seq.IsDefined()) return true;
    std::size_t i = 0;
    for (const YAML::Node& item : seq) {
        if (!item.IsMap()) return c.fail("evidence", "item " + dec(i) + " must be a map");
        Ctx sub{"evidence[" + dec(i) + "]", {}};
        Evidence ev;
        const bool ok = get_str(item, "id", ev.id, sub) && get_str(item, "path", ev.path, sub) &&
                        get_uint(item, "size", ev.size, sub) &&
                        read_digests(item, ev.digests, sub) &&
                        get_str(item, "acquired_at", ev.acquired_at, sub) &&
                        get_str(item, "note", ev.note, sub);
        if (!ok) {
            c.error = sub.error;
            return false;
        }
        out.push_back(std::move(ev));
        ++i;
    }
    return true;
}

bool read_coverage(const YAML::Node& root, std::vector<Coverage>& out, Ctx& c) {
    YAML::Node seq;
    if (!get_seq(root, "coverage", seq, c)) return false;
    if (!seq.IsDefined()) return true;
    std::size_t i = 0;
    for (const YAML::Node& item : seq) {
        if (!item.IsMap()) return c.fail("coverage", "item " + dec(i) + " must be a map");
        Ctx sub{"coverage[" + dec(i) + "]", {}};
        Coverage cv;
        const bool ok = get_str(item, "format", cv.format, sub) &&
                        get_str(item, "status", cv.status, sub) &&
                        get_str(item, "detail", cv.detail, sub);
        if (!ok) {
            c.error = sub.error;
            return false;
        }
        out.push_back(std::move(cv));
        ++i;
    }
    return true;
}

bool read_tools(const YAML::Node& root, std::vector<ToolRecord>& out, Ctx& c) {
    YAML::Node seq;
    if (!get_seq(root, "tools", seq, c)) return false;
    if (!seq.IsDefined()) return true;
    std::size_t i = 0;
    for (const YAML::Node& item : seq) {
        if (!item.IsMap()) return c.fail("tools", "item " + dec(i) + " must be a map");
        Ctx sub{"tools[" + dec(i) + "]", {}};
        ToolRecord t;
        std::int64_t exit_code = 0;
        std::optional<std::int64_t> ec;
        bool ok = get_str(item, "name", t.name, sub) && get_str(item, "version", t.version, sub) &&
                  get_string_seq(item, "argv", t.argv, sub) &&
                  get_opt_i64(item, "exit_code", ec, sub) &&
                  get_double(item, "seconds", t.seconds, sub);
        if (ok && ec) {
            exit_code = *ec;
            if (exit_code < -2147483648LL || exit_code > 2147483647LL)
                ok = sub.fail("exit_code", "is out of range");
            else
                t.exit_code = static_cast<int>(exit_code);
        }
        if (!ok) {
            c.error = sub.error;
            return false;
        }
        out.push_back(std::move(t));
        ++i;
    }
    return true;
}

// ---------------------------------------------------------------------------
// JSON Schema
// ---------------------------------------------------------------------------

using json = nlohmann::ordered_json;

json uint64_schema(const char* desc) {
    return json{{"type", "integer"},
                {"minimum", 0},
                {"maximum", std::uint64_t{18446744073709551615ULL}},
                {"description", desc}};
}

json uint32_schema(const char* desc) {
    return json{
        {"type", "integer"}, {"minimum", 0}, {"maximum", 4294967295ULL}, {"description", desc}};
}

json int64_schema(const char* desc) {
    return json{{"type", "integer"},
                {"minimum", std::int64_t{-9223372036854775807LL - 1}},
                {"maximum", std::int64_t{9223372036854775807LL}},
                {"description", desc}};
}

json string_schema(const char* desc) {
    return json{{"type", "string"}, {"description", desc}};
}

json iso_schema(const char* desc) {
    return json{{"type", "string"},
                {"pattern", "^-?[0-9]{4,}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
                {"description", desc}};
}

json string_array_schema(const char* desc) {
    return json{{"type", "array"}, {"items", json{{"type", "string"}}}, {"description", desc}};
}

json string_map_schema(const char* desc) {
    return json{{"type", "object"},
                {"additionalProperties", json{{"type", "string"}}},
                {"description", desc}};
}

json ref(const char* def) {
    return json{{"$ref", std::string("#/$defs/") + def}};
}

json build_schema() {
    json s;
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema";
    s["title"] = "OmniTrace manifest";
    s["description"] =
        "manifest.yaml (schema omnitrace/1): the whole case as data. Keys are emitted in the order "
        "listed "
        "under each object's `properties`. Integers are decimal; `offset_hex` and `*_iso` keys are "
        "read-only conveniences derived from their integer twins.";
    s["type"] = "object";
    s["required"] =
        json::array({"schema", "run", "evidence", "nodes", "coverage", "tools", "diagnostics"});
    s["additionalProperties"] = false;
    json props;
    props["schema"] =
        json{{"const", "omnitrace/1"}, {"description", "Manifest schema identifier."}};
    props["run"] = ref("run");
    props["case"] = ref("case");
    props["evidence"] =
        json{{"type", "array"},
             {"items", ref("evidence")},
             {"description", "Evidence files as given by the examiner, in argument order."}};
    props["nodes"] =
        json{{"type", "array"},
             {"items", ref("node")},
             {"description", "The evidence graph in insertion order; ids are sequential."}};
    props["coverage"] =
        json{{"type", "array"},
             {"items", ref("coverage")},
             {"description", "One row per capability the run could or could not exercise."}};
    props["tools"] = json{{"type", "array"},
                          {"items", ref("tool")},
                          {"description", "External tools invoked during the run."}};
    props["diagnostics"] = json{
        {"type", "array"}, {"items", ref("diagnostic")}, {"description", "Run-level diagnostics."}};
    s["properties"] = std::move(props);

    json defs;

    json run;
    run["type"] = "object";
    run["description"] = "Who produced this manifest and when.";
    run["required"] =
        json::array({"tool", "version", "git_sha", "started_at", "finished_at", "host_os", "argv"});
    run["additionalProperties"] = false;
    run["properties"] =
        json{{"tool", string_schema("Producer name, normally \"omnitrace\".")},
             {"version", string_schema("Producer version (OMNITRACE_VERSION).")},
             {"git_sha", string_schema("Producer git commit if known; empty otherwise.")},
             {"started_at", string_schema("ISO-8601 UTC start of the run; empty if unknown.")},
             {"finished_at", string_schema("ISO-8601 UTC end of the run; empty if unknown.")},
             {"host_os", string_schema("Host operating system label.")},
             {"argv", string_array_schema("Command line of the run.")}};
    defs["run"] = std::move(run);

    // Optional: written only when the examiner supplied at least one field, so
    // it is not in the top-level `required` list.
    json case_info;
    case_info["type"] = "object";
    case_info["description"] = "Examiner-supplied case identity; absent when none was given.";
    case_info["required"] = json::array({"id", "examiner", "notes"});
    case_info["additionalProperties"] = false;
    case_info["properties"] = json{{"id", string_schema("Case, exhibit or job number.")},
                                   {"examiner", string_schema("Who ran the tool.")},
                                   {"notes", string_schema("Free text carried into the report.")}};
    defs["case"] = std::move(case_info);

    json digests;
    digests["type"] = "object";
    digests["description"] = "MD5, SHA-1 and SHA-256 of the same bytes, lowercase hex.";
    digests["required"] = json::array({"md5", "sha1", "sha256", "bytes"});
    digests["additionalProperties"] = false;
    digests["properties"] =
        json{{"md5", json{{"type", "string"}, {"pattern", "^([0-9a-f]{32})?$"}}},
             {"sha1", json{{"type", "string"}, {"pattern", "^([0-9a-f]{40})?$"}}},
             {"sha256", json{{"type", "string"}, {"pattern", "^([0-9a-f]{64})?$"}}},
             {"bytes", uint64_schema("Number of bytes hashed.")}};
    defs["digests"] = std::move(digests);

    json evidence;
    evidence["type"] = "object";
    evidence["description"] = "One examiner-supplied evidence file.";
    evidence["required"] = json::array({"id", "path", "size", "acquired_at", "note"});
    evidence["additionalProperties"] = false;
    evidence["properties"] =
        json{{"id", json{{"type", "string"}, {"pattern", "^e[0-9]+$"}}},
             {"path", string_schema("Path as given by the examiner.")},
             {"size", uint64_schema("File size in bytes.")},
             {"digests", ref("digests")},
             {"acquired_at", string_schema("ISO-8601 acquisition time, or empty.")},
             {"note", string_schema("Examiner note, or empty.")}};
    defs["evidence"] = std::move(evidence);

    json diag;
    diag["type"] = "object";
    diag["description"] = "A structured diagnostic: stable kebab-case code plus a human message.";
    diag["required"] = json::array({"severity", "code", "message"});
    diag["additionalProperties"] = false;
    diag["properties"] = json{
        {"severity", json{{"type", "string"}, {"enum", json::array({"info", "warning", "error"})}}},
        {"code", string_schema("Stable machine slug, e.g. \"jffs2-crc-mismatch\".")},
        {"message", string_schema("Human sentence.")}};
    defs["diagnostic"] = std::move(diag);

    json location;
    location["type"] = "object";
    location["description"] = "Where the node's bytes live, relative to a Source.";
    location["required"] = json::array({"source", "offset", "offset_hex", "length"});
    location["additionalProperties"] = false;
    location["properties"] = json{
        {"source", string_schema("Source id the offset is relative to.")},
        {"offset", uint64_schema("Byte offset, decimal.")},
        {"offset_hex", json{{"type", "string"},
                            {"pattern", "^0x[0-9a-f]+$"},
                            {"description", "Lowercase hex twin of `offset`; ignored on read."}}},
        {"length", uint64_schema("Byte length; 0 = unknown.")}};
    defs["location"] = std::move(location);

    json file;
    file["type"] = "object";
    file["description"] =
        "Per-file metadata as recorded by the filesystem. Timestamps are unix seconds with an "
        "ISO-8601 twin. "
        "`deleted` and `superseded` appear only when true; `version` only when > 0; `link_target` "
        "only for "
        "symlinks; `rdev_*` only for devices; `extra` only when non-empty.";
    file["required"] =
        json::array({"path", "kind", "mode", "mode_octal", "uid", "gid", "size", "inode", "nlink"});
    file["additionalProperties"] = false;
    json fprops;
    fprops["path"] =
        string_schema("POSIX-style path relative to the filesystem root, no leading '/'.");
    fprops["kind"] = json{{"type", "string"},
                          {"enum", json::array({"regular", "directory", "symlink", "char-device",
                                                "block-device", "fifo", "socket", "unknown"})}};
    fprops["mode"] = uint32_schema("Permission bits (and type bits if the FS has them), decimal.");
    fprops["mode_octal"] =
        json{{"type", "string"},
             {"pattern", "^[0-7]{4}$"},
             {"description", "Low 12 bits of `mode` in octal; ignored on read."}};
    fprops["uid"] = uint32_schema("Owner user id.");
    fprops["gid"] = uint32_schema("Owner group id.");
    fprops["size"] = uint64_schema("Size in bytes.");
    fprops["mtime"] = int64_schema("Modification time, unix seconds.");
    fprops["mtime_iso"] = iso_schema("ISO-8601 twin of `mtime`; ignored on read.");
    fprops["mtime_nsec"] = uint32_schema("Nanosecond part of `mtime`.");
    fprops["ctime"] = int64_schema("Inode change time, unix seconds.");
    fprops["ctime_iso"] = iso_schema("ISO-8601 twin of `ctime`; ignored on read.");
    fprops["ctime_nsec"] = uint32_schema("Nanosecond part of `ctime`.");
    fprops["atime"] = int64_schema("Access time, unix seconds.");
    fprops["atime_iso"] = iso_schema("ISO-8601 twin of `atime`; ignored on read.");
    fprops["atime_nsec"] = uint32_schema("Nanosecond part of `atime`.");
    fprops["crtime"] = int64_schema("Creation time, unix seconds.");
    fprops["crtime_iso"] = iso_schema("ISO-8601 twin of `crtime`; ignored on read.");
    fprops["inode"] = uint64_schema("Inode number; 0 if the FS has none.");
    fprops["nlink"] = uint32_schema("Hard link count; 0 if unknown.");
    fprops["link_target"] = string_schema("Symlink target.");
    fprops["rdev_major"] = uint32_schema("Device major number.");
    fprops["rdev_minor"] = uint32_schema("Device minor number.");
    fprops["deleted"] =
        json{{"const", true}, {"description", "No live directory entry points at this entry."}};
    fprops["superseded"] =
        json{{"const", true},
             {"description", "An older version of a file that still has a live entry."}};
    fprops["version"] = json{
        {"type", "integer"},
        {"minimum", 1},
        {"maximum", std::uint64_t{18446744073709551615ULL}},
        {"description",
         "FS-recorded version of this inode (JFFS2 version, UBIFS sqnum order, YAFFS2 sequence)."}};
    fprops["extra"] = string_map_schema("FS-specific extras (compression, xattr summary, ...).");
    file["properties"] = std::move(fprops);
    defs["file"] = std::move(file);

    json node;
    node["type"] = "object";
    node["description"] =
        "One node of the evidence graph. `file` is present only for kind \"file\"; `digests` only "
        "when hashed.";
    node["required"] =
        json::array({"id", "parent", "kind", "name", "format", "location", "confidence", "evidence",
                     "endian", "attrs", "diagnostics", "children"});
    node["additionalProperties"] = false;
    json nprops;
    nprops["id"] = json{{"type", "string"},
                        {"pattern", "^n[0-9]{6,}$"},
                        {"description", "Sequential id assigned by the graph."}};
    nprops["parent"] = json{{"type", "string"},
                            {"pattern", "^(n[0-9]{6,})?$"},
                            {"description", "Parent id; empty for a root."}};
    nprops["kind"] = json{{"type", "string"},
                          {"enum", json::array({"image", "partition", "container", "filesystem",
                                                "file", "region", "artifact"})}};
    nprops["name"] = string_schema("Human label: partition name, file name, format label.");
    nprops["format"] =
        string_schema("Format slug (\"squashfs\", \"mbr\", \"gzip\", ...); empty for file/region.");
    nprops["location"] = ref("location");
    nprops["confidence"] = json{{"type", "integer"},
                                {"minimum", 0},
                                {"maximum", 100},
                                {"description", "0-100; see the confidence tiers."}};
    nprops["evidence"] = string_schema("Why the confidence.");
    nprops["endian"] = json{{"type", "string"}, {"enum", json::array({"little", "big"})}};
    nprops["attrs"] =
        string_map_schema("Format-specific attributes: version, compression, arch, label.");
    nprops["file"] = ref("file");
    nprops["digests"] = ref("digests");
    nprops["diagnostics"] = json{{"type", "array"}, {"items", ref("diagnostic")}};
    nprops["children"] =
        json{{"type", "array"},
             {"items", json{{"type", "string"}, {"pattern", "^n[0-9]{6,}$"}}},
             {"description", "Child ids in insertion order; derived from `parent` on read."}};
    node["properties"] = std::move(nprops);
    defs["node"] = std::move(node);

    json coverage;
    coverage["type"] = "object";
    coverage["required"] = json::array({"format", "status", "detail"});
    coverage["additionalProperties"] = false;
    coverage["properties"] =
        json{{"format", string_schema("Format slug.")},
             {"status",
              string_schema("\"supported\" | \"partial\" | \"unsupported\" | \"tool-missing\".")},
             {"detail", string_schema("What was or was not possible.")}};
    defs["coverage"] = std::move(coverage);

    json tool;
    tool["type"] = "object";
    tool["required"] = json::array({"name", "version", "argv", "exit_code", "seconds"});
    tool["additionalProperties"] = false;
    tool["properties"] =
        json{{"name", string_schema("Tool name.")},
             {"version", string_schema("Tool version string.")},
             {"argv", string_array_schema("Arguments the tool was invoked with.")},
             {"exit_code",
              json{{"type", "integer"}, {"minimum", -2147483648LL}, {"maximum", 2147483647LL}}},
             {"seconds", json{{"type", "number"}, {"description", "Wall time in seconds."}}}};
    defs["tool"] = std::move(tool);

    s["$defs"] = std::move(defs);
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::string manifest_to_yaml(const Manifest& m) {
    YAML::Emitter e;
    e.SetIndent(2);
    e << YAML::BeginMap;
    emit_key_str(e, "schema", Manifest::kSchema);

    e << YAML::Key << "run" << YAML::Value << YAML::BeginMap;
    emit_key_str(e, "tool", m.run.tool);
    emit_key_str(e, "version", m.run.version);
    emit_key_str(e, "git_sha", m.run.git_sha);
    emit_key_str(e, "started_at", m.run.started_at);
    emit_key_str(e, "finished_at", m.run.finished_at);
    emit_key_str(e, "host_os", m.run.host_os);
    emit_string_seq(e, "argv", m.run.argv);
    e << YAML::EndMap;

    // Written only when the examiner supplied something, so a case made
    // without the flags is byte-identical to one made before they existed and
    // every checked-in expected manifest stays valid.
    if (!m.case_info.empty()) {
        e << YAML::Key << "case" << YAML::Value << YAML::BeginMap;
        emit_key_str(e, "id", m.case_info.id);
        emit_key_str(e, "examiner", m.case_info.examiner);
        emit_key_str(e, "notes", m.case_info.notes);
        e << YAML::EndMap;
    }

    e << YAML::Key << "evidence" << YAML::Value;
    begin_seq(e, m.evidence.empty());
    for (const Evidence& ev : m.evidence) {
        e << YAML::BeginMap;
        emit_key_str(e, "id", ev.id);
        emit_key_str(e, "path", ev.path);
        emit_key_u64(e, "size", ev.size);
        if (!ev.digests.empty()) emit_digests(e, ev.digests);
        emit_key_str(e, "acquired_at", ev.acquired_at);
        emit_key_str(e, "note", ev.note);
        e << YAML::EndMap;
    }
    e << YAML::EndSeq;

    e << YAML::Key << "nodes" << YAML::Value;
    begin_seq(e, m.nodes().empty());
    for (const Node& n : m.nodes()) emit_node(e, n);
    e << YAML::EndSeq;

    e << YAML::Key << "coverage" << YAML::Value;
    begin_seq(e, m.coverage.empty());
    for (const Coverage& c : m.coverage) {
        e << YAML::BeginMap;
        emit_key_str(e, "format", c.format);
        emit_key_str(e, "status", c.status);
        emit_key_str(e, "detail", c.detail);
        e << YAML::EndMap;
    }
    e << YAML::EndSeq;

    e << YAML::Key << "tools" << YAML::Value;
    begin_seq(e, m.tools.empty());
    for (const ToolRecord& t : m.tools) {
        e << YAML::BeginMap;
        emit_key_str(e, "name", t.name);
        emit_key_str(e, "version", t.version);
        emit_string_seq(e, "argv", t.argv);
        e << YAML::Key << "exit_code" << YAML::Value << t.exit_code;
        e << YAML::Key << "seconds" << YAML::Value << double_text(t.seconds);
        e << YAML::EndMap;
    }
    e << YAML::EndSeq;

    emit_diagnostics(e, m.diagnostics);
    e << YAML::EndMap;
    return finish(e);
}

namespace {

constexpr const char* kCodeListingUnreadable = "case-listing-unreadable";
constexpr const char* kCodeRelocated = "case-relocated";

std::string read_whole(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// Is `p` inside `root`? A string prefix is not enough: `/cases/router2` is
// not inside `/cases/router`, and the whole point of the test is that another
// case's files are not this case's.
bool under(const std::filesystem::path& p, const std::filesystem::path& root) {
    const std::filesystem::path rel =
        p.lexically_normal().lexically_relative(root.lexically_normal());
    return !rel.empty() && *rel.begin() != "..";
}

// Where this entry's bytes actually are, if they are in this case at all.
//
// Two rules, and both were learned by watching the wrong thing happen.
//
// **The file beside the listing wins over the recorded host_path.** A case is
// routinely *copied* rather than moved, and the copy's listings still name the
// original's paths, which exist. Trusting host_path first reads the original
// case's files while reporting on the copy -- silently, and the two can
// differ, which is exactly the situation when an examiner compares a working
// copy against an archived one.
//
// **A path outside the case directory is never this case's bytes.** A case is
// self-contained (docs/CASE_LAYOUT.md). A host_path pointing elsewhere came
// from another machine or another case, and following it produced records
// from somebody else's files for a case whose own tree had been deleted.
void rebase(EntryResult& r, const std::filesystem::path& files_dir,
            const std::filesystem::path& case_root, bool& relocated) {
    std::error_code ec;
    if (!r.meta.path.empty()) {
        const std::filesystem::path here = files_dir / r.meta.path;
        if (std::filesystem::exists(here, ec)) {
            if (!r.host_path.empty() && r.host_path != here.string()) relocated = true;
            r.host_path = here.string();
            return;
        }
    }
    // Only a recorded path that is inside this case may be believed.
    const std::filesystem::path recorded =
        r.host_path.empty() ? std::filesystem::path{} : std::filesystem::path(r.host_path);
    if (!recorded.empty() && under(recorded, case_root) && std::filesystem::exists(recorded, ec))
        return;

    r.host_path.clear();
    r.written = false;
}

// filesystems/ before containers/, each sorted by node id, so two runs over
// the same case produce the same order.
void collect_dirs(const std::filesystem::path& base, std::vector<std::filesystem::path>& out) {
    std::error_code ec;
    if (!std::filesystem::is_directory(base, ec)) return;
    std::vector<std::filesystem::path> found;
    for (const auto& e : std::filesystem::directory_iterator(base, ec)) {
        if (!e.is_directory()) continue;
        if (std::filesystem::exists(e.path() / "listing.yaml", ec)) found.push_back(e.path());
    }
    std::sort(found.begin(), found.end());
    out.insert(out.end(), found.begin(), found.end());
}

}  // namespace

Status load_case_listings(const std::string& case_dir,
                          std::vector<std::pair<std::string, std::vector<EntryResult>>>& out,
                          std::vector<Diagnostic>& diagnostics) {
    out.clear();
    const std::filesystem::path dir(case_dir);
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec))
        return Status::fail("case-not-a-directory: '" + case_dir + "'");

    std::vector<std::filesystem::path> dirs;
    collect_dirs(dir / "filesystems", dirs);
    collect_dirs(dir / "containers", dirs);

    std::uint64_t relocated_listings = 0;
    for (const std::filesystem::path& d : dirs) {
        const std::string text = read_whole(d / "listing.yaml");
        if (text.empty()) {
            diagnostics.push_back({Severity::Warning, kCodeListingUnreadable,
                                   "'" + (d / "listing.yaml").string() +
                                       "' is empty or could not be read; the entries it "
                                       "describes are not part of this examination"});
            continue;
        }
        std::string node_id;
        std::vector<EntryResult> entries;
        if (const Status st = listing_from_yaml(text, node_id, entries); !st) {
            diagnostics.push_back({Severity::Warning, kCodeListingUnreadable,
                                   "'" + (d / "listing.yaml").string() + "': " + st.error});
            continue;
        }
        bool relocated = false;
        for (EntryResult& r : entries) rebase(r, d / "files", dir, relocated);
        if (relocated) ++relocated_listings;
        out.emplace_back(node_id.empty() ? d.filename().string() : node_id, std::move(entries));
    }

    if (relocated_listings != 0)
        diagnostics.push_back(
            {Severity::Info, kCodeRelocated,
             "the case has moved since it was written: " + dec(relocated_listings) +
                 " listing(s) recorded host paths that are not where their files are now; the "
                 "files beside each listing were read instead"});
    return Status::success();
}

Status listing_from_yaml(const std::string& text, std::string& node_id,
                         std::vector<EntryResult>& entries) {
    YAML::Node root;
    try {
        root = YAML::Load(text);
    } catch (const YAML::Exception& ex) {
        return Status::fail(std::string("listing: yaml parse error: ") + ex.what());
    } catch (const std::exception& ex) {
        return Status::fail(std::string("listing: yaml parse error: ") + ex.what());
    }
    if (!root.IsMap()) return Status::fail("listing: document must be a map");

    Ctx c{"listing", {}};
    std::string id;
    std::vector<EntryResult> read;
    try {
        if (!get_str(root, "filesystem", id, c, true)) return Status::fail(c.error);
        YAML::Node items;
        if (!get_seq(root, "entries", items, c)) return Status::fail(c.error);
        if (items.IsDefined()) {
            std::size_t i = 0;
            for (const YAML::Node& item : items) {
                if (!item.IsMap())
                    return Status::fail("listing: entries item " + dec(i) + " must be a map");
                Ctx sub{"listing entry " + dec(i), {}};
                YAML::Node fm;
                if (!get_map(item, "file", fm, sub)) return Status::fail(sub.error);
                if (!fm.IsDefined())
                    return Status::fail("listing: entries item " + dec(i) + " has no 'file'");
                EntryResult r;
                if (!read_file_meta(fm, r.meta, sub)) return Status::fail(sub.error);
                if (!read_digests(item, r.digests, sub) ||
                    !get_str(item, "host_path", r.host_path, sub) ||
                    !get_bool(item, "written", r.written, sub) ||
                    !get_bool(item, "truncated", r.truncated, sub) ||
                    !read_diagnostics(item, r.diagnostics, sub))
                    return Status::fail(sub.error);
                read.push_back(std::move(r));
                ++i;
            }
        }
    } catch (const YAML::Exception& ex) {
        return Status::fail(std::string("listing: yaml error: ") + ex.what());
    }
    node_id = std::move(id);
    entries = std::move(read);
    return Status::success();
}

Status manifest_from_yaml(const std::string& text, Manifest& out) {
    YAML::Node root;
    try {
        root = YAML::Load(text);
    } catch (const YAML::Exception& ex) {
        return Status::fail(std::string("manifest: yaml parse error: ") + ex.what());
    } catch (const std::exception& ex) {
        return Status::fail(std::string("manifest: yaml parse error: ") + ex.what());
    }
    if (!root.IsMap()) return Status::fail("manifest: document must be a map");

    Manifest m;
    Ctx c{"manifest", {}};
    try {
        std::string schema;
        if (!get_str(root, "schema", schema, c, true)) return Status::fail(c.error);
        if (schema != Manifest::kSchema) {
            return Status::fail("manifest: key 'schema' is '" + schema + "', expected '" +
                                Manifest::kSchema + "'");
        }
        if (!read_run(root, m.run, c)) return Status::fail(c.error);
        if (!read_case(root, m.case_info, c)) return Status::fail(c.error);
        if (!read_evidence(root, m.evidence, c)) return Status::fail(c.error);
        YAML::Node nodes;
        if (!get_seq(root, "nodes", nodes, c)) return Status::fail(c.error);
        if (nodes.IsDefined()) {
            std::size_t i = 0;
            for (const YAML::Node& item : nodes) {
                if (!read_node(item, i, m, c)) return Status::fail(c.error);
                ++i;
            }
        }
        if (!read_coverage(root, m.coverage, c)) return Status::fail(c.error);
        if (!read_tools(root, m.tools, c)) return Status::fail(c.error);
        if (!read_diagnostics(root, m.diagnostics, c)) return Status::fail(c.error);
    } catch (const YAML::Exception& ex) {
        // yaml-cpp can still throw on pathological documents (e.g. a map used
        // as a key); report rather than propagate.
        return Status::fail(std::string("manifest: yaml error: ") + ex.what());
    }
    out = std::move(m);
    return Status::success();
}

std::string listing_to_yaml(const std::string& fs_node_id,
                            const std::vector<EntryResult>& entries) {
    YAML::Emitter e;
    e.SetIndent(2);
    e << YAML::BeginMap;
    emit_key_str(e, "filesystem", fs_node_id);
    e << YAML::Key << "entries" << YAML::Value;
    begin_seq(e, entries.empty());
    for (const EntryResult& r : entries) {
        e << YAML::BeginMap;
        emit_file_meta(e, r.meta);
        if (!r.digests.empty()) emit_digests(e, r.digests);
        if (!r.host_path.empty()) emit_key_str(e, "host_path", r.host_path);
        if (r.written) e << YAML::Key << "written" << YAML::Value << true;
        if (r.truncated) e << YAML::Key << "truncated" << YAML::Value << true;
        if (!r.diagnostics.empty()) emit_diagnostics(e, r.diagnostics);
        e << YAML::EndMap;
    }
    e << YAML::EndSeq;
    e << YAML::EndMap;
    return finish(e);
}

std::string manifest_json_schema() {
    return build_schema().dump(2) + "\n";
}

}  // namespace omnitrace::output
