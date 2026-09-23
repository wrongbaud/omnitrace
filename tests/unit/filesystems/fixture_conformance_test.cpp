// fixture_conformance_test.cpp — every registered filesystem reader against
// the fixture ground truth in tests/fixtures/out.
//
// For each <name>.expected.yaml the suite instantiates one parameter. A
// fixture whose `image.format` has no reader in the FilesystemRegistry is
// skipped with a message naming the format, so the test log doubles as a
// coverage report (see the Coverage test at the bottom); a fixture whose
// format has a reader is opened the way `discovery::analyze` would open it
// (the validator's finding at offset 0, or the whole image when the validator
// fails, which is itself a failure) and then checked four ways:
//
//   LiveTree      ListingSink, history off: every `tree:` entry present with
//                 matching kind, size, mode, owner, mtime, link target and
//                 sha256; hard links share an inode; no extra entries beyond
//                 the allowed list (lost+found on ext).
//   History       ListingSink, history on, when the YAML has a `history:`
//                 section: every superseded and deleted entry present with
//                 the right flags, version, size, sha256; counts >= the YAML.
//   DiskSink      the extracted files hash to the expected sha256 and the
//                 historical versions land under .omnitrace-versions/<path>/v<n>.
//   Determinism   three walks (two fresh readers, one re-walk) emit the same
//                 entry sequence and diagnostics.
//
// The parser for expected.yaml is fixture_yaml.{h,cpp}; its own tests are at
// the end of this file. Nothing here depends on a particular reader, so a new
// reader is covered the moment it registers.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fixture_yaml.h"
#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Node.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/discovery/Signature.h"
#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {
namespace {

namespace stdfs = std::filesystem;
using fixture_yaml::Node;

constexpr const char* kNoFixtures = "no-fixtures";
constexpr const char* kVersionsDir = ".omnitrace-versions";

// ------------------------------------------------------------------ helpers

stdfs::path fixtures_dir() {
    return stdfs::path(OMNITRACE_TEST_DATA_DIR) / "out";
}

// Every fixture with a ground-truth file, sorted by name. A sentinel keeps the
// suite instantiated (and skipping) when the directory has not been built.
std::vector<std::string> fixture_names() {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& de : stdfs::directory_iterator(fixtures_dir(), ec)) {
        const std::string fn = de.path().filename().string();
        const std::string suffix = ".expected.yaml";
        if (fn.size() > suffix.size() &&
            fn.compare(fn.size() - suffix.size(), suffix.size(), suffix) == 0)
            names.push_back(fn.substr(0, fn.size() - suffix.size()));
    }
    std::sort(names.begin(), names.end());
    if (names.empty()) names.push_back(kNoFixtures);
    return names;
}

std::string param_name(const ::testing::TestParamInfo<std::string>& info) {
    std::string s = info.param;
    for (char& c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) c = '_';
    return s;
}

std::string join_diags(const std::vector<Diagnostic>& d) {
    std::string s;
    for (const Diagnostic& x : d)
        s += std::string(severity_name(x.severity)) + " " + x.code + ": " + x.message + "\n";
    return s;
}

// "ext4" -> "ext", "fat32" -> "fat", "vfat" -> "fat", "yaffs2" -> "yaffs".
std::string canonical_format(std::string f) {
    while (!f.empty() && f.back() >= '0' && f.back() <= '9') f.pop_back();
    if (f == "vfat") f = "fat";
    return f;
}

bool same_format(const std::string& a, const std::string& b) {
    return a == b || canonical_format(a) == canonical_format(b);
}

// The registry key whose reader handles `fmt`, or empty. An exact match wins
// over a family match ("ext4" fixture, "ext" reader).
std::string reader_key_for(const std::string& fmt) {
    const std::vector<std::string> keys = FilesystemRegistry::instance().formats();
    for (const std::string& k : keys)
        if (k == fmt) return k;
    for (const std::string& k : keys)
        if (same_format(k, fmt)) return k;
    return {};
}

class TempDir {
   public:
    explicit TempDir(const std::string& tag) {
        stdfs::path base;
        if (const char* env = std::getenv("OMNITRACE_TEST_TMPDIR"))
            base = env;
        else
            base = stdfs::temp_directory_path();
        static int counter = 0;
        std::random_device rd;
        path_ = base / ("omnitrace-conformance-" + tag + "-" + std::to_string(rd()) + "-" +
                        std::to_string(counter++));
        stdfs::remove_all(path_);
        stdfs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        stdfs::remove_all(path_, ec);
    }
    const stdfs::path& path() const { return path_; }

   private:
    stdfs::path path_;
};

std::string octal(std::uint32_t mode) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0%o", static_cast<unsigned>(mode & 07777u));
    return buf;
}

// ------------------------------------------------------------------ expected.yaml

struct ExpectedEntry {
    std::string path, kind;
    std::optional<std::uint32_t> mode, uid, gid, nlink;
    std::optional<std::uint64_t> size;
    std::optional<std::int64_t> mtime;
    std::optional<std::string> sha256, hardlink_of, link_target;
};

struct ExpectedVersion {
    std::string path;
    std::optional<std::uint64_t> inode, version, size;
    std::optional<std::int64_t> mtime;
    std::optional<std::string> sha256;
    bool content_recoverable = true;  // absent means yes
};

std::optional<std::uint32_t> u32_of(const Node& n) {
    const auto v = n.as_uint();
    if (!v || *v > 0xFFFFFFFFull) return std::nullopt;
    return static_cast<std::uint32_t>(*v);
}

std::optional<std::string> str_of(const Node& n) {
    if (!n.is_scalar()) return std::nullopt;
    return n.str();
}

std::optional<std::uint32_t> mode_of(const Node& n) {
    if (!n.is_scalar() || n.str().empty()) return std::nullopt;
    std::uint32_t v = 0;
    for (const char c : n.str()) {
        if (c < '0' || c > '7') return std::nullopt;
        v = v * 8 + static_cast<std::uint32_t>(c - '0');
    }
    return v;
}

std::vector<ExpectedEntry> expected_tree(const Node& doc) {
    std::vector<ExpectedEntry> out;
    for (const Node& row : doc["tree"].items()) {
        ExpectedEntry e;
        e.path = row.str_or("path");
        e.kind = row.str_or("kind");
        e.mode = mode_of(row["mode"]);
        e.uid = u32_of(row["uid"]);
        e.gid = u32_of(row["gid"]);
        e.nlink = u32_of(row["nlink"]);
        e.size = row["size"].as_uint();
        e.mtime = row["mtime"].as_int();
        e.sha256 = str_of(row["sha256"]);
        e.hardlink_of = str_of(row["hardlink_of"]);
        e.link_target = str_of(row["link_target"]);
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<ExpectedVersion> expected_versions(const Node& list) {
    std::vector<ExpectedVersion> out;
    for (const Node& row : list.items()) {
        ExpectedVersion v;
        v.path = row.str_or("path");
        v.inode = row["inode"].as_uint();
        v.version = row["version"].as_uint();
        v.size = row["size"].as_uint();
        v.mtime = row["mtime"].as_int();
        v.sha256 = str_of(row["sha256"]);
        v.content_recoverable = row["content_recoverable"].as_bool().value_or(true);
        out.push_back(std::move(v));
    }
    return out;
}

// ------------------------------------------------------------------ the fixture under test

struct Fixture {
    std::string name;
    Node doc;
    stdfs::path image;
    std::string format;      // image.format in the YAML
    std::string reader_key;  // registry key that handles it
    std::shared_ptr<MappedFile> file;
    Span span;  // what the reader is opened over (mirrors discovery::analyze)
    std::optional<discovery::Finding> finding;
    bool f_mode = true, f_owner = true;
    std::int64_t mtime_tolerance = 0;  // features.mtime_resolution - 1
    bool has_history = false;
    std::vector<ExpectedEntry> tree;
    std::vector<ExpectedVersion> superseded, deleted, current;

    bool is_ext() const { return canonical_format(format) == "ext"; }
    // Live entries a reader may legitimately add beyond the YAML tree.
    bool extra_allowed(const std::string& path) const {
        if (is_ext() && (path == "lost+found" || path.rfind("lost+found/", 0) == 0)) return true;
        return false;
    }
};

// Loads and identifies the fixture. `skip` is set when the test should skip;
// a hard problem is reported with ADD_FAILURE and `skip` left empty.
std::optional<Fixture> load_fixture(const std::string& name, std::string& skip) {
    skip.clear();
    if (name == kNoFixtures || !stdfs::exists(fixtures_dir())) {
        skip =
            "fixtures not built: " + fixtures_dir().string() + " (run scripts/fixtures.sh build)";
        return std::nullopt;
    }
    Fixture fx;
    fx.name = name;
    const stdfs::path yaml = fixtures_dir() / (name + ".expected.yaml");
    std::string why;
    std::optional<Node> doc = fixture_yaml::parse_file(yaml.string(), &why);
    if (!doc) {
        ADD_FAILURE() << "cannot parse " << yaml << ": " << why;
        return std::nullopt;
    }
    fx.doc = std::move(*doc);
    fx.format = fx.doc["image"].str_or("format");
    if (fx.format.empty()) {
        ADD_FAILURE() << yaml << ": image.format missing";
        return std::nullopt;
    }
    fx.reader_key = reader_key_for(fx.format);
    if (fx.reader_key.empty()) {
        skip = "no filesystem reader registered for format '" + fx.format + "' (fixture " + name +
               "); registered: ";
        for (const std::string& k : FilesystemRegistry::instance().formats()) skip += k + " ";
        return std::nullopt;
    }
    if (!fx.doc.has("tree")) {
        skip = "fixture " + name + " has no tree section (a wrapper image)";
        return std::nullopt;
    }
    fx.image = fixtures_dir() / fx.doc["image"].str_or("file", name + ".img");
    if (!stdfs::exists(fx.image)) {
        ADD_FAILURE() << "fixture " << name
                      << ": ground truth present but image missing: " << fx.image;
        return std::nullopt;
    }
    const Node& feat = fx.doc["features"];
    fx.f_mode = feat["mode"].as_bool().value_or(true);
    fx.f_owner = feat["owner"].as_bool().value_or(true);
    const std::int64_t res = feat["mtime_resolution"].as_int().value_or(1);
    fx.mtime_tolerance = res > 1 ? res - 1 : 0;
    fx.tree = expected_tree(fx.doc);
    if (fx.tree.empty()) {
        ADD_FAILURE() << "fixture " << name << ": empty tree";
        return std::nullopt;
    }
    fx.has_history = fx.doc["history"].is_mapping();
    if (fx.has_history) {
        fx.superseded = expected_versions(fx.doc["history"]["superseded"]);
        fx.deleted = expected_versions(fx.doc["history"]["deleted"]);
        fx.current = expected_versions(fx.doc["history"]["current"]);
    }

    if (Status st = MappedFile::open(fx.image.string(), fx.file); !st) {
        ADD_FAILURE() << "cannot map " << fx.image << ": " << st.error;
        return std::nullopt;
    }
    const Span whole = Span::whole(fx.file);
    // Identify it the way analyze() does: the validator's finding at offset 0.
    const std::vector<discovery::Finding> found =
        discovery::scan(whole, discovery::SignatureSet::builtin(), {});
    for (const discovery::Finding& f : found) {
        if (f.offset == 0 && same_format(f.format, fx.format)) {
            fx.finding = f;
            break;
        }
    }
    if (fx.finding) {
        fx.span = fx.finding->size != 0 ? whole.sub(0, fx.finding->size) : whole;
        EXPECT_GE(static_cast<int>(fx.finding->confidence),
                  static_cast<int>(Confidence::Structural))
            << name << ": the validator identified the fixture at offset 0 but only at tier "
            << confidence_tier(fx.finding->confidence) << ": " << fx.finding->evidence;
    } else {
        std::string seen;
        for (const discovery::Finding& f : found)
            seen += " " + f.format + "@" + std::to_string(f.offset);
        ADD_FAILURE() << name << ": no validator identified format '" << fx.format
                      << "' at offset 0 (a reader is registered under '" << fx.reader_key
                      << "', so analyze() would never open it); findings:"
                      << (seen.empty() ? " none" : seen);
        fx.span = whole;  // still exercise the reader over the whole image
    }
    return fx;
}

#define LOAD_FIXTURE_OR_SKIP(var)                                        \
    std::string skip_reason_;                                            \
    std::optional<Fixture> var = load_fixture(GetParam(), skip_reason_); \
    if (!var) {                                                          \
        if (!skip_reason_.empty()) GTEST_SKIP() << skip_reason_;         \
        FAIL() << "fixture " << GetParam() << " could not be loaded";    \
    }

bool open_reader(const Fixture& fx, std::unique_ptr<FilesystemReader>& out) {
    out = FilesystemRegistry::instance().create(fx.reader_key);
    if (!out) {
        ADD_FAILURE() << "registry returned no reader for '" << fx.reader_key << "'";
        return false;
    }
    EXPECT_TRUE(same_format(out->format(), fx.format))
        << "reader registered under '" << fx.reader_key << "' reports format() '" << out->format()
        << "'";
    if (Status st = out->open(fx.span); !st) {
        ADD_FAILURE() << fx.name << ": " << fx.reader_key
                      << " reader refused to open the fixture: " << st.error;
        return false;
    }
    return true;
}

struct Walked {
    Status status;
    WalkResult result;
    std::vector<EntryResult> entries;                // emission order
    std::map<std::string, const EntryResult*> live;  // path -> live entry
    std::vector<const EntryResult*> historical;      // deleted or superseded
    void index() {
        live.clear();
        historical.clear();
        for (const EntryResult& e : entries) {
            if (e.meta.deleted || e.meta.superseded)
                historical.push_back(&e);
            else
                live.emplace(e.meta.path, &e);
        }
    }
};

// Walks into a ListingSink (hashing) and indexes the result. `reader` may be
// null, in which case a fresh one is opened.
Walked walk_listing(const Fixture& fx, bool history, FilesystemReader* reader = nullptr) {
    Walked w;
    std::unique_ptr<FilesystemReader> own;
    if (!reader) {
        if (!open_reader(fx, own)) {
            w.status = Status::fail("open failed");
            return w;
        }
        reader = own.get();
    }
    WalkOptions opts;
    opts.history = history;
    ListingSink sink(true, opts.limits);
    w.status = reader->walk(sink, opts, w.result);
    EXPECT_EQ(w.result.entries_out.size(), sink.entries().size())
        << fx.name << ": WalkResult::entries_out must list every entry the Sink accepted";
    w.entries = sink.entries();
    w.index();
    return w;
}

void expect_clean(const Fixture& fx, const Walked& w, const std::string& label) {
    ASSERT_TRUE(w.status.ok) << fx.name << " (" << label << "): walk failed: " << w.status.error
                             << "\n"
                             << join_diags(w.result.diagnostics);
    EXPECT_FALSE(w.result.truncated) << fx.name << " (" << label << "): walk reported truncated";
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_EQ(d.severity, Severity::Info)
            << fx.name << " (" << label << "): walk diagnostic on a clean fixture: " << d.code
            << ": " << d.message;
    for (const EntryResult& e : w.entries) {
        EXPECT_FALSE(e.truncated) << fx.name << " (" << label << "): " << e.meta.path
                                  << " truncated";
        for (const Diagnostic& d : e.diagnostics)
            EXPECT_EQ(d.severity, Severity::Info)
                << fx.name << " (" << label << "): " << e.meta.path << ": " << d.code << ": "
                << d.message;
    }
}

// The live tree must be exactly the YAML tree (plus allowed extras).
void check_live_tree(const Fixture& fx, const Walked& w, const std::string& label) {
    const std::string who = fx.name + " (" + label + ")";
    std::set<std::string> expected_paths;
    for (const ExpectedEntry& e : fx.tree) {
        expected_paths.insert(e.path);
        const auto it = w.live.find(e.path);
        if (it == w.live.end()) {
            ADD_FAILURE() << who << ": missing " << e.path;
            continue;
        }
        const EntryResult& r = *it->second;
        const FileMeta& m = r.meta;
        EXPECT_EQ(std::string(entry_kind_name(m.kind)), e.kind) << who << ": " << e.path << " kind";
        if (fx.f_mode && e.mode) {
            EXPECT_EQ(octal(m.mode), octal(*e.mode)) << who << ": " << e.path << " mode";
        }
        if (fx.f_owner) {
            if (e.uid) {
                EXPECT_EQ(m.uid, *e.uid) << who << ": " << e.path << " uid";
            }
            if (e.gid) {
                EXPECT_EQ(m.gid, *e.gid) << who << ": " << e.path << " gid";
            }
        }
        if (e.mtime) {
            ASSERT_TRUE(m.mtime.has_value()) << who << ": " << e.path << " has no mtime";
            const std::int64_t diff =
                *m.mtime > *e.mtime ? *m.mtime - *e.mtime : *e.mtime - *m.mtime;
            EXPECT_LE(diff, fx.mtime_tolerance)
                << who << ": " << e.path << " mtime " << *m.mtime << " expected " << *e.mtime;
        }
        if (e.size && e.kind != "directory") {
            EXPECT_EQ(m.size, *e.size) << who << ": " << e.path << " size";
        }
        if (e.link_target) {
            EXPECT_EQ(m.link_target, *e.link_target) << who << ": " << e.path << " link_target";
        }
        if (e.kind == "regular") {
            if (e.sha256) {
                EXPECT_EQ(r.digests.sha256, *e.sha256) << who << ": " << e.path << " sha256";
            }
            if (e.size) {
                EXPECT_EQ(r.digests.bytes, *e.size) << who << ": " << e.path << " bytes received";
            }
        }
        if (e.nlink) {
            if (m.nlink != 0) {
                EXPECT_EQ(m.nlink, *e.nlink) << who << ": " << e.path << " nlink";
            } else
                std::cout << "note: " << who << ": " << e.path
                          << " reader reports no nlink (expected " << *e.nlink << ")\n";
        }
        if (e.hardlink_of) {
            const auto other = w.live.find(*e.hardlink_of);
            if (other == w.live.end()) {
                ADD_FAILURE() << who << ": " << e.path << " hard-link target " << *e.hardlink_of
                              << " missing";
            } else {
                EXPECT_NE(m.inode, 0u) << who << ": " << e.path << " hard link with inode 0";
                EXPECT_EQ(m.inode, other->second->meta.inode)
                    << who << ": " << e.path << " and " << *e.hardlink_of << " must share an inode";
            }
        }
        EXPECT_FALSE(m.deleted) << who << ": " << e.path;
        EXPECT_FALSE(m.superseded) << who << ": " << e.path;
    }
    std::string extras;
    for (const auto& [path, r] : w.live)
        if (!expected_paths.count(path) && !fx.extra_allowed(path)) extras += "\n  " + path;
    EXPECT_TRUE(extras.empty()) << who << ": entries not in the expected tree:" << extras;
}

void check_counts(const Fixture& fx, const Walked& w, const std::string& label) {
    const std::string who = fx.name + " (" + label + ")";
    std::uint64_t files = 0, dirs = 0, symlinks = 0, others = 0, sup = 0, del = 0;
    for (const EntryResult& e : w.entries) {
        if (e.meta.superseded) sup++;
        if (e.meta.deleted) del++;
        switch (e.meta.kind) {
            case EntryKind::Regular:
                files++;
                break;
            case EntryKind::Directory:
                dirs++;
                break;
            case EntryKind::Symlink:
                symlinks++;
                break;
            default:
                others++;
                break;
        }
    }
    EXPECT_EQ(w.result.entries, w.entries.size()) << who << ": WalkResult::entries";
    EXPECT_EQ(w.result.files, files) << who << ": WalkResult::files";
    EXPECT_EQ(w.result.dirs, dirs) << who << ": WalkResult::dirs";
    EXPECT_EQ(w.result.symlinks, symlinks) << who << ": WalkResult::symlinks";
    EXPECT_EQ(w.result.others, others) << who << ": WalkResult::others";
    EXPECT_EQ(w.result.superseded, sup) << who << ": WalkResult::superseded";
    EXPECT_EQ(w.result.deleted, del) << who << ": WalkResult::deleted";
}

// The walked entry for a superseded version: same path and version.
const EntryResult* find_superseded(const Walked& w, const ExpectedVersion& v) {
    for (const EntryResult* e : w.historical)
        if (e->meta.superseded && e->meta.path == v.path && v.version &&
            e->meta.version == *v.version)
            return e;
    return nullptr;
}

// The walked entry for a deleted file: by path, or by the lost+found/#<inode>
// name a reader uses when it could not recover the name. When several
// candidates exist the one with the expected content wins.
//
// Failing both, by content alone. Some formats damage the name when they
// delete: FAT overwrites the first character of the 8.3 name with 0xE5 and
// keeps no other copy, so `DELETED.TXT` can only ever be recovered as
// `_ELETED.TXT`. Insisting on the path there would mean either failing a
// reader that recovered the file correctly or having it invent the missing
// character. A sha256 identifies the recovered bytes better than a name the
// filesystem deliberately destroyed; the match must still be unique.
const EntryResult* find_deleted(const Walked& w, const ExpectedVersion& v) {
    const std::string orphan = v.inode ? "lost+found/#" + std::to_string(*v.inode) : std::string();
    const EntryResult* first = nullptr;
    for (const EntryResult* e : w.historical) {
        if (!e->meta.deleted) continue;
        if (e->meta.path != v.path && (orphan.empty() || e->meta.path != orphan)) continue;
        if (v.sha256 && e->digests.sha256 == *v.sha256) return e;
        if (!first) first = e;
    }
    if (first != nullptr || !v.sha256) return first;
    const EntryResult* by_content = nullptr;
    for (const EntryResult* e : w.historical) {
        if (!e->meta.deleted || e->digests.sha256 != *v.sha256) continue;
        if (by_content != nullptr) return nullptr;  // ambiguous: prove it by path instead
        by_content = e;
    }
    return by_content;
}

void check_version_fields(const Fixture& fx, const ExpectedVersion& v, const EntryResult& r,
                          const std::string& who) {
    const FileMeta& m = r.meta;
    if (v.size) {
        EXPECT_EQ(m.size, *v.size) << who << " size";
    }
    if (v.inode) {
        EXPECT_EQ(m.inode, *v.inode) << who << " inode";
    }
    if (v.mtime && m.mtime) {
        const std::int64_t diff = *m.mtime > *v.mtime ? *m.mtime - *v.mtime : *v.mtime - *m.mtime;
        EXPECT_LE(diff, fx.mtime_tolerance)
            << who << " mtime " << *m.mtime << " expected " << *v.mtime;
    }
    if (v.sha256 && v.content_recoverable) {
        EXPECT_EQ(r.digests.sha256, *v.sha256) << who << " sha256";
        if (v.size) {
            EXPECT_EQ(r.digests.bytes, *v.size) << who << " bytes received";
        }
    }
}

void check_history(const Fixture& fx, const Walked& w, const std::string& label) {
    const std::string who = fx.name + " (" + label + ")";
    for (const ExpectedVersion& v : fx.superseded) {
        const EntryResult* r = find_superseded(w, v);
        if (!r) {
            std::string have;
            for (const EntryResult* e : w.historical)
                if (e->meta.path == v.path)
                    have += " v" + std::to_string(e->meta.version) +
                            (e->meta.deleted ? "(deleted)" : "");
            ADD_FAILURE() << who << ": superseded " << v.path << " version "
                          << v.version.value_or(0) << " not emitted; versions seen for that path:"
                          << (have.empty() ? " none" : have);
            continue;
        }
        check_version_fields(
            fx, v, *r, who + ": superseded " + v.path + " v" + std::to_string(r->meta.version));
    }
    for (const ExpectedVersion& v : fx.deleted) {
        const EntryResult* r = find_deleted(w, v);
        if (!r) {
            ADD_FAILURE() << who << ": deleted " << v.path << " not emitted (deleted=true)";
            continue;
        }
        if (r->meta.path != v.path)
            std::cout << "note: " << who << ": deleted " << v.path
                      << " recovered without its name as " << r->meta.path << "\n";
        check_version_fields(fx, v, *r, who + ": deleted " + v.path);
    }
    // The live entry of a versioned file may carry the current version.
    for (const ExpectedVersion& v : fx.current) {
        const auto it = w.live.find(v.path);
        if (it == w.live.end() || !v.version) continue;
        if (it->second->meta.version != 0) {
            EXPECT_EQ(it->second->meta.version, *v.version)
                << who << ": live " << v.path << " version";
        }
    }
    EXPECT_GE(w.result.superseded, fx.superseded.size()) << who << ": WalkResult::superseded";
    EXPECT_GE(w.result.deleted, fx.deleted.size()) << who << ": WalkResult::deleted";
    for (const EntryResult* e : w.historical) {
        EXPECT_TRUE(e->meta.deleted || e->meta.superseded);
        if (e->meta.superseded) {
            EXPECT_NE(e->meta.version, 0u)
                << who << ": superseded " << e->meta.path << " has version 0";
        }
    }
}

// ------------------------------------------------------------------ the tests

class FixtureConformance : public ::testing::TestWithParam<std::string> {};

TEST_P(FixtureConformance, LiveTree) {
    LOAD_FIXTURE_OR_SKIP(fx);
    const Walked w = walk_listing(*fx, false);
    expect_clean(*fx, w, "live");
    EXPECT_TRUE(w.historical.empty()) << fx->name << ": history entries emitted with history=false";
    check_counts(*fx, w, "live");
    check_live_tree(*fx, w, "live");
}

TEST_P(FixtureConformance, History) {
    LOAD_FIXTURE_OR_SKIP(fx);
    if (!fx->has_history) GTEST_SKIP() << fx->name << " has no history section";
    const Walked w = walk_listing(*fx, true);
    expect_clean(*fx, w, "history");
    check_counts(*fx, w, "history");
    check_live_tree(*fx, w, "history");  // history must not disturb the live tree
    check_history(*fx, w, "history");
}

TEST_P(FixtureConformance, DiskSink) {
    LOAD_FIXTURE_OR_SKIP(fx);
    std::unique_ptr<FilesystemReader> reader;
    ASSERT_TRUE(open_reader(*fx, reader));
    TempDir tmp(fx->name);
    const stdfs::path root = tmp.path() / "files";
    DiskSink::Options dopts;
    dopts.hash = true;
    dopts.write_versions = true;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open(root.string(), dopts, sink).ok);
    WalkOptions opts;
    opts.history = fx->has_history;
    Walked w;
    w.status = reader->walk(*sink, opts, w.result);
    w.entries = w.result.entries_out;
    w.index();
    expect_clean(*fx, w, "disk");
    check_live_tree(*fx, w, "disk");
    if (fx->has_history) check_history(*fx, w, "disk");

    const std::string who = fx->name + " (disk)";
    for (const ExpectedEntry& e : fx->tree) {
        const auto it = w.live.find(e.path);
        if (it == w.live.end()) continue;  // reported by check_live_tree
        const EntryResult& r = *it->second;
        const stdfs::path on_disk = root / e.path;
        if (e.kind == "regular") {
            EXPECT_TRUE(r.written) << who << ": " << e.path << " not written";
            EXPECT_EQ(r.host_path, on_disk.string()) << who << ": " << e.path << " host_path";
            Digests d;
            ASSERT_TRUE(hash_file(on_disk.string(), d).ok) << who << ": " << on_disk;
            if (e.sha256) {
                EXPECT_EQ(d.sha256, *e.sha256) << who << ": " << e.path << " on-disk sha256";
            }
            if (e.size) {
                EXPECT_EQ(d.bytes, *e.size) << who << ": " << e.path << " on-disk size";
            }
        } else if (e.kind == "directory") {
            EXPECT_TRUE(stdfs::is_directory(on_disk))
                << who << ": " << e.path << " not a directory on disk";
        } else if (e.kind == "symlink") {
#ifndef _WIN32
            std::error_code ec;
            EXPECT_TRUE(stdfs::is_symlink(on_disk))
                << who << ": " << e.path << " not a symlink on disk";
            if (e.link_target) {
                EXPECT_EQ(stdfs::read_symlink(on_disk, ec).string(), *e.link_target)
                    << who << ": " << e.path;
            }
#endif
        }
    }
    const stdfs::path versions = root / kVersionsDir;
    if (!fx->has_history) {
        EXPECT_FALSE(stdfs::exists(versions))
            << who << ": " << kVersionsDir << " created without history";
        return;
    }
    auto check_version_file = [&](const ExpectedVersion& v, const EntryResult& r,
                                  const std::string& what) {
        const stdfs::path on_disk = versions / r.meta.path / ("v" + std::to_string(r.meta.version));
        EXPECT_EQ(r.host_path, on_disk.string()) << who << ": " << what << " host_path";
        if (!(v.sha256 && v.content_recoverable)) return;
        EXPECT_TRUE(r.written) << who << ": " << what << " not written";
        Digests d;
        ASSERT_TRUE(hash_file(on_disk.string(), d).ok)
            << who << ": " << what << " missing at " << on_disk;
        EXPECT_EQ(d.sha256, *v.sha256) << who << ": " << what << " on-disk sha256";
    };
    for (const ExpectedVersion& v : fx->superseded)
        if (const EntryResult* r = find_superseded(w, v))
            check_version_file(v, *r,
                               "superseded " + v.path + " v" + std::to_string(r->meta.version));
    for (const ExpectedVersion& v : fx->deleted)
        if (const EntryResult* r = find_deleted(w, v))
            check_version_file(v, *r, "deleted " + v.path);
    for (const EntryResult* e : w.historical)
        EXPECT_EQ(e->host_path.rfind(versions.string() + "/", 0), 0u)
            << who << ": historical entry " << e->meta.path << " placed at " << e->host_path;
}

std::string entry_signature(const EntryResult& e) {
    const FileMeta& m = e.meta;
    std::string s =
        m.path + "|" + entry_kind_name(m.kind) + "|" + octal(m.mode) + "|" + std::to_string(m.uid) +
        ":" + std::to_string(m.gid) + "|" + std::to_string(m.size) + "|" +
        std::to_string(m.mtime.value_or(-1)) + "|" + std::to_string(m.ctime.value_or(-1)) + "|" +
        std::to_string(m.atime.value_or(-1)) + "|ino " + std::to_string(m.inode) + "|nlink " +
        std::to_string(m.nlink) + "|" + m.link_target + "|" + std::to_string(m.rdev_major) + ":" +
        std::to_string(m.rdev_minor) + "|" + (m.deleted ? "D" : "") + (m.superseded ? "S" : "") +
        "|v" + std::to_string(m.version) + "|" + e.digests.sha256 + "|" +
        std::to_string(e.digests.bytes);
    for (const auto& [k, v] : m.extra) s += "|" + k + "=" + v;
    for (const Diagnostic& d : e.diagnostics) s += "|" + d.code;
    return s;
}

std::vector<std::string> signatures(const Walked& w) {
    std::vector<std::string> out;
    for (const EntryResult& e : w.entries) out.push_back(entry_signature(e));
    for (const Diagnostic& d : w.result.diagnostics)
        out.push_back("diag|" + d.code + "|" + d.message);
    return out;
}

TEST_P(FixtureConformance, Determinism) {
    LOAD_FIXTURE_OR_SKIP(fx);
    std::unique_ptr<FilesystemReader> a;
    ASSERT_TRUE(open_reader(*fx, a));
    const Walked first = walk_listing(*fx, fx->has_history, a.get());
    const Walked again = walk_listing(*fx, fx->has_history, a.get());  // same reader, second walk
    const Walked fresh = walk_listing(*fx, fx->has_history);           // a new reader
    ASSERT_TRUE(first.status.ok) << first.status.error;
    ASSERT_FALSE(first.entries.empty());
    const std::vector<std::string> s1 = signatures(first);
    for (const auto& [label, other] : std::vector<std::pair<std::string, const Walked*>>{
             {"re-walk", &again}, {"fresh reader", &fresh}}) {
        const std::vector<std::string> s2 = signatures(*other);
        EXPECT_EQ(other->status.ok, first.status.ok) << fx->name << " (" << label << ")";
        ASSERT_EQ(s2.size(), s1.size()) << fx->name << " (" << label << "): entry count differs";
        for (std::size_t i = 0; i < s1.size(); ++i) {
            if (s1[i] != s2[i]) {
                ADD_FAILURE() << fx->name << " (" << label << "): entry " << i
                              << " differs\n  first: " << s1[i] << "\n  other: " << s2[i];
                break;
            }
        }
    }
}

INSTANTIATE_TEST_SUITE_P(Fixtures, FixtureConformance, ::testing::ValuesIn(fixture_names()),
                         param_name);

// One table that says which fixtures the registered readers cover. Never
// fails; it is the log line to read when a format is "supported" on paper.
TEST(FixtureCoverage, Report) {
    if (!stdfs::exists(fixtures_dir())) GTEST_SKIP() << "fixtures not built: " << fixtures_dir();
    std::cout << "fixture conformance coverage (" << fixtures_dir().string() << ")\n";
    std::cout << "  registered readers:";
    for (const std::string& k : FilesystemRegistry::instance().formats()) std::cout << " " << k;
    std::cout << "\n";
    std::size_t covered = 0, total = 0;
    for (const std::string& name : fixture_names()) {
        if (name == kNoFixtures) continue;
        const stdfs::path yaml = fixtures_dir() / (name + ".expected.yaml");
        std::string why;
        const std::optional<Node> doc = fixture_yaml::parse_file(yaml.string(), &why);
        std::string fmt = doc ? (*doc)["image"].str_or("format", "?") : "unparsable";
        const bool has_tree = doc && doc->has("tree");
        const std::string key = reader_key_for(fmt);
        std::string state;
        if (!has_tree)
            state = "wrapper (partitions/volumes/layers), not a reader fixture";
        else if (key.empty())
            state = "NO READER";
        else {
            state = "reader '" + key + "'";
            covered++;
        }
        if (has_tree) total++;
        std::cout << "  " << name << ": format " << fmt << ": " << state;
        if (doc && (*doc)["history"].is_mapping()) std::cout << " [history]";
        std::cout << "\n";
    }
    std::cout << "  " << covered << " of " << total << " reader fixtures have a reader\n";
    RecordProperty("fixtures_with_reader", static_cast<int>(covered));
    RecordProperty("reader_fixtures", static_cast<int>(total));
}

// ------------------------------------------------------------------ fixture_yaml

const char* kSample = R"(# Generated by tests/fixtures/generate.py. Do not edit; regenerate.
schema: omnitrace-fixture/1
name: sample
image:
  file: sample.img
  format: jffs2
  size: 393216
  sha256: 21ece6c8d59e69681d3745a4ba50e133f1c229ef572b42048d686be60a8af2e1
  builder: mkfs.jffs2 (mtd-utils) 2.1.5
  argv:
  - -r
  - /tmp/stage
  - '65536'
  - --little-endian
  empty: []
  nothing: {}
features:
  symlink: true
  hardlink: false
  mode: true
  mtime_resolution: 2
tree:
- path: bin
  kind: directory
  mode: '0755'
  uid: 1000
  gid: 100
  size: 0
  mtime: 1700000002
- path: data/dir with spaces/ünïcödé ファイル.txt
  kind: regular
  mode: '0644'
  size: 296
  sha256: ba2890ab3c93ac668cb589203c3efd60aa30b24e74fd8afe54262e44a7c59cd3
  mtime: 1700000022
- path: bin/sh
  kind: symlink
  link_target: busybox
attrs:
  version: '4.0'
  disk_signature: '0x0badc0de'
  pinned_note: 'after mkyaffs2: every object header''s atime/ctime set to its mtime (nsec 0),
    node CRCs recomputed'
  quoted: "tab\there \"q\" \u00e9\x41"
  negative: -5
history:
  superseded:
  - path: history/config.txt
    inode: 17
    version: 1
    content_recoverable: false
  deleted: []
  note: mtools rewrites a file by deleting the entry and allocating afresh; the old clusters may have been reused,
    so only the deleted.txt bytes are guaranteed recoverable. Timestamps are local time with TZ=UTC.
layers:
- gzip
- tar
nested:
- - a
  - b
- key: v
  other: w
null_value:
)";

TEST(FixtureYaml, EmbeddedSample) {
    std::string err;
    const std::optional<Node> doc = fixture_yaml::parse(kSample, &err);
    ASSERT_TRUE(doc.has_value()) << err;
    const Node& d = *doc;
    ASSERT_TRUE(d.is_mapping());
    EXPECT_EQ(d.str_or("schema"), "omnitrace-fixture/1");
    EXPECT_EQ(d["name"].str(), "sample");
    EXPECT_EQ(d["image"]["format"].str(), "jffs2");
    EXPECT_EQ(d["image"]["size"].as_uint(), 393216u);
    EXPECT_EQ(d["image"]["size"].as_int(), 393216);
    EXPECT_EQ(d["image"]["builder"].str(), "mkfs.jffs2 (mtd-utils) 2.1.5");
    const Node& argv = d["image"]["argv"];
    ASSERT_TRUE(argv.is_sequence());
    ASSERT_EQ(argv.size(), 4u);
    EXPECT_EQ(argv[0].str(), "-r");
    EXPECT_EQ(argv[1].str(), "/tmp/stage");
    EXPECT_EQ(argv[2].str(), "65536");
    EXPECT_TRUE(argv[2].quoted());
    EXPECT_FALSE(argv[0].quoted());
    EXPECT_EQ(argv[3].str(), "--little-endian");
    EXPECT_TRUE(argv[9].is_null());
    EXPECT_TRUE(d["image"]["empty"].is_sequence());
    EXPECT_EQ(d["image"]["empty"].size(), 0u);
    EXPECT_TRUE(d["image"]["nothing"].is_mapping());
    EXPECT_EQ(d["features"]["symlink"].as_bool(), true);
    EXPECT_EQ(d["features"]["hardlink"].as_bool(), false);
    EXPECT_FALSE(d["features"]["owner"].as_bool().has_value());
    EXPECT_EQ(d["features"]["mtime_resolution"].as_int(), 2);
    const Node& tree = d["tree"];
    ASSERT_EQ(tree.size(), 3u);
    EXPECT_EQ(tree[0]["path"].str(), "bin");
    EXPECT_EQ(tree[0]["mode"].str(), "0755");
    EXPECT_TRUE(tree[0]["mode"].quoted());
    EXPECT_EQ(tree[0]["uid"].as_uint(), 1000u);
    EXPECT_EQ(tree[0]["mtime"].as_int(), 1700000002);
    EXPECT_EQ(tree[1]["path"].str(), "data/dir with spaces/ünïcödé ファイル.txt");
    EXPECT_EQ(tree[1]["size"].as_uint(), 296u);
    EXPECT_EQ(tree[2]["link_target"].str(), "busybox");
    EXPECT_FALSE(tree[2].has("size"));
    EXPECT_EQ(tree[2].entries().size(), 3u);
    EXPECT_EQ(tree[2].entries()[0].first, "path");
    EXPECT_EQ(d["attrs"]["version"].str(), "4.0");
    EXPECT_EQ(d["attrs"]["disk_signature"].str(), "0x0badc0de");
    EXPECT_FALSE(d["attrs"]["disk_signature"].as_uint().has_value());
    EXPECT_EQ(d["attrs"]["pinned_note"].str(),
              "after mkyaffs2: every object header's atime/ctime set to its mtime (nsec 0), node "
              "CRCs recomputed");
    EXPECT_EQ(d["attrs"]["quoted"].str(),
              "tab\there \"q\" \xC3\xA9"
              "A");
    EXPECT_EQ(d["attrs"]["negative"].as_int(), -5);
    EXPECT_FALSE(d["attrs"]["negative"].as_uint().has_value());
    EXPECT_EQ(d["history"]["superseded"][0]["inode"].as_uint(), 17u);
    EXPECT_EQ(d["history"]["superseded"][0]["content_recoverable"].as_bool(), false);
    EXPECT_TRUE(d["history"]["deleted"].is_sequence());
    EXPECT_EQ(d["history"]["deleted"].size(), 0u);
    EXPECT_EQ(d["history"]["note"].str(),
              "mtools rewrites a file by deleting the entry and allocating afresh; the old "
              "clusters may have been "
              "reused, so only the deleted.txt bytes are guaranteed recoverable. Timestamps are "
              "local time with "
              "TZ=UTC.");
    ASSERT_EQ(d["layers"].size(), 2u);
    EXPECT_EQ(d["layers"][1].str(), "tar");
    ASSERT_EQ(d["nested"].size(), 2u);
    ASSERT_TRUE(d["nested"][0].is_sequence());
    EXPECT_EQ(d["nested"][0][1].str(), "b");
    EXPECT_EQ(d["nested"][1]["other"].str(), "w");
    EXPECT_TRUE(d["null_value"].is_null());
    EXPECT_TRUE(d.has("null_value"));
    EXPECT_FALSE(d.has("absent"));
    EXPECT_TRUE(d["absent"]["deeper"][3].is_null());
    EXPECT_EQ(d.find("absent"), nullptr);
    EXPECT_EQ(d.size(), 10u);
}

TEST(FixtureYaml, RejectsWhatItDoesNotSupport) {
    struct Case {
        const char* text;
        const char* why;
    };
    const Case cases[] = {
        {"a: [1, 2]\n", "flow sequence"},
        {"a: {b: 1}\n", "flow mapping"},
        {"a: |\n  text\n", "block scalar"},
        {"a: &x 1\nb: *x\n", "anchor"},
        {"a: !!int 1\n", "tag"},
        {"a: 'open\n", "unterminated quote"},
        {"a: \"bad \\q\"\n", "unknown escape"},
        {"a: 1\na: 2\n", "duplicate key"},
        {"a:\n  b: 1\n c: 2\n", "bad dedent"},
        {"a: 1\n  b: 2\n", "indented after a scalar value"},
        {"\ta: 1\n", "tab indentation"},
        {"- a\nb: 1\n", "sequence then mapping at the same level"},
    };
    for (const Case& c : cases) {
        std::string err;
        EXPECT_FALSE(fixture_yaml::parse(c.text, &err).has_value())
            << c.why << " must be rejected: " << c.text;
        EXPECT_FALSE(err.empty()) << c.why;
    }
    std::string err;
    const std::optional<Node> empty = fixture_yaml::parse("# only a comment\n\n---\n", &err);
    ASSERT_TRUE(empty.has_value()) << err;
    EXPECT_TRUE(empty->is_null());
    const std::optional<Node> scalar = fixture_yaml::parse("just text\n", &err);
    ASSERT_TRUE(scalar.has_value()) << err;
    EXPECT_EQ(scalar->str(), "just text");
    EXPECT_FALSE(fixture_yaml::parse_file("/nonexistent/omnitrace/file.yaml", &err).has_value());
    EXPECT_FALSE(err.empty());
    // Values that PyYAML writes unquoted and OmniTrace must not mistake.
    const std::optional<Node> ints = fixture_yaml::parse(
        "a: 18446744073709551615\nb: 18446744073709551616\n"
        "c: -9223372036854775808\nd: 0x10\ne: ''\n",
        &err);
    ASSERT_TRUE(ints.has_value()) << err;
    EXPECT_EQ((*ints)["a"].as_uint(), 18446744073709551615ull);
    EXPECT_FALSE((*ints)["a"].as_int().has_value());
    EXPECT_FALSE((*ints)["b"].as_uint().has_value());
    EXPECT_EQ((*ints)["c"].as_int(), std::numeric_limits<std::int64_t>::min());
    EXPECT_FALSE((*ints)["d"].as_uint().has_value());
    EXPECT_TRUE((*ints)["e"].is_scalar());
    EXPECT_EQ((*ints)["e"].str(), "");
    EXPECT_FALSE((*ints)["e"].as_uint().has_value());
}

// Every ground-truth file present must parse and carry the fields the
// conformance tests rely on; index.yaml must agree with the directory.
TEST(FixtureYaml, ParsesEveryExpectedYaml) {
    if (!stdfs::exists(fixtures_dir())) GTEST_SKIP() << "fixtures not built: " << fixtures_dir();
    std::size_t seen = 0;
    for (const std::string& name : fixture_names()) {
        if (name == kNoFixtures) continue;
        const stdfs::path yaml = fixtures_dir() / (name + ".expected.yaml");
        std::string err;
        const std::optional<Node> doc = fixture_yaml::parse_file(yaml.string(), &err);
        ASSERT_TRUE(doc.has_value()) << err;
        seen++;
        EXPECT_EQ((*doc)["schema"].str(), "omnitrace-fixture/1") << yaml;
        EXPECT_EQ((*doc)["name"].str(), name) << yaml;
        const Node& image = (*doc)["image"];
        ASSERT_TRUE(image.is_mapping()) << yaml;
        EXPECT_FALSE(image.str_or("format").empty()) << yaml;
        EXPECT_EQ(image["sha256"].str().size(), 64u) << yaml;
        const stdfs::path img = fixtures_dir() / image.str_or("file");
        if (stdfs::exists(img)) {
            EXPECT_EQ(image["size"].as_uint(), static_cast<std::uint64_t>(stdfs::file_size(img)))
                << yaml;
        }
        if (doc->has("tree")) {
            ASSERT_TRUE((*doc)["tree"].is_sequence()) << yaml;
            std::string prev;
            for (const Node& row : (*doc)["tree"].items()) {
                ASSERT_TRUE(row.is_mapping()) << yaml;
                const std::string path = row.str_or("path");
                EXPECT_FALSE(path.empty()) << yaml;
                EXPECT_LT(prev, path) << yaml << ": tree not sorted by path";
                prev = path;
                const std::string kind = row.str_or("kind");
                EXPECT_TRUE(kind == "regular" || kind == "directory" || kind == "symlink")
                    << yaml << ": " << path;
                if (kind == "regular") {
                    EXPECT_EQ(row["sha256"].str().size(), 64u) << yaml << ": " << path;
                }
                if (row.has("mode")) {
                    EXPECT_TRUE(mode_of(row["mode"]).has_value()) << yaml << ": " << path;
                }
                EXPECT_TRUE(row["mtime"].as_int().has_value()) << yaml << ": " << path;
            }
        }
        if (doc->has("history")) {
            const Node& h = (*doc)["history"];
            ASSERT_TRUE(h.is_mapping()) << yaml;
            for (const char* key : {"superseded", "current", "deleted"}) {
                if (!h.has(key)) continue;
                EXPECT_TRUE(h[key].is_sequence()) << yaml << ": history." << key;
                for (const Node& row : h[key].items())
                    EXPECT_FALSE(row.str_or("path").empty()) << yaml;
            }
        }
    }
    EXPECT_GT(seen, 0u);
    const stdfs::path index = fixtures_dir() / "index.yaml";
    if (!stdfs::exists(index)) return;
    std::string err;
    const std::optional<Node> idx = fixture_yaml::parse_file(index.string(), &err);
    ASSERT_TRUE(idx.has_value()) << err;
    for (const Node& row : (*idx)["fixtures"].items()) {
        EXPECT_TRUE(stdfs::exists(fixtures_dir() / row.str_or("expected")))
            << "index.yaml lists " << row.str_or("name");
        EXPECT_TRUE(stdfs::exists(fixtures_dir() / row.str_or("image")))
            << "index.yaml lists " << row.str_or("name");
    }
}

}  // namespace
}  // namespace omnitrace::fs
