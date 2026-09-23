// yaml_test.cpp — manifest/listing YAML: round trip, determinism, tolerance
// of missing keys, and precise failures on hostile input.
#include "omnitrace/output/Yaml.h"

#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>

#include "fixture.h"

namespace omnitrace::output {
namespace {

using test::full_manifest;
using test::sample_entries;

// Every top-level key in the documented order, nothing else.
TEST(Yaml, TopLevelKeyOrder) {
    const std::string y = manifest_to_yaml(full_manifest());
    const YAML::Node root = YAML::Load(y);
    ASSERT_TRUE(root.IsMap());
    std::vector<std::string> keys;
    for (const auto& kv : root) keys.push_back(kv.first.Scalar());
    const std::vector<std::string> want = {"schema",   "run",   "evidence",   "nodes",
                                           "coverage", "tools", "diagnostics"};
    EXPECT_EQ(keys, want);
    EXPECT_EQ(root["schema"].Scalar(), "omnitrace/1");
    // ISO timestamps are quoted so YAML 1.1 consumers keep them as strings.
    EXPECT_NE(y.find("started_at: \"2026-01-02T03:04:05Z\""), std::string::npos);
    EXPECT_NE(y.find("mtime_iso: \"2023-11-14T22:13:20Z\""), std::string::npos);
}

TEST(Yaml, NodeKeyOrder) {
    const YAML::Node root = YAML::Load(manifest_to_yaml(full_manifest()));
    const YAML::Node n = root["nodes"][3];  // the File node with every FileMeta field
    std::vector<std::string> keys;
    for (const auto& kv : n) keys.push_back(kv.first.Scalar());
    const std::vector<std::string> want = {
        "id",       "parent", "kind",  "name", "format",  "location",    "confidence",
        "evidence", "endian", "attrs", "file", "digests", "diagnostics", "children"};
    EXPECT_EQ(keys, want);

    std::vector<std::string> fkeys;
    for (const auto& kv : n["file"]) fkeys.push_back(kv.first.Scalar());
    const std::vector<std::string> fwant = {
        "path",       "kind",  "mode",      "mode_octal", "uid",     "gid",
        "size",       "mtime", "mtime_iso", "mtime_nsec", "ctime",   "ctime_iso",
        "ctime_nsec", "atime", "atime_iso", "atime_nsec", "crtime",  "crtime_iso",
        "inode",      "nlink", "deleted",   "superseded", "version", "extra"};
    EXPECT_EQ(fkeys, fwant);
    EXPECT_EQ(n["file"]["mode_octal"].Scalar(), "0644");
    EXPECT_EQ(n["file"]["mtime_iso"].Scalar(), "2023-11-14T22:13:20Z");
    EXPECT_EQ(n["location"]["offset"].as<std::uint64_t>(), 0x123456u);
    EXPECT_EQ(n["location"]["offset_hex"].Scalar(), "0x123456");
    // Convenience twins are quoted so YAML 1.1 consumers keep them as strings.
    EXPECT_NE(manifest_to_yaml(full_manifest()).find("offset_hex: \"0x123456\""),
              std::string::npos);
    EXPECT_NE(manifest_to_yaml(full_manifest()).find("mode_octal: \"0644\""), std::string::npos);
}

TEST(Yaml, FlagsOnlyWhenSetAndBlocksOnlyWhenPresent) {
    const YAML::Node root = YAML::Load(manifest_to_yaml(full_manifest()));
    const YAML::Node link = root["nodes"][4];
    EXPECT_FALSE(link["file"]["deleted"].IsDefined());
    EXPECT_FALSE(link["file"]["superseded"].IsDefined());
    EXPECT_FALSE(link["file"]["version"].IsDefined());
    EXPECT_FALSE(link["file"]["extra"].IsDefined());
    EXPECT_FALSE(link["file"]["rdev_major"].IsDefined());
    EXPECT_FALSE(link["file"]["ctime"].IsDefined());
    EXPECT_EQ(link["file"]["link_target"].Scalar(), "busybox");
    EXPECT_FALSE(link["digests"].IsDefined());
    const YAML::Node dev = root["nodes"][5];
    EXPECT_EQ(dev["file"]["rdev_major"].as<int>(), 5);
    EXPECT_EQ(dev["file"]["rdev_minor"].as<int>(), 1);
    const YAML::Node part = root["nodes"][1];
    EXPECT_FALSE(part["file"].IsDefined());
    EXPECT_FALSE(part["digests"].IsDefined());
    EXPECT_TRUE(part["attrs"].IsMap());
    EXPECT_EQ(part["attrs"]["index"].Scalar(), "2");
    EXPECT_EQ(root["tools"][0]["seconds"].as<double>(), 0.1);
    EXPECT_EQ(root["tools"][0]["exit_code"].as<int>(), -1);
}

TEST(Yaml, Deterministic) {
    const Manifest m = full_manifest();
    const std::string a = manifest_to_yaml(m);
    const std::string b = manifest_to_yaml(m);
    EXPECT_EQ(a, b);
    EXPECT_EQ(listing_to_yaml("n000003", sample_entries()),
              listing_to_yaml("n000003", sample_entries()));
    EXPECT_EQ(manifest_json_schema(), manifest_json_schema());
    EXPECT_EQ(a.back(), '\n');
}

TEST(Yaml, RoundTripIsByteIdentical) {
    const Manifest m = full_manifest();
    const std::string a = manifest_to_yaml(m);
    Manifest back;
    const Status st = manifest_from_yaml(a, back);
    ASSERT_TRUE(st.ok) << st.error;
    EXPECT_EQ(manifest_to_yaml(back), a);

    ASSERT_EQ(back.nodes().size(), m.nodes().size());
    EXPECT_EQ(back.run.argv, m.run.argv);
    EXPECT_EQ(back.evidence.size(), 1u);
    EXPECT_EQ(back.evidence[0].digests.sha256, std::string(64, 'a'));
    EXPECT_EQ(back.coverage.size(), 2u);
    EXPECT_EQ(back.tools.size(), 1u);
    EXPECT_EQ(back.tools[0].exit_code, -1);
    EXPECT_DOUBLE_EQ(back.tools[0].seconds, 0.1);
    EXPECT_EQ(back.diagnostics.size(), 1u);

    const Node* f = back.find("n000004");
    ASSERT_NE(f, nullptr);
    ASSERT_TRUE(f->file.has_value());
    const FileMeta& fm = *f->file;
    const FileMeta want = test::full_file_meta();
    EXPECT_EQ(fm.path, want.path);
    EXPECT_EQ(fm.kind, want.kind);
    EXPECT_EQ(fm.mode, want.mode);
    EXPECT_EQ(fm.uid, want.uid);
    EXPECT_EQ(fm.gid, want.gid);
    EXPECT_EQ(fm.size, want.size);
    EXPECT_EQ(fm.mtime, want.mtime);
    EXPECT_EQ(fm.ctime, want.ctime);
    EXPECT_EQ(fm.atime, want.atime);
    EXPECT_EQ(fm.crtime, want.crtime);
    EXPECT_EQ(fm.mtime_nsec, want.mtime_nsec);
    EXPECT_EQ(fm.ctime_nsec, want.ctime_nsec);
    EXPECT_EQ(fm.atime_nsec, want.atime_nsec);
    EXPECT_EQ(fm.inode, want.inode);
    EXPECT_EQ(fm.nlink, want.nlink);
    EXPECT_EQ(fm.deleted, want.deleted);
    EXPECT_EQ(fm.superseded, want.superseded);
    EXPECT_EQ(fm.version, want.version);
    EXPECT_EQ(fm.extra, want.extra);
    EXPECT_EQ(f->digests.md5, std::string(32, 'b'));
    EXPECT_EQ(f->digests.bytes, 4096u);

    const Node* fs = back.find("n000003");
    ASSERT_NE(fs, nullptr);
    EXPECT_EQ(fs->endian, Endian::Big);
    EXPECT_EQ(fs->kind, NodeKind::Filesystem);
    ASSERT_EQ(fs->diagnostics.size(), 2u);
    EXPECT_EQ(fs->diagnostics[0].severity, Severity::Warning);
    EXPECT_EQ(fs->diagnostics[0].code, "squashfs-limit-entries");
    EXPECT_EQ(fs->child_ids, (std::vector<std::string>{"n000004", "n000005", "n000006"}));
    EXPECT_EQ(back.find("n000008")->diagnostics[0].severity, Severity::Error);
    EXPECT_EQ(back.find("n000009")->kind, NodeKind::Artifact);
    EXPECT_EQ(back.count(NodeKind::File), 3u);
}

TEST(Yaml, EveryNodeKindSurvives) {
    Manifest m;
    for (const NodeKind k :
         {NodeKind::Image, NodeKind::Partition, NodeKind::Container, NodeKind::Filesystem,
          NodeKind::File, NodeKind::Region, NodeKind::Artifact}) {
        Node n;
        n.kind = k;
        n.name = node_kind_name(k);
        if (k == NodeKind::File) n.file = FileMeta{};
        m.add_node(n);
    }
    Manifest back;
    ASSERT_TRUE(manifest_from_yaml(manifest_to_yaml(m), back).ok);
    ASSERT_EQ(back.nodes().size(), 7u);
    for (std::size_t i = 0; i < 7; ++i) EXPECT_EQ(back.nodes()[i].kind, m.nodes()[i].kind);
    EXPECT_EQ(manifest_to_yaml(back), manifest_to_yaml(m));
}

TEST(Yaml, AmbiguousStringsAreQuotedAndSurvive) {
    Manifest m;
    Node n;
    n.kind = NodeKind::Image;
    n.name = "123";
    n.format = "true";
    n.evidence = "null";
    n.attrs["a"] = "0x10";
    n.attrs["b"] = "";
    n.attrs["c"] = "1e3";
    n.attrs["d"] = " padded ";
    n.attrs["e"] = "ünïcödé ファイル";
    n.attrs["f"] = "line1\nline2\ttab";
    m.add_node(n);
    const std::string y = manifest_to_yaml(m);
    EXPECT_NE(y.find("name: \"123\""), std::string::npos);
    EXPECT_NE(y.find("format: \"true\""), std::string::npos);
    Manifest back;
    ASSERT_TRUE(manifest_from_yaml(y, back).ok);
    const Node& b = back.nodes()[0];
    EXPECT_EQ(b.name, "123");
    EXPECT_EQ(b.format, "true");
    EXPECT_EQ(b.evidence, "null");
    EXPECT_EQ(b.attrs, n.attrs);
}

TEST(Yaml, MissingOptionalKeysAreTolerated) {
    const std::string y =
        "schema: omnitrace/1\n"
        "nodes:\n"
        "  - id: n000001\n"
        "    kind: image\n"
        "  - id: n000002\n"
        "    parent: n000001\n"
        "    kind: file\n"
        "    file:\n"
        "      path: a/b\n";
    Manifest m;
    const Status st = manifest_from_yaml(y, m);
    ASSERT_TRUE(st.ok) << st.error;
    ASSERT_EQ(m.nodes().size(), 2u);
    EXPECT_EQ(m.run.tool, "omnitrace");
    EXPECT_EQ(m.nodes()[0].confidence, 0);
    EXPECT_EQ(m.nodes()[0].endian, Endian::Little);
    EXPECT_EQ(m.nodes()[0].child_ids, std::vector<std::string>{"n000002"});
    ASSERT_TRUE(m.nodes()[1].file.has_value());
    EXPECT_EQ(m.nodes()[1].file->path, "a/b");
    EXPECT_EQ(m.nodes()[1].file->kind, EntryKind::Regular);
    EXPECT_FALSE(m.nodes()[1].file->mtime.has_value());
    EXPECT_FALSE(m.nodes()[1].file->deleted);
}

TEST(Yaml, ConvenienceTwinsAreIgnoredOnRead) {
    const std::string y =
        "schema: omnitrace/1\n"
        "nodes:\n"
        "  - id: n000001\n"
        "    kind: file\n"
        "    location: {source: e1, offset: 4096, offset_hex: \"0xdeadbeef\", length: 1}\n"
        "    file: {path: x, mode: 511, mode_octal: \"0000\", mtime: 5, mtime_iso: garbage}\n";
    Manifest m;
    ASSERT_TRUE(manifest_from_yaml(y, m).ok);
    EXPECT_EQ(m.nodes()[0].location.offset, 4096u);
    EXPECT_EQ(m.nodes()[0].file->mode, 511u);
    EXPECT_EQ(m.nodes()[0].file->mtime, 5);
}

TEST(Yaml, DanglingParentKeepsRecordedDiagnosticWithoutDuplicating) {
    Manifest m;
    Node n;
    n.kind = NodeKind::Region;
    n.parent_id = "n999999";
    m.add_node(n);
    ASSERT_EQ(m.nodes()[0].diagnostics.size(), 1u);
    const std::string y = manifest_to_yaml(m);
    Manifest back;
    ASSERT_TRUE(manifest_from_yaml(y, back).ok);
    ASSERT_EQ(back.nodes()[0].diagnostics.size(), 1u);
    EXPECT_EQ(back.nodes()[0].diagnostics[0].code, "manifest-parent-missing");
    EXPECT_EQ(manifest_to_yaml(back), y);

    // A hand-edited file that dropped the warning gets it back.
    const std::string stripped =
        "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: region, parent: n999999}\n";
    Manifest again;
    ASSERT_TRUE(manifest_from_yaml(stripped, again).ok);
    ASSERT_EQ(again.nodes()[0].diagnostics.size(), 1u);
    EXPECT_EQ(again.nodes()[0].diagnostics[0].code, "manifest-parent-missing");
}

struct Hostile {
    const char* name;
    const char* text;
    const char* expect;  // substring the error must contain
};

TEST(Yaml, HostileInputsFailWithNodeIdAndKey) {
    const Hostile cases[] = {
        {"not yaml", "schema: [unterminated", "parse error"},
        {"scalar document", "just a string\n", "must be a map"},
        {"wrong schema", "schema: omnitrace/9\n", "'schema'"},
        {"missing schema", "nodes: []\n", "'schema' is required"},
        {"nodes not a sequence", "schema: omnitrace/1\nnodes: {a: b}\n",
         "'nodes' must be a sequence"},
        {"node not a map", "schema: omnitrace/1\nnodes: [7]\n", "item 0 must be a map"},
        {"node without id", "schema: omnitrace/1\nnodes:\n  - kind: image\n",
         "node #1: key 'id' is required"},
        {"node without kind", "schema: omnitrace/1\nnodes:\n  - id: n000001\n",
         "node n000001: key 'kind' is required"},
        {"unknown kind", "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: blob}\n",
         "node n000001: key 'kind' has unknown value 'blob'"},
        {"unknown endian",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, endian: middle}\n",
         "node n000001: key 'endian'"},
        {"offset negative",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, location: {offset: -1}}\n",
         "node n000001 location: key 'offset' must be a non-negative integer"},
        {"offset overflow",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, location: {offset: "
         "99999999999999999999}}\n",
         "node n000001 location: key 'offset'"},
        {"offset string",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, location: {offset: abc}}\n",
         "node n000001 location: key 'offset'"},
        {"offset hex only",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, location: {offset: 0x10}}\n",
         "node n000001 location: key 'offset'"},
        {"location not a map",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, location: 5}\n",
         "node n000001: key 'location' must be a map"},
        {"confidence too big",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, confidence: 101}\n",
         "node n000001: key 'confidence' is out of range"},
        {"confidence absurd",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, confidence: "
         "18446744073709551616}\n",
         "node n000001: key 'confidence'"},
        {"attrs not a map",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, attrs: [1]}\n",
         "node n000001: key 'attrs' must be a map of strings"},
        {"file not a map",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: file, file: yes}\n",
         "node n000001: key 'file' must be a map"},
        {"file mode overflow",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: file, file: {mode: 4294967296}}\n",
         "node n000001 file: key 'mode' is out of range"},
        {"file kind unknown",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: file, file: {kind: pipe}}\n",
         "node n000001 file: key 'kind' has unknown value 'pipe'"},
        {"file deleted not bool",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: file, file: {deleted: maybe}}\n",
         "node n000001 file: key 'deleted' must be a boolean"},
        {"file mtime float",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: file, file: {mtime: 1.5}}\n",
         "node n000001 file: key 'mtime' must be an integer"},
        {"file mtime_nsec negative",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: file, file: {mtime_nsec: -3}}\n",
         "node n000001 file: key 'mtime_nsec'"},
        {"digest not string",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, digests: {sha256: [1]}}\n",
         "node n000001 digests: key 'sha256' must be a string"},
        {"diagnostic severity unknown",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, diagnostics: [{severity: "
         "fatal, code: x}]}\n",
         "node n000001 diagnostics[0]: key 'severity' has unknown value 'fatal'"},
        {"diagnostics not a sequence",
         "schema: omnitrace/1\nnodes:\n  - {id: n000001, kind: image, diagnostics: 3}\n",
         "node n000001: key 'diagnostics' must be a sequence"},
        {"ids out of order", "schema: omnitrace/1\nnodes:\n  - {id: n000002, kind: image}\n",
         "node n000002: key 'id' is 'n000002' but position 1"},
        {"run not a map", "schema: omnitrace/1\nrun: 4\n", "manifest: key 'run' must be a map"},
        {"run argv not strings", "schema: omnitrace/1\nrun: {argv: [[1]]}\n", "run: key 'argv'"},
        {"evidence size string", "schema: omnitrace/1\nevidence: [{id: e1, size: big}]\n",
         "evidence[0]: key 'size' must be a non-negative integer"},
        {"tool exit_code huge", "schema: omnitrace/1\ntools: [{name: t, exit_code: 99999999999}]\n",
         "tools[0]: key 'exit_code' is out of range"},
        {"tool seconds string", "schema: omnitrace/1\ntools: [{name: t, seconds: fast}]\n",
         "tools[0]: key 'seconds' must be a number"},
        {"coverage row scalar", "schema: omnitrace/1\ncoverage: [x]\n", "item 0 must be a map"},
        {"run diagnostics scalar", "schema: omnitrace/1\ndiagnostics: [x]\n",
         "manifest: key 'diagnostics' item 0 must be a map"},
    };
    for (const Hostile& h : cases) {
        Manifest m;
        const Status st = manifest_from_yaml(h.text, m);
        EXPECT_FALSE(st.ok) << h.name;
        EXPECT_NE(st.error.find(h.expect), std::string::npos)
            << h.name << ": got '" << st.error << "'";
    }
}

TEST(Yaml, EmptyAndTruncatedDocuments) {
    Manifest m;
    EXPECT_FALSE(manifest_from_yaml("", m).ok);
    EXPECT_FALSE(manifest_from_yaml("---\n", m).ok);
    EXPECT_FALSE(manifest_from_yaml(std::string("\0\0\0", 3), m).ok);
    // Truncate a valid document at every 97th byte: never crash, and either
    // fail cleanly or parse a prefix.
    const std::string full = manifest_to_yaml(test::full_manifest());
    for (std::size_t cut = 0; cut < full.size(); cut += 97) {
        Manifest partial;
        const Status st = manifest_from_yaml(full.substr(0, cut), partial);
        (void)st;
    }
}

TEST(Yaml, DeepNestingDoesNotCrash) {
    std::string y = "schema: omnitrace/1\nnodes: ";
    for (int i = 0; i < 20000; ++i) y += '[';
    Manifest m;
    EXPECT_FALSE(manifest_from_yaml(y, m).ok);
}

TEST(Yaml, ListingLayout) {
    const std::string y = listing_to_yaml("n000003", sample_entries());
    const YAML::Node root = YAML::Load(y);
    std::vector<std::string> keys;
    for (const auto& kv : root) keys.push_back(kv.first.Scalar());
    EXPECT_EQ(keys, (std::vector<std::string>{"filesystem", "entries"}));
    EXPECT_EQ(root["filesystem"].Scalar(), "n000003");
    ASSERT_EQ(root["entries"].size(), 3u);

    const YAML::Node a = root["entries"][0];
    std::vector<std::string> akeys;
    for (const auto& kv : a) akeys.push_back(kv.first.Scalar());
    EXPECT_EQ(akeys, (std::vector<std::string>{"file", "digests", "host_path", "written"}));
    EXPECT_EQ(a["file"]["path"].Scalar(), "etc/config/network.conf");
    EXPECT_EQ(a["file"]["version"].as<int>(), 7);
    EXPECT_TRUE(a["file"]["deleted"].as<bool>());
    EXPECT_EQ(a["digests"]["sha256"].Scalar(), std::string(64, 'c'));

    const YAML::Node b = root["entries"][1];
    EXPECT_EQ(b["file"]["path"].Scalar(), "weird|name\nwith newline");
    EXPECT_TRUE(b["truncated"].as<bool>());
    EXPECT_FALSE(b["written"].IsDefined());
    EXPECT_FALSE(b["host_path"].IsDefined());
    EXPECT_FALSE(b["digests"].IsDefined());
    ASSERT_EQ(b["diagnostics"].size(), 1u);
    EXPECT_EQ(b["diagnostics"][0]["code"].Scalar(), "sink-limit-bytes");

    const YAML::Node c = root["entries"][2];
    EXPECT_EQ(c["file"]["link_target"].Scalar(), "busybox");
    EXPECT_FALSE(c["diagnostics"].IsDefined());
}

TEST(Yaml, ListingEmpty) {
    const std::string y = listing_to_yaml("n000001", {});
    const YAML::Node root = YAML::Load(y);
    EXPECT_EQ(root["filesystem"].Scalar(), "n000001");
    EXPECT_TRUE(root["entries"].IsSequence());
    EXPECT_EQ(root["entries"].size(), 0u);
}

// --------------------------------------------------- listing_from_yaml

// The inverse has to be exact, because every post-analysis layer takes
// entries and nothing else: what a round trip loses, a re-examination of a
// case can never recover.
TEST(Yaml, ListingRoundTripsEveryField) {
    const std::vector<EntryResult> in = sample_entries();
    std::string node_id;
    std::vector<EntryResult> back;
    ASSERT_TRUE(listing_from_yaml(listing_to_yaml("n000003", in), node_id, back));
    EXPECT_EQ(node_id, "n000003");
    ASSERT_EQ(back.size(), in.size());

    for (std::size_t i = 0; i < in.size(); ++i) {
        const FileMeta& a = in[i].meta;
        const FileMeta& b = back[i].meta;
        EXPECT_EQ(a.path, b.path) << "entry " << i;
        EXPECT_EQ(a.kind, b.kind) << "entry " << i;
        EXPECT_EQ(a.mode, b.mode);
        EXPECT_EQ(a.uid, b.uid);
        EXPECT_EQ(a.gid, b.gid);
        EXPECT_EQ(a.size, b.size);
        EXPECT_EQ(a.mtime, b.mtime);
        EXPECT_EQ(a.inode, b.inode);
        EXPECT_EQ(a.nlink, b.nlink);
        EXPECT_EQ(a.link_target, b.link_target);
        // The flags the analyzers key on: a deleted or superseded entry is
        // history, and a layer that could not tell would describe a machine
        // that no longer existed.
        EXPECT_EQ(a.deleted, b.deleted) << "entry " << i;
        EXPECT_EQ(a.superseded, b.superseded) << "entry " << i;
        EXPECT_EQ(a.version, b.version);
        EXPECT_EQ(a.extra, b.extra);
        EXPECT_EQ(in[i].host_path, back[i].host_path);
        EXPECT_EQ(in[i].written, back[i].written);
        EXPECT_EQ(in[i].truncated, back[i].truncated);
        EXPECT_EQ(in[i].digests.sha256, back[i].digests.sha256);
        EXPECT_EQ(in[i].diagnostics.size(), back[i].diagnostics.size());
    }
}

TEST(Yaml, ListingRoundTripSurvivesHostileNames) {
    // A path with a newline and a pipe in it round-trips: the writer quotes it
    // and the reader gets the bytes back, not an approximation.
    std::vector<EntryResult> in(1);
    in[0].meta.path = "weird|name\nwith newline\ttab";
    in[0].meta.kind = EntryKind::Regular;
    in[0].meta.link_target = "../../etc/passwd";
    in[0].meta.extra["note"] = "a: b\nc";
    std::string id;
    std::vector<EntryResult> back;
    ASSERT_TRUE(listing_from_yaml(listing_to_yaml("n1", in), id, back));
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].meta.path, in[0].meta.path);
    EXPECT_EQ(back[0].meta.link_target, in[0].meta.link_target);
    EXPECT_EQ(back[0].meta.extra, in[0].meta.extra);
}

TEST(Yaml, ListingFromYamlRefusesRubbish) {
    std::string id;
    std::vector<EntryResult> e;
    EXPECT_FALSE(listing_from_yaml("", id, e));
    EXPECT_FALSE(listing_from_yaml("not a map", id, e));
    EXPECT_FALSE(listing_from_yaml("entries: []", id, e)) << "no 'filesystem' key";
    EXPECT_FALSE(listing_from_yaml("filesystem: n1\nentries: [1,2]", id, e))
        << "an entry must be a map";
    EXPECT_FALSE(listing_from_yaml("filesystem: n1\nentries:\n  - written: true", id, e))
        << "an entry must have a 'file'";
    EXPECT_FALSE(listing_from_yaml("filesystem: n1\nentries:\n  - file:\n      kind: wat", id, e))
        << "an unknown kind is refused, not guessed";
    // A refused document leaves the outputs untouched.
    EXPECT_TRUE(id.empty());
    EXPECT_TRUE(e.empty());
}

TEST(Yaml, ListingEmptyRoundTrips) {
    std::string id;
    std::vector<EntryResult> e;
    ASSERT_TRUE(listing_from_yaml(listing_to_yaml("n000001", {}), id, e));
    EXPECT_EQ(id, "n000001");
    EXPECT_TRUE(e.empty());
}

// ------------------------------------------------- load_case_listings

namespace {

class CaseDir {
   public:
    CaseDir() {
        std::error_code ec;
        std::random_device rd;
        static int n = 0;
        std::filesystem::path base;
        if (const char* env = std::getenv("OMNITRACE_TEST_TMPDIR"))
            base = env;
        else
            base = std::filesystem::temp_directory_path();
        path_ = base / ("omnitrace-case-" + std::to_string(rd()) + "-" + std::to_string(n++));
        std::filesystem::remove_all(path_, ec);
        std::filesystem::create_directories(path_, ec);
    }
    ~CaseDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    CaseDir(const CaseDir&) = delete;
    CaseDir& operator=(const CaseDir&) = delete;
    const std::filesystem::path& path() const { return path_; }

    // One filesystem listing plus the file it describes.
    void add(const std::string& node, const std::string& entry_path, const std::string& content,
             const std::string& recorded_host_path) {
        const std::filesystem::path d = path_ / "filesystems" / node;
        std::filesystem::create_directories(d / "files", ec_);
        std::ofstream(d / "files" / entry_path, std::ios::binary) << content;
        std::vector<EntryResult> e(1);
        e[0].meta.path = entry_path;
        e[0].meta.kind = EntryKind::Regular;
        e[0].meta.size = content.size();
        e[0].host_path = recorded_host_path;
        e[0].written = true;
        std::ofstream(d / "listing.yaml", std::ios::binary) << listing_to_yaml(node, e);
    }
    void drop_files(const std::string& node) {
        std::filesystem::remove_all(path_ / "filesystems" / node / "files", ec_);
    }

   private:
    std::filesystem::path path_;
    std::error_code ec_;
};

std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

}  // namespace

TEST(Yaml, LoadCaseListingsPrefersTheFileBesideTheListing) {
    // A case is routinely *copied* rather than moved, and the copy's listings
    // still name the original's paths -- which exist. Trusting the recorded
    // host_path first reads the original's files while reporting on the copy,
    // silently, and the two can differ.
    CaseDir original;
    original.add("n1", "marker.txt", "ORIGINAL", "");
    CaseDir copy;
    copy.add("n1", "marker.txt", "COPY",
             (original.path() / "filesystems" / "n1" / "files" / "marker.txt").string());

    std::vector<std::pair<std::string, std::vector<EntryResult>>> out;
    std::vector<Diagnostic> diags;
    ASSERT_TRUE(load_case_listings(copy.path().string(), out, diags));
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0].second.size(), 1u);
    EXPECT_EQ(slurp(out[0].second[0].host_path), "COPY")
        << "the listing lives beside the files it describes";
    bool said = false;
    for (const Diagnostic& d : diags) said = said || d.code == "case-relocated";
    EXPECT_TRUE(said) << "a moved case says so rather than looking identical to one that has not";
}

TEST(Yaml, LoadCaseListingsNeverLeavesTheCaseDirectory) {
    // A case is self-contained. A host_path pointing outside it came from
    // another machine or another case, and following it produced records from
    // somebody else's files for a case whose own tree had been deleted.
    CaseDir elsewhere;
    elsewhere.add("n1", "marker.txt", "SOMEONE ELSE", "");
    CaseDir gutted;
    gutted.add("n1", "marker.txt", "MINE",
               (elsewhere.path() / "filesystems" / "n1" / "files" / "marker.txt").string());
    gutted.drop_files("n1");

    std::vector<std::pair<std::string, std::vector<EntryResult>>> out;
    std::vector<Diagnostic> diags;
    ASSERT_TRUE(load_case_listings(gutted.path().string(), out, diags));
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0].second.size(), 1u);
    // The metadata survives; the bytes are declared absent rather than
    // fetched from a path that is not this case.
    EXPECT_EQ(out[0].second[0].meta.path, "marker.txt");
    EXPECT_FALSE(out[0].second[0].written);
    EXPECT_TRUE(out[0].second[0].host_path.empty());
}

TEST(Yaml, LoadCaseListingsDoesNotMistakeASiblingForThisCase) {
    // The containment test is a path test, not a string test: a case directory
    // named `<case>-copy` sits next to `<case>` and has it as a prefix, and
    // reading the copy's files while reporting on the original is the same bug
    // by another route.
    CaseDir base;
    const std::filesystem::path sibling = base.path().string() + "-copy";
    std::error_code ec;
    std::filesystem::create_directories(sibling / "filesystems" / "n1" / "files", ec);
    std::ofstream(sibling / "filesystems" / "n1" / "files" / "marker.txt", std::ios::binary)
        << "SIBLING";
    base.add("n1", "marker.txt", "MINE",
             (sibling / "filesystems" / "n1" / "files" / "marker.txt").string());
    base.drop_files("n1");

    std::vector<std::pair<std::string, std::vector<EntryResult>>> out;
    std::vector<Diagnostic> diags;
    ASSERT_TRUE(load_case_listings(base.path().string(), out, diags));
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0].second.size(), 1u);
    EXPECT_TRUE(out[0].second[0].host_path.empty()) << "the sibling is a different case";
    std::filesystem::remove_all(sibling, ec);
}

TEST(Yaml, LoadCaseListingsIsOrderedAndSurvivesABadListing) {
    CaseDir c;
    c.add("n002", "b.txt", "b", "");
    c.add("n001", "a.txt", "a", "");
    // A listing that is not readable must not take the rest of the case down.
    const std::filesystem::path bad = c.path() / "filesystems" / "n003";
    std::error_code ec;
    std::filesystem::create_directories(bad, ec);
    std::ofstream(bad / "listing.yaml", std::ios::binary) << "entries: [oops";

    std::vector<std::pair<std::string, std::vector<EntryResult>>> out;
    std::vector<Diagnostic> diags;
    ASSERT_TRUE(load_case_listings(c.path().string(), out, diags));
    ASSERT_EQ(out.size(), 2u) << "the two good listings, the bad one skipped";
    EXPECT_EQ(out[0].first, "n001") << "sorted, so two runs over a case agree";
    EXPECT_EQ(out[1].first, "n002");
    bool said = false;
    for (const Diagnostic& d : diags) said = said || d.code == "case-listing-unreadable";
    EXPECT_TRUE(said) << "and it says which one it could not read";
}

TEST(Yaml, LoadCaseListingsRefusesSomethingThatIsNotACase) {
    std::vector<std::pair<std::string, std::vector<EntryResult>>> out;
    std::vector<Diagnostic> diags;
    EXPECT_FALSE(load_case_listings("/nonexistent/not/a/case", out, diags));
    // A directory with no listings at all is empty, not an error.
    const CaseDir empty;
    EXPECT_TRUE(load_case_listings(empty.path().string(), out, diags));
    EXPECT_TRUE(out.empty());
}

}  // namespace
}  // namespace omnitrace::output
