// yaml_test.cpp — manifest/listing YAML: round trip, determinism, tolerance
// of missing keys, and precise failures on hostile input.
#include "omnitrace/output/Yaml.h"

#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

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

}  // namespace
}  // namespace omnitrace::output
