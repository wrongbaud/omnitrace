// hostile_strings_test.cpp — evidence strings that are not valid UTF-8 (a raw
// 0xB5 gzip name, a 0xFF path, embedded NULs) must never break the YAML or
// Markdown emitters, and what they emit must parse and round-trip.
#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

#include <string>

#include "fixture.h"
#include "omnitrace/core/Text.h"
#include "omnitrace/output/Markdown.h"
#include "omnitrace/output/Yaml.h"

namespace omnitrace::output {
namespace {

std::string bytes(std::initializer_list<int> v) {
    std::string s;
    for (const int b : v) s.push_back(static_cast<char>(b));
    return s;
}

// The fixture with hostile bytes injected into every string field a reader or
// the CLI can populate from evidence.
Manifest hostile_manifest() {
    Manifest m = test::full_manifest();
    const std::string b5 = bytes({0xB5});
    const std::string nul = std::string("\0", 1);
    const std::string overlong = bytes({0xC0, 0x80});
    const std::string surrogate = bytes({0xED, 0xA0, 0x80});
    m.run.host_os = "linux" + b5;
    m.run.argv.push_back("--label=" + b5 + nul);
    m.evidence[0].path = "/cases/" + b5 + "/dump.bin";
    m.evidence[0].note = "note" + nul + "after";
    m.coverage[1].detail = "detail " + overlong;
    m.tools[0].argv.push_back(surrogate);
    m.diagnostics.push_back({Severity::Warning, "run-" + b5, "message " + b5 + nul});
    Node* cont = m.find("n000007");
    cont->name = "orig" + b5 + "name" + nul + ".gz";  // the gzip original-name case
    cont->attrs["original_name"] = "orig" + b5 + "name";
    cont->attrs["key" + b5] = "v";
    cont->attrs[b5 + nul] = b5;
    cont->evidence = "header " + b5;
    cont->format = "gzip";
    Node* file = m.find("n000004");
    file->file->path = "etc/" + b5 + "/passwd" + nul;
    file->file->link_target = "target" + bytes({0xFF});
    file->file->extra["xattr" + b5] = "value" + surrogate;
    Node* link = m.find("n000005");
    link->file->link_target = bytes({0xF4, 0x90, 0x80, 0x80});  // > U+10FFFF
    return m;
}

TEST(HostileStrings, ManifestYamlIsCleanAndRoundTrips) {
    const Manifest m = hostile_manifest();
    const std::string y = manifest_to_yaml(m);
    EXPECT_TRUE(is_clean_utf8(y));
    EXPECT_EQ(y.find(bytes({0xB5})), std::string::npos);
    EXPECT_EQ(y.find(std::string("\0", 1)), std::string::npos);
    EXPECT_NE(y.find("\\xb5"), std::string::npos);
    EXPECT_NE(y.find("\\x00"), std::string::npos);

    Manifest back;
    const Status st = manifest_from_yaml(y, back);
    ASSERT_TRUE(st.ok) << st.error;
    // The escaped forms survive as ordinary text on the other side ...
    const Node* cont = back.find("n000007");
    ASSERT_NE(cont, nullptr);
    EXPECT_EQ(cont->name, "orig\\xb5name\\x00.gz");
    EXPECT_EQ(cont->attrs.at("original_name"), "orig\\xb5name");
    EXPECT_EQ(cont->attrs.at("key\\xb5"), "v");
    EXPECT_EQ(cont->attrs.at("\\xb5\\x00"), "\\xb5");
    EXPECT_EQ(cont->evidence, "header \\xb5");
    const Node* file = back.find("n000004");
    ASSERT_NE(file, nullptr);
    ASSERT_TRUE(file->file.has_value());
    EXPECT_EQ(file->file->path, "etc/\\xb5/passwd\\x00");
    EXPECT_EQ(file->file->link_target, "target\\xff");
    EXPECT_EQ(file->file->extra.at("xattr\\xb5"), "value\\xed\\xa0\\x80");
    EXPECT_EQ(back.find("n000005")->file->link_target, "\\xf4\\x90\\x80\\x80");
    EXPECT_EQ(back.run.host_os, "linux\\xb5");
    EXPECT_EQ(back.run.argv.back(), "--label=\\xb5\\x00");
    EXPECT_EQ(back.evidence[0].path, "/cases/\\xb5/dump.bin");
    EXPECT_EQ(back.evidence[0].note, "note\\x00after");
    EXPECT_EQ(back.coverage[1].detail, "detail \\xc0\\x80");
    EXPECT_EQ(back.tools[0].argv.back(), "\\xed\\xa0\\x80");
    EXPECT_EQ(back.diagnostics.back().code, "run-\\xb5");
    EXPECT_EQ(back.diagnostics.back().message, "message \\xb5\\x00");
    // ... and re-emitting is a fixed point (sanitizing is idempotent).
    EXPECT_EQ(manifest_to_yaml(back), y);
    // Same hostile input, same bytes.
    EXPECT_EQ(manifest_to_yaml(hostile_manifest()), y);
}

TEST(HostileStrings, ListingYamlWithRawPathBytes) {
    std::vector<EntryResult> entries = test::sample_entries();
    entries[0].meta.path = "usr/" + bytes({0xFF}) + "/lib" + std::string("\0", 1);
    entries[0].meta.link_target = bytes({0xB5});
    entries[0].meta.extra[bytes({0xFF})] = bytes({0xFE});
    entries[0].host_path = "case/" + bytes({0xFF});
    entries[1].diagnostics[0].message = "stopped " + bytes({0xB5});
    const std::string y = listing_to_yaml("n" + bytes({0xB5}), entries);
    EXPECT_TRUE(is_clean_utf8(y));
    EXPECT_NE(y.find("\\xff"), std::string::npos);
    YAML::Node root;
    ASSERT_NO_THROW(root = YAML::Load(y));
    EXPECT_EQ(root["filesystem"].Scalar(), "n\\xb5");
    const YAML::Node first = root["entries"][0];
    EXPECT_EQ(first["file"]["path"].Scalar(), "usr/\\xff/lib\\x00");
    EXPECT_EQ(first["file"]["link_target"].Scalar(), "\\xb5");
    EXPECT_EQ(first["file"]["extra"]["\\xff"].Scalar(), "\\xfe");
    EXPECT_EQ(first["host_path"].Scalar(), "case/\\xff");
    EXPECT_EQ(root["entries"][1]["diagnostics"][0]["message"].Scalar(), "stopped \\xb5");
}

TEST(HostileStrings, MarkdownIsCleanAndShowsEscapes) {
    const Manifest m = hostile_manifest();
    const std::string summary = summary_markdown(m);
    const std::string parts = partitions_markdown(m);
    for (const std::string& md : {summary, parts}) {
        EXPECT_TRUE(is_clean_utf8(md));
        EXPECT_EQ(md.find(bytes({0xB5})), std::string::npos);
        EXPECT_EQ(md.find(std::string("\0", 1)), std::string::npos);
        EXPECT_NE(md.find("\\xb5"), std::string::npos);
    }
    // Sanitized text still goes through md_escape: the escape's own backslash
    // is doubled so the rendered document shows a literal "\xb5".
    EXPECT_NE(summary.find("\"orig\\\\xb5name\\\\x00.gz\""), std::string::npos);
    EXPECT_NE(summary.find("| warning | run-\\\\xb5 | message \\\\xb5\\\\x00 |"),
              std::string::npos);
    EXPECT_NE(summary.find("/cases/\\\\xb5/dump.bin"), std::string::npos);
    EXPECT_NE(summary.find("detail \\\\xc0\\\\x80"), std::string::npos);
    EXPECT_NE(parts.find("`n000007` orig\\\\xb5name\\\\x00.gz"), std::string::npos);

    std::vector<EntryResult> entries = test::sample_entries();
    entries[2].meta.path = "bin/" + bytes({0xB5});
    entries[2].meta.link_target = bytes({0xFF}) + "|busybox";
    entries[2].digests.sha256 = bytes({0xB5}) + std::string(63, 'x');
    const std::string listing = listing_markdown("n" + bytes({0xB5}), entries);
    EXPECT_TRUE(is_clean_utf8(listing));
    EXPECT_NE(listing.find("# Listing for `n\\\\xb5`"), std::string::npos);
    EXPECT_NE(listing.find("| bin/\\\\xb5 -> \\\\xff\\|busybox | symlink |"), std::string::npos);
    EXPECT_NE(listing.find("| \\\\xb5xxxxxxxxxxx |"), std::string::npos);
    EXPECT_EQ(listing_markdown("n" + bytes({0xB5}), entries), listing);
}

}  // namespace
}  // namespace omnitrace::output
