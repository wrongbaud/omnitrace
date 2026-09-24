// artifacts_yaml_test.cpp — reading artifacts.yaml back into a SweepResult.
//
// `omnitrace report <case>` rebuilds six of its seven sections by re-running
// the post-analysis layers over recovered entries. The seventh cannot work
// that way: a sweep needs the image, and re-reading a 16 GiB dump to re-find
// hits the case already lists is work for no gain. So the hits are read back
// instead, and these tests are what make that trustworthy -- a reader that
// quietly returned fewer hits than the file claims would make a report
// understate what an examiner found.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "omnitrace/rules/Sweep.h"

using namespace omnitrace;
using namespace omnitrace::rules;

// `Severity` names two different enums in these two namespaces -- the run's
// (info/warning/error) and a rule's (info..critical) -- so both are qualified
// throughout rather than relying on which `using` wins.

namespace {

ArtifactHit hit(const std::string& pack, const std::string& rule, rules::Severity sev,
                const std::string& node, const std::string& path, std::uint64_t off,
                const std::string& match) {
    ArtifactHit a;
    a.hit.pack = pack;
    a.hit.rule = rule;
    a.hit.category = "network";
    a.hit.severity = sev;
    a.hit.offset = off;
    a.hit.match = match;
    a.hit.context = "..." + match + "...";
    a.node = node;
    a.path = path;
    return a;
}

SweepResult sample() {
    SweepResult r;
    r.files_scanned = 104536;
    r.regions_scanned = 16;
    r.regions_skipped = 4;
    r.bytes_scanned = 9415217556ull;
    r.truncated = false;
    r.diagnostics.push_back({omnitrace::Severity::Warning, "rules-file-unreadable",
                             "'etc/shadow' could not be read"});
    r.hits.push_back(hit("net", "mac-address", rules::Severity::Low, "n000042", "etc/network.conf", 128,
                         "00:1a:2b:3c:4d:5e"));
    r.hits.push_back(hit("creds", "private-key", rules::Severity::Critical, "n000043", "etc/ssl/key.pem",
                         0, "-----BEGIN RSA PRIVATE KEY-----"));
    r.hits.push_back(hit("net", "mac-address", rules::Severity::Low, "n000099", "", 4096, "de:ad:be:ef"));
    return r;
}

}  // namespace

// The round trip has to carry the fields the report section reads: the
// summary counters, which cannot be recounted from the hits, and each hit's
// rule, pack and severity, which is what the section groups by.
TEST(ArtifactsYaml, RoundTripsEverythingTheReportReads) {
    const SweepResult in = sample();
    Manifest m;
    const std::string text = artifacts_to_yaml(m, in);

    SweepResult out;
    const Status st = artifacts_from_yaml(text, out);
    ASSERT_TRUE(st) << st.error;

    EXPECT_EQ(out.files_scanned, in.files_scanned);
    EXPECT_EQ(out.regions_scanned, in.regions_scanned);
    EXPECT_EQ(out.regions_skipped, in.regions_skipped);
    EXPECT_EQ(out.bytes_scanned, in.bytes_scanned);
    EXPECT_EQ(out.truncated, in.truncated);
    ASSERT_EQ(out.hits.size(), in.hits.size());
    ASSERT_EQ(out.diagnostics.size(), in.diagnostics.size());
    EXPECT_EQ(out.diagnostics[0].code, "rules-file-unreadable");
    EXPECT_EQ(out.diagnostics[0].severity, omnitrace::Severity::Warning);

    for (std::size_t i = 0; i < in.hits.size(); ++i) {
        const ArtifactHit& a = in.hits[i];
        const ArtifactHit& b = out.hits[i];
        EXPECT_EQ(b.hit.rule, a.hit.rule) << "hit " << i;
        EXPECT_EQ(b.hit.pack, a.hit.pack) << "hit " << i;
        EXPECT_EQ(b.hit.category, a.hit.category) << "hit " << i;
        EXPECT_EQ(b.hit.severity, a.hit.severity) << "hit " << i;
        EXPECT_EQ(b.hit.offset, a.hit.offset) << "hit " << i;
        EXPECT_EQ(b.hit.match, a.hit.match) << "hit " << i;
        EXPECT_EQ(b.node, a.node) << "hit " << i;
        EXPECT_EQ(b.path, a.path) << "hit " << i;
    }
}

// Writing it again from what was read has to produce the same document, which
// is the check that no field is being dropped on the way through.
TEST(ArtifactsYaml, WhatIsReadBackWritesTheSameDocument) {
    Manifest m;
    const std::string once = artifacts_to_yaml(m, sample());
    SweepResult out;
    ASSERT_TRUE(artifacts_from_yaml(once, out));
    EXPECT_EQ(artifacts_to_yaml(m, out), once);
}

// The guard this exists for. A file cut short while being written parses
// cleanly and yields fewer hits than its summary claims; reporting the smaller
// number as a finding is the most misleading thing this could do.
TEST(ArtifactsYaml, ATruncatedDocumentIsRefusedRatherThanUndercounted) {
    Manifest m;
    const std::string full = artifacts_to_yaml(m, sample());
    const std::size_t cut = full.find("  - rule: private-key");
    ASSERT_NE(cut, std::string::npos);
    const std::string truncated = full.substr(0, cut);

    SweepResult out;
    out.hits.push_back(hit("x", "y", rules::Severity::Info, "n1", "p", 0, "m"));
    const Status st = artifacts_from_yaml(truncated, out);
    EXPECT_FALSE(st.ok);
    EXPECT_NE(st.error.find("summary claims 3"), std::string::npos) << st.error;
    EXPECT_NE(st.error.find("holds 1"), std::string::npos) << st.error;
    EXPECT_EQ(out.hits.size(), 1u) << "out must be untouched on failure";
}

TEST(ArtifactsYaml, RefusesAForeignOrMissingSchema) {
    SweepResult out;
    EXPECT_FALSE(artifacts_from_yaml("schema: omnitrace-artifacts/2\nsummary:\n  hits: 0\n", out));
    EXPECT_FALSE(artifacts_from_yaml("summary:\n  hits: 0\n", out));
    EXPECT_FALSE(artifacts_from_yaml("- not\n- a map\n", out));
    EXPECT_FALSE(artifacts_from_yaml("schema: [", out)) << "a yaml error must not throw";
}

// A severity or a count this cannot name is an error, never a default: every
// default here is a number or a label a report would go on to print as fact.
TEST(ArtifactsYaml, RefusesAFieldItCannotParseRatherThanDefaultingIt) {
    const std::string base = "schema: " + std::string(kArtifactsSchema) + "\n";
    SweepResult out;
    EXPECT_FALSE(artifacts_from_yaml(base + "summary:\n  hits: 1\nhits:\n  - rule: r\n"
                                            "    severity: urgent\n",
                                     out));
    EXPECT_FALSE(artifacts_from_yaml(base + "summary:\n  hits: 0\n  files_scanned: lots\n", out));
    EXPECT_FALSE(artifacts_from_yaml(base + "summary:\n  hits: 0\ndiagnostics:\n"
                                            "  - severity: loud\n    code: c\n",
                                     out));
}

// An empty sweep is a real result, not a missing one.
TEST(ArtifactsYaml, AnEmptySweepRoundTrips) {
    Manifest m;
    SweepResult empty;
    empty.files_scanned = 12;
    SweepResult out;
    const Status st = artifacts_from_yaml(artifacts_to_yaml(m, empty), out);
    ASSERT_TRUE(st) << st.error;
    EXPECT_TRUE(out.hits.empty());
    EXPECT_EQ(out.files_scanned, 12u);
}
