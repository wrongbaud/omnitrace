// diff_test.cpp — comparing two cases.
//
// Entries are built by hand rather than read off disk, so a test says exactly
// what each case held. The cases here deliberately use *different node ids for
// the same filesystem*, because that is what happens in the field and is the
// thing the comparison must not depend on.
#include "omnitrace/diff/Diff.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace omnitrace;
using namespace omnitrace::diff;

namespace {

EntryResult file(const std::string& path, const std::string& sha, std::uint64_t size = 10) {
    EntryResult e;
    e.meta.path = path;
    e.meta.kind = EntryKind::Regular;
    e.meta.size = size;
    e.digests.sha256 = sha;
    e.digests.bytes = size;
    e.written = true;
    return e;
}
EntryResult deleted(const std::string& path, const std::string& sha) {
    EntryResult e = file(path, sha);
    e.meta.deleted = true;
    return e;
}
EntryResult dir(const std::string& path) {
    EntryResult e;
    e.meta.path = path;
    e.meta.kind = EntryKind::Directory;
    return e;
}

std::string sha(char c) {
    return std::string(64, c);
}

analyzers::Survey survey_with(const std::vector<std::pair<std::string, std::string>>& facts,
                              const std::string& node = "n1") {
    analyzers::Survey s;
    analyzers::Report r;
    r.node = node;
    r.platform = analyzers::Platform::Linux;
    for (const auto& [k, v] : facts) r.facts.push_back({k, v, "etc/os-release"});
    s.reports.push_back(std::move(r));
    return s;
}

const FileChange* change_for(const std::vector<FileChange>& v, const std::string& path) {
    for (const FileChange& c : v)
        if (c.path == path) return &c;
    return nullptr;
}

}  // namespace

// The comparison is by path and by content, and never by node id: ids are
// assigned in discovery order, so the same filesystem is n000018 in one case
// and n000021 in the other as soon as anything earlier in the image differs.
TEST(Diff, MatchesFilesAcrossCasesWithDifferentNodeIds) {
    const analyzers::FilesystemEntries a = {
        {"n000018", {file("etc/passwd", sha('a')), file("bin/busybox", sha('b')),
                     file("etc/only-in-a", sha('c'))}}};
    const analyzers::FilesystemEntries b = {
        {"n000021", {file("etc/passwd", sha('a')), file("bin/busybox", sha('d')),
                     file("etc/only-in-b", sha('e'))}}};

    const CaseDiff d = compare(a, b, {}, {}, {}, {});
    EXPECT_EQ(d.files.files_a, 3u);
    EXPECT_EQ(d.files.files_b, 3u);
    EXPECT_EQ(d.files.same, 1u) << "etc/passwd, same path and same bytes";
    EXPECT_EQ(d.files.changed_total, 1u);
    EXPECT_EQ(d.files.removed_total, 1u);
    EXPECT_EQ(d.files.added_total, 1u);
    EXPECT_FALSE(d.identical());

    const FileChange* c = change_for(d.files.changed, "bin/busybox");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->sha_a, sha('b'));
    EXPECT_EQ(c->sha_b, sha('d'));
    EXPECT_EQ(c->node_a, "n000018");
    EXPECT_EQ(c->node_b, "n000021") << "the node is reported, never matched on";
}

// A file that moved is one removal and one addition by path, and neither by
// content. The gap between the two views is the interesting part.
TEST(Diff, ContentViewSeesAFileThatOnlyMoved) {
    const analyzers::FilesystemEntries a = {{"n1", {file("usr/bin/tool", sha('a'))}}};
    const analyzers::FilesystemEntries b = {{"n9", {file("bin/tool", sha('a'))}}};

    const CaseDiff d = compare(a, b, {}, {}, {}, {});
    EXPECT_EQ(d.files.removed_total, 1u) << "by path it is gone";
    EXPECT_EQ(d.files.added_total, 1u) << "and new";
    EXPECT_EQ(d.files.contents_common, 1u) << "by content it is the same file";
    EXPECT_EQ(d.files.moved, 1u);
    EXPECT_EQ(d.files.same, 0u);
}

TEST(Diff, TwoCopiesOfACaseAreIdentical) {
    const analyzers::FilesystemEntries a = {
        {"n1", {dir("etc"), file("etc/passwd", sha('a')), file("bin/sh", sha('b'))}}};
    const analyzers::FilesystemEntries b = {
        {"n7", {dir("etc"), file("etc/passwd", sha('a')), file("bin/sh", sha('b'))}}};
    const CaseDiff d = compare(a, b, survey_with({{"os.id", "openwrt"}}),
                               survey_with({{"os.id", "openwrt"}}, "n7"), {}, {});
    EXPECT_TRUE(d.identical());
    EXPECT_EQ(d.files.same, 2u);
    EXPECT_TRUE(d.platform.empty()) << "the same fact from a different node is the same fact";
}

// History is not the system as it was running. A deleted file recovered from
// one case and not the other says something about recovery, not the device.
TEST(Diff, DeletedAndSupersededEntriesAreNotCompared) {
    analyzers::FilesystemEntries a = {{"n1", {file("etc/passwd", sha('a')),
                                              deleted("etc/shadow.old", sha('z'))}}};
    const analyzers::FilesystemEntries b = {{"n1", {file("etc/passwd", sha('a'))}}};
    const CaseDiff d = compare(a, b, {}, {}, {}, {});
    EXPECT_TRUE(d.identical());
    EXPECT_EQ(d.files.files_a, 1u) << "the deleted entry is not a file of the running system";
}

// The facts are keyed on their own name across every filesystem, because the
// reports carrying them are identified by node id.
TEST(Diff, ReportsPlatformFactsThatDisagree) {
    const analyzers::FilesystemEntries e = {{"n1", {file("etc/passwd", sha('a'))}}};
    const CaseDiff d = compare(
        e, e, survey_with({{"os.version", "18.06.1"}, {"os.id", "openwrt"}}),
        survey_with({{"os.version", "21.02.0"}, {"os.id", "openwrt"}, {"service.telnet", "y"}},
                    "n5"),
        {}, {});
    ASSERT_EQ(d.platform.size(), 2u) << "os.id agrees and is not reported";
    EXPECT_EQ(d.platform[0].key, "os.version");
    EXPECT_EQ(d.platform[0].a, "18.06.1");
    EXPECT_EQ(d.platform[0].b, "21.02.0");
    EXPECT_EQ(d.platform[1].key, "service.telnet");
    EXPECT_EQ(d.platform[1].a, "") << "absent on one side";
    EXPECT_EQ(d.platform[1].b, "y");
    EXPECT_FALSE(d.identical());
}

// Addresses move whenever anything is recompiled, so the comparison is by
// name: a name appearing or disappearing is what says a driver changed.
TEST(Diff, ComparesKernelSymbolsByNameNotAddress) {
    const analyzers::FilesystemEntries e = {{"n1", {file("etc/passwd", sha('a'))}}};
    const std::string sa = "c0100000 T _stext\nc0100010 t shared_fn\nc0100020 T only_in_a\n";
    // Every address differs; two of the three names do not.
    const std::string sb = "c0200000 T _stext\nc0200040 t shared_fn\nc0200080 T only_in_b\n";
    const CaseDiff d = compare(e, e, {}, {}, sa, sb, {});
    EXPECT_TRUE(d.symbols.present_a);
    EXPECT_TRUE(d.symbols.present_b);
    EXPECT_EQ(d.symbols.symbols_a, 3u);
    EXPECT_EQ(d.symbols.common, 2u) << "recompiling moves every address";
    ASSERT_EQ(d.symbols.only_a.size(), 1u);
    EXPECT_EQ(d.symbols.only_a[0], "only_in_a");
    ASSERT_EQ(d.symbols.only_b.size(), 1u);
    EXPECT_EQ(d.symbols.only_b[0], "only_in_b");
    EXPECT_FALSE(d.identical());
}

// With nothing to compare against, "14,589 symbols only in A" is every symbol
// A has. The count stays and the names go, or an absence reads as a finding.
TEST(Diff, OneSidedSymbolTablesAreCountedNotListed) {
    const analyzers::FilesystemEntries e = {{"n1", {file("etc/passwd", sha('a'))}}};
    const std::string sa = "c0100000 T _stext\nc0100010 t a_fn\n";
    const CaseDiff d = compare(e, e, {}, {}, sa, {}, {});
    EXPECT_TRUE(d.symbols.present_a);
    EXPECT_FALSE(d.symbols.present_b);
    EXPECT_EQ(d.symbols.only_a_total, 2u) << "counted";
    EXPECT_TRUE(d.symbols.only_a.empty()) << "not listed";
    bool said = false;
    for (const Diagnostic& g : d.diagnostics)
        if (g.code == "diff-symbols-one-sided") said = true;
    EXPECT_TRUE(said);
}

// nm leaves the address column blank when it does not know one; the name is
// still the last field.
TEST(Diff, ReadsSymbolLinesWithNoAddress) {
    const analyzers::FilesystemEntries e = {{"n1", {file("etc/passwd", sha('a'))}}};
    const CaseDiff d = compare(e, e, {}, {}, "         T with_no_address\n",
                               "c0100000 T with_no_address\n", {});
    EXPECT_EQ(d.symbols.common, 1u);
    EXPECT_EQ(d.symbols.only_a_total, 0u);
}

// A totals-versus-listed mistake is how a diff comes to understate what it
// found, so the totals are taken before the lists are capped.
TEST(Diff, TotalsAreExactWhenTheListsAreCapped) {
    std::vector<EntryResult> many;
    for (int i = 0; i < 50; ++i)
        many.push_back(file("f" + std::to_string(i), std::string(64, 'a' + (i % 20))));
    const analyzers::FilesystemEntries a = {{"n1", many}};
    const analyzers::FilesystemEntries b = {{"n1", {file("kept", sha('z'))}}};

    DiffLimits lim;
    lim.max_listed = 5;
    const CaseDiff d = compare(a, b, {}, {}, {}, {}, lim);
    EXPECT_EQ(d.files.removed_total, 50u) << "exact";
    EXPECT_EQ(d.files.removed.size(), 5u) << "listed";
    EXPECT_EQ(d.files.added_total, 1u);
}

// A case analysed with --no-extract has no files, and a diff that then reports
// "everything was removed" is describing the run rather than the device.
TEST(Diff, SaysSoWhenOneCaseHasNoFilesAtAll) {
    const analyzers::FilesystemEntries a = {{"n1", {file("etc/passwd", sha('a'))}}};
    const analyzers::FilesystemEntries b = {{"n1", {dir("etc")}}};
    const CaseDiff d = compare(a, b, {}, {}, {}, {});
    bool said = false;
    for (const Diagnostic& g : d.diagnostics)
        if (g.code == "diff-case-empty") said = true;
    EXPECT_TRUE(said);
}

TEST(Diff, RendersBothFormsWithoutLosingTheTotals) {
    const analyzers::FilesystemEntries a = {{"n1", {file("a", sha('a')), file("both", sha('c'))}}};
    const analyzers::FilesystemEntries b = {{"n2", {file("b", sha('b')), file("both", sha('c'))}}};
    CaseDiff d = compare(a, b, {}, {}, {}, {});
    d.label_a = "case-a";
    d.label_b = "case-b";

    const std::string md = to_markdown(d);
    EXPECT_NE(md.find("case-a"), std::string::npos);
    EXPECT_NE(md.find("Only in A"), std::string::npos);
    const std::string yaml = to_yaml(d);
    EXPECT_NE(yaml.find("schema: omnitrace-diff/1"), std::string::npos);
    EXPECT_NE(yaml.find("identical: false"), std::string::npos);
    EXPECT_NE(yaml.find("only_a: 1"), std::string::npos);
    EXPECT_NE(yaml.find("same: 1"), std::string::npos);
}

// A device's own bytes reach the markup here too: a path is attacker
// controlled and a pipe in one would otherwise break the table.
TEST(Diff, EscapesPathsForTheFormatTheyAreRenderedIn) {
    const analyzers::FilesystemEntries a = {{"n1", {file("etc/we|rd\"name", sha('a'))}}};
    const analyzers::FilesystemEntries b = {{"n1", {file("plain", sha('b'))}}};
    const CaseDiff d = compare(a, b, {}, {}, {}, {});
    const std::string md = to_markdown(d);
    EXPECT_EQ(md.find("etc/we|rd"), std::string::npos) << "a raw pipe would break the row";
    EXPECT_NE(md.find("we\\|rd"), std::string::npos);
    const std::string yaml = to_yaml(d);
    EXPECT_NE(yaml.find("we|rd\\\""), std::string::npos) << "quoted for YAML instead";
}
