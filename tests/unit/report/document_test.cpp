// document_test.cpp — the report document model and its renderers.
//
// Escaping gets the most attention here, and it is not a style concern: a
// report puts a device's own bytes into markup. A partition named
// `<script>alert(1)</script>`, a certificate subject containing a pipe, a
// banner with a newline in it -- all of those are attacker-controlled, and the
// previous generation of this built markup by string concatenation.
#include <gtest/gtest.h>

#include <string>

#include "omnitrace/report/Document.h"

using namespace omnitrace;
using namespace omnitrace::report;

namespace {

Document tiny(const std::string& title, Block b) {
    Document d;
    d.meta.title = title;
    Section s;
    s.title = "Section";
    s.blocks.push_back(std::move(b));
    d.sections.push_back(std::move(s));
    return d;
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

}  // namespace

TEST(ReportEscaping, MarkupInEvidenceCannotBecomeMarkup) {
    const std::string nasty = "<script>alert('x')</script> & \"quoted\"";
    const Document d = tiny(nasty, Paragraph{nasty});
    const std::string html = to_html(d);

    EXPECT_FALSE(contains(html, "<script>")) << "a device's own name must not become a tag";
    EXPECT_TRUE(contains(html, "&lt;script&gt;"));
    EXPECT_TRUE(contains(html, "&amp;"));
    EXPECT_TRUE(contains(html, "&quot;"));
    EXPECT_TRUE(contains(html, "&#39;"));
    // The title reaches <title> and the body; both are escaped.
    EXPECT_EQ(html.find("<script>"), std::string::npos);
}

TEST(ReportEscaping, APipeCannotBreakAMarkdownTable) {
    Table t;
    t.headers = {"Subject", "Issuer"};
    // A real certificate subject is comma-separated and can hold anything.
    t.rows.push_back({"CN=a|b,O=evil\\corp", "line one\nline two"});
    const std::string md = to_markdown(tiny("t", t));

    EXPECT_TRUE(contains(md, "a\\|b")) << "an unescaped pipe would add a column";
    EXPECT_TRUE(contains(md, "evil\\\\corp"));
    EXPECT_FALSE(contains(md, "line one\nline two")) << "a newline would end the row";
    EXPECT_TRUE(contains(md, "<br>"));

    // Every row still has the same number of cells as the header.
    std::size_t bars = 0;
    for (const char c : md)
        if (c == '|') ++bars;
    EXPECT_GT(bars, 0u);
}

TEST(ReportTables, RaggedRowsAreSquaredNotEmitted) {
    // A builder that appends a short row must not produce broken markup.
    Table t;
    t.headers = {"A", "B", "C"};
    t.rows.push_back({"1"});
    t.rows.push_back({"1", "2", "3", "4 - dropped"});
    const std::string html = to_html(tiny("t", t));

    // Three cells per row, always.
    std::size_t tds = 0;
    for (std::size_t i = html.find("<td>"); i != std::string::npos; i = html.find("<td>", i + 1))
        ++tds;
    EXPECT_EQ(tds, 6u) << "two rows of exactly three cells";
    EXPECT_FALSE(contains(html, "dropped")) << "an over-long row is cut to the header width";

    const std::string md = to_markdown(tiny("t", t));
    EXPECT_FALSE(contains(md, "dropped"));
}

TEST(ReportRendering, TheSameDocumentRendersIdenticallyEveryTime) {
    // Two reports of the same evidence have to be comparable, so nothing may
    // depend on a clock, a hash order or an address.
    Document d;
    d.meta.title = "Case";
    d.meta.fields = {{"Tool", "omnitrace"}, {"Evidence", "a.bin"}};
    Section s;
    s.title = "One";
    s.blocks.push_back(Paragraph{"text"});
    s.blocks.push_back(KeyValues{"caption", {{"k", "v"}, {"k2", "v2"}}});
    s.blocks.push_back(Callout{Tone::Warn, "Careful", "something"});
    s.blocks.push_back(CodeBlock{"", "0x00"});
    s.blocks.push_back(BulletList{{"a", "b"}});
    Section sub;
    sub.title = "Two";
    sub.blocks.push_back(Paragraph{"nested"});
    s.subsections.push_back(std::move(sub));
    d.sections.push_back(std::move(s));

    EXPECT_EQ(to_html(d), to_html(d));
    EXPECT_EQ(to_markdown(d), to_markdown(d));
}

TEST(ReportRendering, TheHtmlIsSelfContained) {
    // A report is handed to someone else. A page that fetches a stylesheet or
    // a font shows a broken document offline, and one that phones out when
    // opened is worse than ugly.
    const std::string html = to_html(tiny("t", Paragraph{"x"}));
    EXPECT_FALSE(contains(html, "http://"));
    EXPECT_FALSE(contains(html, "https://"));
    EXPECT_FALSE(contains(html, "<script"));
    EXPECT_FALSE(contains(html, "@import"));
    EXPECT_FALSE(contains(html, "<link"));
    EXPECT_TRUE(contains(html, "<style>")) << "the CSS is inline";
    EXPECT_TRUE(contains(html, "@media print")) << "and it prints";
}

TEST(ReportRendering, SectionsGetStableAnchorsAndAContentsList) {
    Document d;
    d.meta.title = "t";
    Section a;
    a.title = "Coverage and limits";
    Section b;
    b.title = "!!!";  // nothing usable in it
    d.sections.push_back(std::move(a));
    d.sections.push_back(std::move(b));
    const std::string html = to_html(d);

    EXPECT_TRUE(contains(html, "id=\"coverage-and-limits\""));
    EXPECT_TRUE(contains(html, "href=\"#coverage-and-limits\""));
    EXPECT_TRUE(contains(html, "id=\"section-1\"")) << "a title with no letters still gets an id";
}

TEST(ReportRendering, AnEmptyDocumentIsValidAndSaysNothing) {
    const Document d;
    const std::string html = to_html(d);
    EXPECT_TRUE(contains(html, "<!DOCTYPE html>"));
    EXPECT_TRUE(contains(html, "</html>"));
    EXPECT_FALSE(contains(html, "<nav")) << "no contents list for no sections";
    EXPECT_FALSE(to_markdown(d).empty());
}

TEST(ReportIntegrity, AMissingFileIsReportedNotIgnored) {
    const std::vector<EvidenceRef> refs = {
        {"e1", "/nonexistent/path/to/evidence.bin", std::string(64, 'a'), 10}};
    const IntegrityResult r = verify_evidence(refs);
    EXPECT_FALSE(r.verified);
    ASSERT_EQ(r.states.size(), 1u);
    EXPECT_EQ(r.states[0].second, "missing");
    ASSERT_FALSE(r.diagnostics.empty());
    EXPECT_EQ(r.diagnostics[0].code, "report-evidence-missing");
}

TEST(ReportIntegrity, NoRecordedHashIsNotAPass) {
    // An older case, or one made with hashing off. Not a failure, but not a
    // verification either, and the difference matters.
    const std::vector<EvidenceRef> refs = {{"e1", "/dev/null", "", 0}};
    const IntegrityResult r = verify_evidence(refs);
    EXPECT_FALSE(r.verified);
    EXPECT_EQ(r.states[0].second, "no recorded hash");
    EXPECT_EQ(r.diagnostics[0].code, "report-evidence-unhashed");
}

TEST(ReportIntegrity, NoEvidenceAtAllIsNotVerified) {
    const IntegrityResult r = verify_evidence({});
    EXPECT_FALSE(r.verified) << "nothing checked is not the same as everything passing";
    EXPECT_TRUE(r.states.empty());
}
