// Render.cpp — HTML and Markdown renderers. See Document.h.
//
// The CSS is omnisonde's brass palette, inlined. Inlined rather than linked
// because a report is handed to someone else: a page that fetches a stylesheet
// or a font shows a broken document on a machine with no network, and a
// forensic report that phones out when opened is worse than ugly. The fonts
// degrade to the platform's own.
#include <algorithm>

#include "omnitrace/report/Document.h"

namespace omnitrace::report {

namespace {

// omnisonde's tokens, verbatim, so two reports from the same shop look like
// they came from the same shop.
constexpr const char* kCss = R"CSS(
:root{
  --bg-void:#08060a; --bg-plate:#0f0c10; --bg-panel:#16121a; --bg-raised:#1e1824;
  --border-base:#2a2435; --border-bright:#3a3248;
  --text-primary:#d8cfc0; --text-secondary:#8a8098; --text-dim:#5a5268; --text-bright:#f0ece4;
  --brass:#c8a24e; --brass-dim:#8a7030; --brass-glow:rgba(200,162,78,.15);
  --crimson:#a83232; --phosphor:#30e878; --danger:#e04848;
  --font-body:'Rajdhani',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;padding:0;background:var(--bg-void);color:var(--text-primary);
  font-family:var(--font-body);font-size:16px;line-height:1.6}
.wrap{max-width:1100px;margin:0 auto;padding:48px 32px 96px}
header.doc{border-bottom:2px solid var(--brass);padding-bottom:24px;margin-bottom:8px}
header.doc h1{margin:0 0 6px;font-size:2.3rem;font-weight:700;letter-spacing:.02em;
  color:var(--text-bright)}
header.doc .subtitle{margin:0 0 18px;color:var(--text-secondary);font-size:1.05rem}
.metagrid{display:grid;grid-template-columns:auto 1fr;gap:4px 18px;font-size:.92rem}
.metagrid dt{color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;font-size:.78rem;
  padding-top:2px}
.metagrid dd{margin:0;color:var(--text-primary);font-family:var(--font-mono);word-break:break-all}
nav.toc{margin:28px 0 8px;padding:16px 20px;background:var(--bg-plate);
  border:1px solid var(--border-base);border-radius:3px}
nav.toc p{margin:0 0 8px;color:var(--brass);text-transform:uppercase;letter-spacing:.08em;
  font-size:.75rem}
nav.toc ol{margin:0;padding-left:20px}
nav.toc a{color:var(--text-secondary);text-decoration:none}
nav.toc a:hover{color:var(--text-bright)}
section{margin-top:40px}
h2{color:var(--brass);font-size:1.5rem;margin:0 0 14px;padding-bottom:6px;
  border-bottom:1px solid var(--border-base);font-weight:600;letter-spacing:.01em}
h3{color:var(--text-bright);font-size:1.15rem;margin:26px 0 10px;font-weight:600}
p{margin:0 0 14px}
table{border-collapse:collapse;width:100%;margin:0 0 18px;font-size:.9rem}
caption{caption-side:top;text-align:left;color:var(--text-dim);font-size:.8rem;
  text-transform:uppercase;letter-spacing:.06em;padding-bottom:6px}
th,td{border:1px solid var(--border-base);padding:7px 11px;text-align:left;vertical-align:top}
th{background:var(--bg-raised);color:var(--brass);font-weight:600;white-space:nowrap}
td{font-family:var(--font-mono);font-size:.85rem;color:var(--text-primary);word-break:break-word}
tbody tr:nth-child(even){background:var(--bg-plate)}
dl.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 18px;margin:0 0 18px;font-size:.92rem}
dl.kv dt{color:var(--text-secondary);white-space:nowrap}
dl.kv dd{margin:0;font-family:var(--font-mono);font-size:.86rem;word-break:break-all}
.callout{border-left:3px solid var(--border-bright);background:var(--bg-panel);
  padding:12px 16px;margin:0 0 18px;border-radius:0 3px 3px 0}
.callout .t{font-weight:700;letter-spacing:.02em;margin-bottom:3px}
.callout p{margin:0;color:var(--text-secondary);font-size:.93rem}
.callout.good{border-left-color:var(--phosphor)} .callout.good .t{color:var(--phosphor)}
.callout.warn{border-left-color:var(--brass);background:var(--brass-glow)}
.callout.warn .t{color:var(--brass)}
.callout.bad{border-left-color:var(--danger)} .callout.bad .t{color:var(--danger)}
.callout.neutral .t{color:var(--text-bright)}
pre{background:var(--bg-plate);border:1px solid var(--border-base);border-radius:3px;
  padding:12px 14px;overflow-x:auto;margin:0 0 18px}
code{font-family:var(--font-mono);font-size:.84rem;color:var(--text-primary)}
ul{margin:0 0 18px;padding-left:22px} li{margin-bottom:4px}
footer.doc{margin-top:64px;padding-top:18px;border-top:1px solid var(--border-base);
  color:var(--text-dim);font-size:.82rem}
@media print{
  :root{--bg-void:#fff;--bg-plate:#f7f7f7;--bg-panel:#f2f2f2;--bg-raised:#ededed;
    --border-base:#bbb;--border-bright:#999;--text-primary:#111;--text-secondary:#444;
    --text-dim:#666;--text-bright:#000;--brass:#7a5c12;--brass-glow:#fdf6e3;--danger:#a00}
  body{font-size:11pt} .wrap{max-width:none;padding:0}
  section{break-inside:avoid-page} table{break-inside:auto} tr{break-inside:avoid}
  nav.toc{break-after:page}
}
)CSS";

void indent(std::string& o, int n) {
    o.append(static_cast<std::size_t>(n) * 2, ' ');
}

// A stable anchor from a title: lowercase, non-alphanumerics to '-', runs
// collapsed. Deterministic, because the table of contents links to it.
std::string anchor_of(const Section& s, std::size_t ordinal) {
    if (!s.anchor.empty()) return s.anchor;
    std::string out;
    for (const char c : s.title) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalnum(u) != 0) {
            out.push_back(static_cast<char>(std::tolower(u)));
        } else if (!out.empty() && out.back() != '-') {
            out.push_back('-');
        }
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    if (out.empty()) out = "section-" + std::to_string(ordinal);
    return out;
}

// Every row squared to the header width, so a ragged table cannot produce
// broken markup.
std::vector<std::string> squared(const std::vector<std::string>& row, std::size_t width) {
    std::vector<std::string> out(
        row.begin(), row.begin() + static_cast<std::ptrdiff_t>(std::min(row.size(), width)));
    out.resize(width);
    return out;
}

std::size_t table_width(const Table& t) {
    std::size_t w = t.headers.size();
    if (w == 0)
        for (const auto& r : t.rows) w = std::max(w, r.size());
    return w;
}

// ------------------------------------------------------------------ HTML

void html_block(std::string& o, const Block& b, int depth) {
    if (const auto* p = std::get_if<Paragraph>(&b)) {
        if (p->text.empty()) return;
        indent(o, depth);
        o += "<p>" + escape_html(p->text) + "</p>\n";
        return;
    }
    if (const auto* c = std::get_if<Callout>(&b)) {
        indent(o, depth);
        o += std::string("<div class=\"callout ") + tone_name(c->tone) + "\">";
        if (!c->title.empty()) o += "<div class=\"t\">" + escape_html(c->title) + "</div>";
        if (!c->text.empty()) o += "<p>" + escape_html(c->text) + "</p>";
        o += "</div>\n";
        return;
    }
    if (const auto* cb = std::get_if<CodeBlock>(&b)) {
        indent(o, depth);
        o += "<pre><code";
        if (!cb->language.empty()) o += " class=\"lang-" + escape_html(cb->language) + "\"";
        o += ">" + escape_html(cb->text) + "</code></pre>\n";
        return;
    }
    if (const auto* l = std::get_if<BulletList>(&b)) {
        if (l->items.empty()) return;
        indent(o, depth);
        o += "<ul>\n";
        for (const std::string& i : l->items) {
            indent(o, depth + 1);
            o += "<li>" + escape_html(i) + "</li>\n";
        }
        indent(o, depth);
        o += "</ul>\n";
        return;
    }
    if (const auto* kv = std::get_if<KeyValues>(&b)) {
        if (kv->rows.empty()) return;
        indent(o, depth);
        o += "<dl class=\"kv\">\n";
        for (const auto& [k, v] : kv->rows) {
            indent(o, depth + 1);
            o += "<dt>" + escape_html(k) + "</dt><dd>" + escape_html(v) + "</dd>\n";
        }
        indent(o, depth);
        o += "</dl>\n";
        return;
    }
    const auto* t = std::get_if<Table>(&b);
    if (t == nullptr) return;
    const std::size_t w = table_width(*t);
    if (w == 0) return;
    indent(o, depth);
    o += "<table>\n";
    if (!t->caption.empty()) {
        indent(o, depth + 1);
        o += "<caption>" + escape_html(t->caption) + "</caption>\n";
    }
    if (!t->headers.empty()) {
        indent(o, depth + 1);
        o += "<thead><tr>";
        for (const std::string& h : squared(t->headers, w)) o += "<th>" + escape_html(h) + "</th>";
        o += "</tr></thead>\n";
    }
    indent(o, depth + 1);
    o += "<tbody>\n";
    for (const auto& r : t->rows) {
        indent(o, depth + 2);
        o += "<tr>";
        for (const std::string& c : squared(r, w)) o += "<td>" + escape_html(c) + "</td>";
        o += "</tr>\n";
    }
    indent(o, depth + 1);
    o += "</tbody>\n";
    indent(o, depth);
    o += "</table>\n";
}

void html_section(std::string& o, const Section& s, std::size_t ordinal, bool sub) {
    const std::string id = anchor_of(s, ordinal);
    if (sub) {
        o += "    <h3 id=\"" + escape_html(id) + "\">" + escape_html(s.title) + "</h3>\n";
    } else {
        o += "  <section>\n    <h2 id=\"" + escape_html(id) + "\">" + escape_html(s.title) +
             "</h2>\n";
    }
    for (const Block& b : s.blocks) html_block(o, b, 2);
    for (std::size_t i = 0; i < s.subsections.size(); ++i)
        html_section(o, s.subsections[i], i, true);
    if (!sub) o += "  </section>\n";
}

// -------------------------------------------------------------- Markdown

void md_block(std::string& o, const Block& b) {
    if (const auto* p = std::get_if<Paragraph>(&b)) {
        if (!p->text.empty()) o += escape_markdown(p->text) + "\n\n";
        return;
    }
    if (const auto* c = std::get_if<Callout>(&b)) {
        o += "> **" +
             escape_markdown(c->title.empty() ? std::string(tone_name(c->tone)) : c->title) + "**";
        if (!c->text.empty()) o += " — " + escape_markdown(c->text);
        o += "\n\n";
        return;
    }
    if (const auto* cb = std::get_if<CodeBlock>(&b)) {
        o += "```" + cb->language + "\n";
        o += cb->text;
        if (!cb->text.empty() && cb->text.back() != '\n') o += "\n";
        o += "```\n\n";
        return;
    }
    if (const auto* l = std::get_if<BulletList>(&b)) {
        for (const std::string& i : l->items) o += "- " + escape_markdown(i) + "\n";
        if (!l->items.empty()) o += "\n";
        return;
    }
    if (const auto* kv = std::get_if<KeyValues>(&b)) {
        if (kv->rows.empty()) return;
        if (!kv->caption.empty()) o += "*" + escape_markdown(kv->caption) + "*\n\n";
        o += "| | |\n|---|---|\n";
        for (const auto& [k, v] : kv->rows)
            o += "| " + escape_markdown(k) + " | " + escape_markdown(v) + " |\n";
        o += "\n";
        return;
    }
    const auto* t = std::get_if<Table>(&b);
    if (t == nullptr) return;
    const std::size_t w = table_width(*t);
    if (w == 0) return;
    if (!t->caption.empty()) o += "*" + escape_markdown(t->caption) + "*\n\n";
    const std::vector<std::string> head =
        t->headers.empty() ? std::vector<std::string>(w) : squared(t->headers, w);
    o += "|";
    for (const std::string& h : head) o += " " + escape_markdown(h) + " |";
    o += "\n|";
    for (std::size_t i = 0; i < w; ++i) o += "---|";
    o += "\n";
    for (const auto& r : t->rows) {
        o += "|";
        for (const std::string& c : squared(r, w)) o += " " + escape_markdown(c) + " |";
        o += "\n";
    }
    o += "\n";
}

void md_section(std::string& o, const Section& s, bool sub) {
    o += (sub ? "### " : "## ") + escape_markdown(s.title) + "\n\n";
    for (const Block& b : s.blocks) md_block(o, b);
    for (const Section& ss : s.subsections) md_section(o, ss, true);
}

}  // namespace

const char* tone_name(Tone t) {
    switch (t) {
        case Tone::Good:
            return "good";
        case Tone::Warn:
            return "warn";
        case Tone::Bad:
            return "bad";
        case Tone::Neutral:
            break;
    }
    return "neutral";
}

std::string escape_html(std::string_view s) {
    std::string o;
    o.reserve(s.size());
    for (const char c : s) {
        switch (c) {
            case '&':
                o += "&amp;";
                break;
            case '<':
                o += "&lt;";
                break;
            case '>':
                o += "&gt;";
                break;
            case '"':
                o += "&quot;";
                break;
            case '\'':
                o += "&#39;";
                break;
            default:
                o.push_back(c);
        }
    }
    return o;
}

std::string escape_markdown(std::string_view s) {
    std::string o;
    o.reserve(s.size());
    for (const char c : s) {
        // A pipe breaks a table and a backslash escapes the escape; a newline
        // inside a cell breaks the row. Everything else is left alone: a
        // report that escaped every asterisk would be unreadable.
        if (c == '|' || c == '\\') o.push_back('\\');
        if (c == '\n' || c == '\r') {
            o += "<br>";
            continue;
        }
        o.push_back(c);
    }
    return o;
}

std::string to_html(const Document& doc) {
    std::string o;
    o += "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
    o += "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n";
    o += "<title>" + escape_html(doc.meta.title) + "</title>\n<style>";
    o += kCss;
    o += "</style>\n</head>\n<body>\n<div class=\"wrap\">\n";

    o += "<header class=\"doc\">\n<h1>" + escape_html(doc.meta.title) + "</h1>\n";
    if (!doc.meta.subtitle.empty())
        o += "<p class=\"subtitle\">" + escape_html(doc.meta.subtitle) + "</p>\n";
    if (!doc.meta.fields.empty()) {
        o += "<dl class=\"metagrid\">\n";
        for (const auto& [k, v] : doc.meta.fields)
            o += "<dt>" + escape_html(k) + "</dt><dd>" + escape_html(v) + "</dd>\n";
        o += "</dl>\n";
    }
    o += "</header>\n";

    if (!doc.sections.empty()) {
        o += "<nav class=\"toc\">\n<p>Contents</p>\n<ol>\n";
        for (std::size_t i = 0; i < doc.sections.size(); ++i)
            o += "<li><a href=\"#" + escape_html(anchor_of(doc.sections[i], i)) + "\">" +
                 escape_html(doc.sections[i].title) + "</a></li>\n";
        o += "</ol>\n</nav>\n";
    }

    for (std::size_t i = 0; i < doc.sections.size(); ++i)
        html_section(o, doc.sections[i], i, false);

    o += "<footer class=\"doc\">Generated by OmniTrace. Every offset in this report is a byte "
         "offset into the evidence named above.</footer>\n";
    o += "</div>\n</body>\n</html>\n";
    return o;
}

std::string to_markdown(const Document& doc) {
    std::string o = "# " + escape_markdown(doc.meta.title) + "\n\n";
    if (!doc.meta.subtitle.empty()) o += escape_markdown(doc.meta.subtitle) + "\n\n";
    if (!doc.meta.fields.empty()) {
        o += "| | |\n|---|---|\n";
        for (const auto& [k, v] : doc.meta.fields)
            o += "| " + escape_markdown(k) + " | " + escape_markdown(v) + " |\n";
        o += "\n";
    }
    for (const Section& s : doc.sections) md_section(o, s, false);
    return o;
}

}  // namespace omnitrace::report
