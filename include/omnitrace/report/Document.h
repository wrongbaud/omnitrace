// Document.h — a typed report document and its renderers.
/// @file Document.h
/// @brief `Document` (a report as data), the blocks it is made of, the HTML
/// and Markdown renderers, and the integrity gate.
///
/// **Why a document and not a string.** The previous generation of this built
/// Markdown by concatenation and shelled out to pandoc in a container to get
/// HTML. That was rejected for three reasons and all of them still hold:
/// provenance (a report is evidence and must not depend on a toolchain that
/// may not be installed or may differ between machines), escaping (string
/// concatenation puts a device's own bytes into markup, and a device name
/// containing `<script>` or a pipe character is attacker-controlled), and
/// determinism (the same case must render byte-identically every time, or two
/// reports of the same evidence cannot be compared).
///
/// So a report is built as data and rendered once. Every string is escaped by
/// the renderer that knows what escaping means for its format; a caller never
/// writes markup.
///
/// **This layer depends on core and nothing else**, which is the point: §7 of
/// the plan wants it liftable into a standalone `omnireport`. It knows about
/// sections, tables and callouts, and nothing about filesystems, platforms or
/// certificates. Whoever has that knowledge builds the Document.
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Status.h"

/// @namespace omnitrace::report
/// @brief A typed report document and its renderers.
namespace omnitrace::report {

/// What a block means, which the renderers turn into colour. Deliberately not
/// a severity: a report says "this is worth your attention", and the mapping
/// from a Diagnostic's severity to a tone is the document builder's decision.
enum class Tone : std::uint8_t {
    Neutral,  ///< Plain.
    Good,     ///< Something verified, checked out, matched.
    Warn,     ///< Worth an examiner's attention.
    Bad,      ///< A finding that changes what the examination should do next.
};
/// "neutral" | "good" | "warn" | "bad".
const char* tone_name(Tone t);

/// Flowing text. One paragraph, no markup.
struct Paragraph {
    std::string text;
};

/// A table. `headers` may be empty for a headerless grid; every row is padded
/// or cut to the header width by the renderer so the output is always square.
struct Table {
    std::string caption;
    std::vector<std::string> headers;
    std::vector<std::vector<std::string>> rows;
};

/// Label/value pairs: the shape most of a forensic report actually is.
struct KeyValues {
    std::string caption;
    std::vector<std::pair<std::string, std::string>> rows;
};

/// A boxed note. This is where a report raises its voice.
struct Callout {
    Tone tone = Tone::Neutral;
    std::string title;
    std::string text;
};

/// Preformatted text: a path, a hash, a hexdump. Never interpreted.
struct CodeBlock {
    std::string language;  ///< A hint for the HTML class; may be empty.
    std::string text;
};

/// A bulleted list.
struct BulletList {
    std::vector<std::string> items;
};

/// One piece of a section.
using Block = std::variant<Paragraph, Table, KeyValues, Callout, CodeBlock, BulletList>;

/// A section, which may hold subsections one level deep. Deeper nesting is
/// deliberately not modelled: a report that needs an h4 wants a new section.
struct Section {
    std::string title;
    std::string anchor;  ///< Stable id for the table of contents; derived when empty.
    std::vector<Block> blocks;
    std::vector<Section> subsections;
};

/// The front matter.
struct Meta {
    std::string title;
    std::string subtitle;
    /// Shown as a grid under the title: case name, evidence, tool version,
    /// generation time. The caller supplies the time -- this layer never reads
    /// a clock, so a Document renders identically whenever it is rendered.
    std::vector<std::pair<std::string, std::string>> fields;
};

/// A whole report.
struct Document {
    Meta meta;
    std::vector<Section> sections;
};

/// One piece of evidence the report stands on.
struct EvidenceRef {
    std::string label;   ///< How the report names it.
    std::string path;    ///< Where it was when the case was made.
    std::string sha256;  ///< What it hashed to then.
    std::uint64_t size = 0;
};

/// What re-hashing the evidence found.
struct IntegrityResult {
    bool verified = false;  ///< Every reference was found and matched.
    std::vector<Diagnostic> diagnostics;
    /// One row per reference: label, state ("ok", "mismatch", "missing",
    /// "unreadable"). Rendered into the report so the check is visible rather
    /// than implied.
    std::vector<std::pair<std::string, std::string>> states;
};

/// Re-hash each reference and compare with what the case recorded.
///
/// A report is a claim about specific bytes. If the evidence has changed since
/// the case was made, or is no longer where it was, every offset in the report
/// refers to something else and saying so is the only honest thing to do. The
/// caller decides whether a mismatch stops the report; `verified` reports the
/// fact, and the states appear in the document either way.
///
/// Re-hashing is real work on a large image, which is why it is a separate
/// call and not something the renderers do.
IntegrityResult verify_evidence(const std::vector<EvidenceRef>& refs);

/// Render as a self-contained HTML page: inline CSS, no external fonts, no
/// scripts, no network. Opens from a case directory on a machine with nothing
/// installed, which is what handing a report to someone else means.
std::string to_html(const Document& doc);

/// Render as Markdown. The same document, for a terminal or a diff.
std::string to_markdown(const Document& doc);

/// Escape for HTML text or an attribute. Exposed because the tests assert on
/// it directly: a device's own bytes end up in this output.
std::string escape_html(std::string_view s);
/// Escape for Markdown, including the table-breaking pipe.
std::string escape_markdown(std::string_view s);

}  // namespace omnitrace::report
