// fixture_yaml.cpp — see fixture_yaml.h.
//
// Line-oriented recursive descent over indentation. Every line is classified
// once (indent, content, line number); blank lines, comments and document
// markers are dropped up front. A sequence item whose payload starts on the
// dash line (`- path: bin`) is re-written in place as a line indented to the
// payload column, so the ordinary mapping parser handles it.
#include "fixture_yaml.h"

#include <cstddef>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>

namespace omnitrace::fixture_yaml {

// ------------------------------------------------------------------ Node

Node Node::scalar(std::string text, bool quoted) {
    Node n;
    n.kind_ = Kind::Scalar;
    n.text_ = std::move(text);
    n.quoted_ = quoted;
    return n;
}

Node Node::sequence() {
    Node n;
    n.kind_ = Kind::Sequence;
    return n;
}

Node Node::mapping() {
    Node n;
    n.kind_ = Kind::Mapping;
    return n;
}

std::optional<std::int64_t> Node::as_int() const {
    if (kind_ != Kind::Scalar || text_.empty()) return std::nullopt;
    std::size_t i = 0;
    bool neg = false;
    if (text_[0] == '-' || text_[0] == '+') {
        neg = text_[0] == '-';
        i = 1;
    }
    if (i >= text_.size()) return std::nullopt;
    std::uint64_t v = 0;
    for (; i < text_.size(); ++i) {
        const char c = text_[i];
        if (c < '0' || c > '9') return std::nullopt;
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    const auto lim = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (neg) {
        if (v > lim + 1) return std::nullopt;
        if (v == lim + 1) return std::numeric_limits<std::int64_t>::min();
        return -static_cast<std::int64_t>(v);
    }
    if (v > lim) return std::nullopt;
    return static_cast<std::int64_t>(v);
}

std::optional<std::uint64_t> Node::as_uint() const {
    if (kind_ != Kind::Scalar || text_.empty()) return std::nullopt;
    std::uint64_t v = 0;
    for (const char c : text_) {
        if (c < '0' || c > '9') return std::nullopt;
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

std::optional<bool> Node::as_bool() const {
    if (kind_ != Kind::Scalar || quoted_) return std::nullopt;
    if (text_ == "true") return true;
    if (text_ == "false") return false;
    return std::nullopt;
}

std::size_t Node::size() const {
    if (kind_ == Kind::Sequence) return items_.size();
    if (kind_ == Kind::Mapping) return entries_.size();
    return 0;
}

const Node* Node::find(const std::string& key) const {
    if (kind_ != Kind::Mapping) return nullptr;
    for (const auto& [k, v] : entries_)
        if (k == key) return &v;
    return nullptr;
}

namespace {
const Node& null_node() {
    static const Node n;
    return n;
}
}  // namespace

const Node& Node::operator[](const std::string& key) const {
    const Node* n = find(key);
    return n ? *n : null_node();
}

const Node& Node::operator[](std::size_t index) const {
    if (kind_ != Kind::Sequence || index >= items_.size()) return null_node();
    return items_[index];
}

std::string Node::str_or(const std::string& key, const std::string& fallback) const {
    const Node* n = find(key);
    return n && n->is_scalar() ? n->str() : fallback;
}

void Node::push_back(Node item) {
    if (kind_ == Kind::Null) kind_ = Kind::Sequence;
    items_.push_back(std::move(item));
}

bool Node::set(std::string key, Node value) {
    if (kind_ == Kind::Null) kind_ = Kind::Mapping;
    if (find(key) != nullptr) return false;
    entries_.emplace_back(std::move(key), std::move(value));
    return true;
}

// ------------------------------------------------------------------ parser

namespace {

struct Line {
    std::size_t indent = 0;  // leading spaces
    std::string text;        // content after the indent, trailing whitespace trimmed
    std::size_t number = 0;  // 1-based line in the input, for errors
};

struct Failure {
    std::size_t line = 0;
    std::string what;
};

bool is_space(char c) {
    return c == ' ' || c == '\t';
}

std::string rtrim(std::string s) {
    while (!s.empty() && (is_space(s.back()) || s.back() == '\r')) s.pop_back();
    return s;
}

std::string ltrim(const std::string& s) {
    std::size_t i = 0;
    while (i < s.size() && is_space(s[i])) ++i;
    return s.substr(i);
}

// Splits the input into classified lines, dropping what carries no data.
std::optional<std::vector<Line>> classify(const std::string& text, Failure& err) {
    std::vector<Line> out;
    std::istringstream in(text);
    std::string raw;
    std::size_t number = 0;
    while (std::getline(in, raw)) {
        ++number;
        raw = rtrim(raw);
        std::size_t indent = 0;
        while (indent < raw.size() && raw[indent] == ' ') ++indent;
        if (indent < raw.size() && raw[indent] == '\t') {
            err = {number, "tab in indentation"};
            return std::nullopt;
        }
        const std::string content = raw.substr(indent);
        if (content.empty() || content[0] == '#') continue;
        if (indent == 0 && (content == "---" || content == "..." || content.rfind("--- ", 0) == 0))
            continue;
        out.push_back({indent, content, number});
    }
    return out;
}

class Parser {
   public:
    explicit Parser(std::vector<Line> lines) : lines_(std::move(lines)) {}

    std::optional<Node> run(Failure& err) {
        if (lines_.empty()) return Node{};
        std::optional<Node> root = parse_block(lines_.front().indent);
        if (!root) {
            err = err_;
            return std::nullopt;
        }
        if (pos_ < lines_.size()) {
            err = {lines_[pos_].number, "unexpected content (bad indentation?)"};
            return std::nullopt;
        }
        return root;
    }

   private:
    std::vector<Line> lines_;
    std::size_t pos_ = 0;
    Failure err_;

    bool at_end() const { return pos_ >= lines_.size(); }
    const Line& cur() const { return lines_[pos_]; }

    std::nullopt_t fail(std::size_t line, std::string what) {
        if (err_.what.empty()) err_ = {line, std::move(what)};
        return std::nullopt;
    }

    static bool is_dash_item(const std::string& t) { return t == "-" || t.rfind("- ", 0) == 0; }

    // Finds the end of a quoted string starting at s[0]; nullopt when it is
    // not closed on this line (a folded scalar continues on the next line).
    static std::optional<std::size_t> quoted_end(const std::string& s) {
        const char q = s[0];
        for (std::size_t i = 1; i < s.size(); ++i) {
            if (q == '"' && s[i] == '\\') {
                ++i;
                continue;
            }
            if (s[i] == q) {
                if (q == '\'' && i + 1 < s.size() && s[i + 1] == '\'') {
                    ++i;
                    continue;
                }
                return i;
            }
        }
        return std::nullopt;
    }

    // Position of the `: ` (or trailing `:`) that makes this line a mapping
    // entry; nullopt when it is a plain value.
    static std::optional<std::size_t> key_colon(const std::string& t) {
        std::size_t start = 0;
        if (!t.empty() && (t[0] == '\'' || t[0] == '"')) {
            const auto e = quoted_end(t);
            if (!e) return std::nullopt;
            start = *e + 1;
            if (start >= t.size() || t[start] != ':') return std::nullopt;
            if (start + 1 == t.size() || t[start + 1] == ' ') return start;
            return std::nullopt;
        }
        if (!t.empty() && (t[0] == '[' || t[0] == '{' || t[0] == '-' || t[0] == '#'))
            return std::nullopt;
        for (std::size_t i = 0; i < t.size(); ++i) {
            if (t[i] == '#' && i > 0 && is_space(t[i - 1])) return std::nullopt;
            if (t[i] == ':' && (i + 1 == t.size() || t[i + 1] == ' ')) return i;
        }
        return std::nullopt;
    }

    std::optional<Node> parse_block(std::size_t indent) {
        if (at_end()) return Node{};
        if (cur().indent != indent) return fail(cur().number, "unexpected indentation");
        if (is_dash_item(cur().text)) return parse_sequence(indent);
        if (key_colon(cur().text)) return parse_mapping(indent);
        // A bare scalar as a whole block (only sensible at the root).
        const Line l = cur();
        ++pos_;
        return parse_inline_value(l.text, indent, l.number);
    }

    std::optional<Node> parse_mapping(std::size_t indent) {
        Node map = Node::mapping();
        while (!at_end() && cur().indent == indent && !is_dash_item(cur().text)) {
            const Line l = cur();
            const auto colon = key_colon(l.text);
            if (!colon) return fail(l.number, "expected 'key: value'");
            std::string key;
            if (l.text[0] == '\'' || l.text[0] == '"') {
                std::optional<std::string> k = unquote_single_line(l.text.substr(0, *colon));
                if (!k) return fail(l.number, "bad quoted key");
                key = *k;
            } else {
                key = rtrim(l.text.substr(0, *colon));
            }
            const std::string rest = ltrim(l.text.substr(*colon + 1));
            ++pos_;
            std::optional<Node> value;
            if (rest.empty()) {
                if (!at_end() && cur().indent > indent)
                    value = parse_block(cur().indent);
                else if (!at_end() && cur().indent == indent && is_dash_item(cur().text))
                    value = parse_sequence(indent);  // PyYAML's indentless sequence
                else
                    value = Node{};
            } else {
                value = parse_inline_value(rest, indent, l.number);
            }
            if (!value) return std::nullopt;
            if (!map.set(key, std::move(*value)))
                return fail(l.number, "duplicate key '" + key + "'");
        }
        if (!at_end() && cur().indent > indent) return fail(cur().number, "unexpected indentation");
        return map;
    }

    std::optional<Node> parse_sequence(std::size_t indent) {
        Node seq = Node::sequence();
        while (!at_end() && cur().indent == indent && is_dash_item(cur().text)) {
            const std::size_t number = cur().number;
            const std::string rest = ltrim(cur().text.substr(1));
            if (rest.empty()) {
                ++pos_;
                if (!at_end() && cur().indent > indent) {
                    std::optional<Node> item = parse_block(cur().indent);
                    if (!item) return std::nullopt;
                    seq.push_back(std::move(*item));
                } else {
                    seq.push_back(Node{});
                }
                continue;
            }
            // Payload on the dash line: re-indent the line to the payload
            // column and let the block parser see it as a normal line.
            const std::size_t col = indent + (cur().text.size() - rest.size());
            if (is_dash_item(rest) || key_colon(rest)) {
                lines_[pos_].indent = col;
                lines_[pos_].text = rest;
                std::optional<Node> item = parse_block(col);
                if (!item) return std::nullopt;
                seq.push_back(std::move(*item));
                continue;
            }
            ++pos_;
            std::optional<Node> item = parse_inline_value(rest, indent, number);
            if (!item) return std::nullopt;
            seq.push_back(std::move(*item));
        }
        if (!at_end() && cur().indent > indent) return fail(cur().number, "unexpected indentation");
        return seq;
    }

    // A value that starts on the current line (already consumed); `owner` is
    // the indentation of the key or dash that owns it, so folded continuation
    // lines are those indented deeper.
    std::optional<Node> parse_inline_value(const std::string& first, std::size_t owner,
                                           std::size_t number) {
        if (first == "[]") return Node::sequence();
        if (first == "{}") return Node::mapping();
        if (first[0] == '[' || first[0] == '{')
            return fail(number, "flow collections are not supported");
        if (first[0] == '|' || first[0] == '>')
            return fail(number, "block scalars are not supported");
        if (first[0] == '&' || first[0] == '*' || first[0] == '!')
            return fail(number, "anchors, aliases and tags are not supported");
        if (first[0] == '\'' || first[0] == '"') return parse_quoted(first, owner, number);
        // Plain scalar, possibly folded over continuation lines.
        std::string text = first;
        while (!at_end() && cur().indent > owner) {
            if (key_colon(cur().text) || is_dash_item(cur().text))
                return fail(cur().number, "mapping values are not allowed inside a plain scalar");
            text += ' ';
            text += cur().text;
            ++pos_;
        }
        if (text == "~" || text == "null") return Node{};
        return Node::scalar(text, false);
    }

    std::optional<Node> parse_quoted(const std::string& first, std::size_t owner,
                                     std::size_t number) {
        const char q = first[0];
        std::string joined = first;
        std::optional<std::size_t> end = quoted_end(joined);
        while (!end) {
            if (at_end() || cur().indent <= owner)
                return fail(number, "unterminated quoted scalar");
            joined += ' ';
            joined += cur().text;
            ++pos_;
            end = quoted_end(joined);
        }
        if (*end + 1 != joined.size()) return fail(number, "trailing characters after quote");
        const std::string body = joined.substr(1, *end - 1);
        std::string out;
        out.reserve(body.size());
        for (std::size_t i = 0; i < body.size(); ++i) {
            const char c = body[i];
            if (q == '\'') {
                if (c == '\'' && i + 1 < body.size() && body[i + 1] == '\'') ++i;
                out += c;
                continue;
            }
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i + 1 >= body.size()) return fail(number, "dangling backslash");
            const char e = body[++i];
            switch (e) {
                case 'n':
                    out += '\n';
                    break;
                case 't':
                    out += '\t';
                    break;
                case 'r':
                    out += '\r';
                    break;
                case '0':
                    out += '\0';
                    break;
                case '\\':
                case '"':
                case '/':
                case ' ':
                    out += e;
                    break;
                case 'x':
                case 'u': {
                    const std::size_t width = e == 'x' ? 2 : 4;
                    if (i + width >= body.size())
                        return fail(number, "short \\" + std::string(1, e));
                    std::uint32_t cp = 0;
                    for (std::size_t k = 0; k < width; ++k) {
                        const char h = body[i + 1 + k];
                        std::uint32_t d;
                        if (h >= '0' && h <= '9')
                            d = static_cast<std::uint32_t>(h - '0');
                        else if (h >= 'a' && h <= 'f')
                            d = static_cast<std::uint32_t>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F')
                            d = static_cast<std::uint32_t>(h - 'A' + 10);
                        else
                            return fail(number, "bad hex escape");
                        cp = cp * 16 + d;
                    }
                    i += width;
                    append_utf8(out, cp);
                    break;
                }
                default:
                    return fail(number, std::string("unknown escape \\") + e);
            }
        }
        return Node::scalar(out, true);
    }

    static void append_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    std::optional<std::string> unquote_single_line(const std::string& s) {
        Parser sub({});
        std::optional<Node> n = sub.parse_quoted(s, 0, 0);
        if (!n) return std::nullopt;
        return n->str();
    }
};

}  // namespace

std::optional<Node> parse(const std::string& text, std::string* error) {
    Failure err;
    std::optional<std::vector<Line>> lines = classify(text, err);
    std::optional<Node> root;
    if (lines) {
        Parser p(std::move(*lines));
        root = p.run(err);
    }
    if (!root && error) *error = "line " + std::to_string(err.line) + ": " + err.what;
    return root;
}

std::optional<Node> parse_file(const std::string& path, std::string* error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (error) *error = "cannot open " + path;
        return std::nullopt;
    }
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::string why;
    std::optional<Node> n = parse(text, &why);
    if (!n && error) *error = path + ": " + why;
    return n;
}

}  // namespace omnitrace::fixture_yaml
