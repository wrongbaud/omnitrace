// fixture_yaml.h — a dependency-free parser for the YAML subset that
// tests/fixtures/generate.py writes (PyYAML safe_dump, block style).
//
// test_filesystems does not link yaml-cpp, and the reader tests must read the
// fixture ground truth without one. The subset is exactly what safe_dump
// emits for the fixture documents: block mappings, block sequences (also the
// "indentless" form PyYAML uses under a mapping key), plain / single-quoted /
// double-quoted scalars that may fold across lines, the empty flow
// collections `[]` and `{}`, full-line comments and document markers. No
// anchors, aliases, tags, block scalars (`|`, `>`) or non-empty flow
// collections: those never appear in a fixture file and a document using them
// is rejected with an error, never mis-parsed.
//
// Everything is kept as text; `as_int` / `as_uint` / `as_bool` convert on
// demand so `mode: '0755'` and `size: 68` are both reachable the way the
// caller wants them.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace omnitrace::fixture_yaml {

/// One YAML value. Mappings keep file order; keys are unique per mapping.
class Node {
   public:
    /// Value type.
    enum class Kind { Null, Scalar, Sequence, Mapping };

    /// A Null node.
    Node() = default;
    /// A Scalar node holding `text` (`quoted` records whether it was quoted).
    static Node scalar(std::string text, bool quoted);
    /// An empty Sequence node.
    static Node sequence();
    /// An empty Mapping node.
    static Node mapping();

    Kind kind() const { return kind_; }
    bool is_null() const { return kind_ == Kind::Null; }
    bool is_scalar() const { return kind_ == Kind::Scalar; }
    bool is_sequence() const { return kind_ == Kind::Sequence; }
    bool is_mapping() const { return kind_ == Kind::Mapping; }

    /// The scalar text; empty for any other kind.
    const std::string& str() const { return text_; }
    /// True when the scalar was written with quotes (`'0755'`).
    bool quoted() const { return quoted_; }
    /// Base-10 integer with optional sign; `nullopt` for anything else.
    std::optional<std::int64_t> as_int() const;
    /// Base-10 unsigned integer; `nullopt` for anything else.
    std::optional<std::uint64_t> as_uint() const;
    /// `true` / `false` (YAML 1.2 core); `nullopt` for anything else.
    std::optional<bool> as_bool() const;

    /// Sequence items, in order; empty for any other kind.
    const std::vector<Node>& items() const { return items_; }
    /// Mapping entries, in file order; empty for any other kind.
    const std::vector<std::pair<std::string, Node>>& entries() const { return entries_; }
    /// Items of a sequence or entries of a mapping; 0 otherwise.
    std::size_t size() const;

    /// Mapping lookup: the value under `key`, or `nullptr`.
    const Node* find(const std::string& key) const;
    /// True when this is a mapping with `key`.
    bool has(const std::string& key) const { return find(key) != nullptr; }
    /// Mapping lookup that never fails: a shared Null node when absent.
    const Node& operator[](const std::string& key) const;
    /// Sequence lookup that never fails: a shared Null node when out of range.
    const Node& operator[](std::size_t index) const;
    /// `find(key)->str()` or `fallback`.
    std::string str_or(const std::string& key, const std::string& fallback = {}) const;

    /// Append a sequence item (builder use).
    void push_back(Node item);
    /// Set a mapping entry; false when the key already exists.
    bool set(std::string key, Node value);

   private:
    Kind kind_ = Kind::Null;
    std::string text_;
    bool quoted_ = false;
    std::vector<Node> items_;
    std::vector<std::pair<std::string, Node>> entries_;
};

/// Parse `text`. On failure returns `nullopt` and sets `error` (when given)
/// to "line N: what".
std::optional<Node> parse(const std::string& text, std::string* error = nullptr);
/// Read `path` and parse it; a missing or unreadable file is an error too.
std::optional<Node> parse_file(const std::string& path, std::string* error = nullptr);

}  // namespace omnitrace::fixture_yaml
