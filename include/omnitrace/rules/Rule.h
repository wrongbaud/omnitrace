// Rule.h — user-extensible search rules and the engine that runs them.
/// @file Rule.h
/// @brief YAML search packs (`rules/*.yaml`), their compiled form, and the
/// hits they produce.
///
/// Discovery answers "what is this?". Rules answer "is the thing an examiner
/// came looking for in here?" — a MAC address, a private key, a VIN, a
/// password file — across every extracted file and every region no signature
/// claimed. The set is deliberately the examiner's to extend: a pack is a
/// YAML file, and `--rules` adds one to the built-ins.
///
/// Four kinds of rule, all compiled into one byte-oriented RE2 set so a scan
/// is a single pass rather than one per rule:
///
/// | kind | pattern | matched against |
/// |---|---|---|
/// | `regex` | an RE2 expression | file and region bytes |
/// | `literal` | exact text | file and region bytes |
/// | `hex` | bytes, `??` as a wildcard | file and region bytes |
/// | `glob-path` | a path glob | the entry's path, not its contents |
///
/// **Why RE2 and not `std::regex`.** A pack is untrusted input in exactly the
/// way an image is: a pattern with nested quantifiers makes a backtracking
/// engine run for longer than the heat death of the case. RE2 is linear in the
/// subject regardless of the pattern, which is the same bargain every reader
/// in this codebase makes with its own input.
///
/// Everything here is byte-oriented (RE2's Latin-1 mode). Evidence is not
/// text, and a rule that matched only valid UTF-8 would miss most of a flash
/// dump. Thread-safety: a built `Engine` is immutable and safe to share.
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Limits.h"
#include "omnitrace/core/Status.h"

/// @namespace omnitrace::rules
/// @brief Search packs, the matching engine and the hits it produces.
namespace omnitrace::rules {

/// How a rule's pattern is interpreted.
enum class Kind : std::uint8_t {
    Regex,     ///< An RE2 expression, byte-oriented.
    Literal,   ///< Exact bytes; the pattern is quoted before compiling.
    Hex,       ///< Hex byte pairs, `??` matching any byte.
    GlobPath,  ///< A glob over the entry's path; never looks at contents.
};

/// What a hit is worth to an examiner. Ordering is meaningful.
enum class Severity : std::uint8_t { Info, Low, Medium, High, Critical };

/// "regex", "literal", "hex", "glob-path"; "info".."critical".
const char* kind_name(Kind k);
const char* severity_name(Severity s);
/// Parse the names above; `false` when the text is not one of them.
bool parse_kind(std::string_view s, Kind& out);
bool parse_severity(std::string_view s, Severity& out);

/// One rule, as written in a pack.
struct Rule {
    std::string id;        ///< Unique within its pack; appears on every hit.
    std::string pack;      ///< The pack that defined it, filled in on load.
    std::string category;  ///< Free text: network, users, credentials, certs, pii, ...
    Kind kind = Kind::Regex;
    std::string pattern;
    /// Optional built-in post-filter that a candidate must also pass:
    /// `vin-checksum`, `luhn`, `mac-not-broadcast`. A match the filter rejects
    /// is not a hit. Empty means every match counts.
    std::string validate;
    Severity severity = Severity::Medium;
    bool in_files = true;    ///< Search extracted file contents.
    bool in_regions = true;  ///< Search regions no signature claimed.
    std::string description;
};

/// A named, versioned set of rules.
struct RulePack {
    std::string name;
    std::uint32_t version = 1;
    std::string origin;  ///< Where it was loaded from, for diagnostics.
    std::vector<Rule> rules;

    /// Parse one YAML document. Fails with `rules-...` and the offending
    /// rule's index and id, the way `SignatureSet::parse` does.
    static Status parse(std::string_view yaml, std::string_view origin, RulePack& out);
    /// Read and parse a file.
    static Status load_file(const std::string& path, RulePack& out);
    /// The packs compiled into the binary (`rules/*.yaml` at the repo root).
    static const std::vector<RulePack>& builtin();
};

/// One match, located and quoted.
struct Hit {
    std::string rule, pack, category;
    Severity severity = Severity::Medium;
    std::uint64_t offset = 0;  ///< Byte offset within the file or region scanned.
    std::string match;         ///< The matched bytes, sanitised and capped.
    std::string context;       ///< Surrounding bytes, sanitised and capped.
};

/// Caps on a scan. Evidence is adversarial and a pack is user input, so both
/// ends are bounded.
struct ScanLimits {
    /// Bytes read from one file or region. A larger one is scanned up to this
    /// and the shortfall reported, never skipped silently.
    std::uint64_t max_bytes_per_item = 64u << 20;
    std::uint64_t max_hits_per_rule_per_item =
        64;                                  ///< Keeps one chatty rule from burying the rest.
    std::uint64_t max_hits_total = 100'000;  ///< Whole-run ceiling.
    std::size_t context_bytes = 40;          ///< Quoted either side of a match.
};

/// A compiled set of packs. Build once, scan many times.
class Engine {
   public:
    Engine();
    ~Engine();
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;

    /// Compile every content rule into one RE2 set. Fails when a pattern does
    /// not compile, naming the rule; a pack with a bad rule is rejected whole
    /// rather than silently losing one line of an examiner's intent.
    static Status build(const std::vector<RulePack>& packs, Engine& out);

    /// Rules that look at bytes, and rules that look at paths.
    std::size_t content_rules() const;
    std::size_t path_rules() const;

    /// Match `data` (a file's or region's bytes) and append to `out`. `in_files`
    /// picks which rules apply. Hits come back ordered by offset then rule id,
    /// so a manifest is byte-identical run to run.
    void scan_bytes(std::span<const std::uint8_t> data, bool in_files, const ScanLimits& lim,
                    std::vector<Hit>& out) const;

    /// Match an entry's path against the `glob-path` rules.
    void scan_path(const std::string& path, std::vector<Hit>& out) const;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace omnitrace::rules
