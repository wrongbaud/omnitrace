// Signature.h — declarative format signatures + structural validators.
//
// A Signature is loaded from TOML (signatures/*.toml, embedded at build time):
//   [[signature]]
//   name = "squashfs-le"      format = "squashfs"   category = "filesystem"
//   magic = "hsqs"            # or hex = "68737173"
//   magic_offset = 0          # where in the structure the magic sits
//   validator = "squashfs"    # optional C++ validator name
//   endian = "little"
//   description = "..."       references = ["https://..."]
// The scanner finds every magic hit; the validator (if any) parses the header at
// (hit - magic_offset), decides the confidence tier, the structure size, and any
// diagnostics. Hits without a validator stay at Confidence::Magic.
/// @file Signature.h
/// @brief Format identification: `Signature` (a TOML rule), `Finding` (a
/// validated hit), `Validator` (the per-format check), the
/// `ValidatorRegistry`, `SignatureSet` and `scan()`.
///
/// docs/formats/signatures.md is the long-form contract: TOML schema, scanner
/// algorithm, conflict resolution and the validator rules. Thread-safety:
/// the registry is populated at static initialization by
/// `OMNITRACE_REGISTER_VALIDATOR` objects and read-only afterwards, so
/// `find()`/`names()` and `scan()` may run concurrently once `main()` has
/// started; `add()` is not synchronized. `SignatureSet::builtin()` is a
/// function-local static and therefore initialized once, thread-safely.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/core/Status.h"

/// @namespace omnitrace::discovery
/// @brief Signature scanning, validators and the analysis driver (`analyze`).
namespace omnitrace::discovery {

/// One `[[signature]]` table from signatures/*.toml. Immutable once loaded.
struct Signature {
    std::string name;      ///< Unique across every loaded file; lands in `Finding::signature`.
    std::string format;    ///< Canonical format id used for `Node::format` and reader lookup.
    std::string category;  ///< "filesystem" | "container" | "partition-table" | "kernel" |
                           ///< "bootloader" | "compressed" | "crypto" | "other".
    std::vector<std::uint8_t> magic;  ///< The bytes to search for (at least 2).
    std::uint64_t magic_offset = 0;   ///< Magic position relative to the structure start.
    std::optional<Endian> endian;     ///< Fixed byte order implied by this magic, if any.
    std::string validator;            ///< Registered validator name; empty = none.
    std::uint64_t alignment =
        1;  ///< Only accept hits whose structure start is a multiple of this (0/1 = any).
    std::string description;                   ///< Free text.
    std::vector<std::string> references;       ///< URLs.
    std::map<std::string, std::string> extra;  ///< Every other TOML key, stringified, for the
                                               ///< validator (its limits live here, not in code).
};

/// One identified structure inside a scanned Span. Produced by `scan()`;
/// `discovery::analyze` turns each into a Node.
///
/// A Validator fills `confidence`, `size`, `attrs`, `evidence`,
/// `diagnostics` and `endian`, and may override `format`/`category`
/// (ext -> "ext4", a uImage kernel -> "kernel"); the scanner sets `signature`
/// and prefixes `evidence` with the magic position.
struct Finding {
    std::uint64_t offset = 0;  ///< Structure start, relative to the scanned Span.
    std::uint64_t size =
        0;                  ///< Extent in bytes; 0 = unknown (magic-only hits, compressed streams).
    std::string format;     ///< Canonical format id.
    std::string category;   ///< As `Signature::category`.
    std::string signature;  ///< `Signature::name` that produced it.
    Confidence confidence = Confidence::Magic;  ///< Trust tier.
    std::string evidence;  ///< Why: "magic \"hsqs\" at 0x1c9245; superblock v4.0, bytes_used ...".
    Endian endian = Endian::Little;  ///< Byte order of the structure.
    std::map<std::string, std::string>
        attrs;  ///< version, compression, arch, label, ...; "also_covers" is read by the scanner.
    std::vector<Diagnostic>
        diagnostics;  ///< Caveats ("<fmt>-truncated", "validator-missing", "scan-hit-limit").
    std::vector<Finding>
        also_matched;  ///< Lower-confidence overlaps suppressed by conflict resolution.
};

// Validator contract: given the whole scanned Span and a candidate structure
// start, return a Finding with confidence/size/attrs filled, or std::nullopt to
// reject. Must never throw on bad input; must never read outside `span`.
/// The per-format structural check. Called with the whole scanned Span, the
/// candidate structure start (`hit - magic_offset`) and the Signature that
/// matched. Return a Finding, or `std::nullopt` to reject the hit as noise.
/// Must never throw and must read only through `span`, so a hostile header
/// yields `nullopt` or a low tier, never a crash.
///
/// ```cpp
/// std::optional<Finding> validate_romfs(const Span& span, std::uint64_t start,
///                                       const Signature& sig) {
///     const auto size = span.at<std::uint32_t>(start + 8, Endian::Big);
///     if (!size || *size < 16) return std::nullopt;          // not a romfs header
///     Finding f;
///     f.offset = start;
///     f.size = std::min<std::uint64_t>(*size, span.size() - start);
///     f.confidence = Confidence::Structural;
///     if (f.size < *size)
///         f.diagnostics.push_back({Severity::Warning, "romfs-truncated", "image ends early"});
///     f.attrs["size"] = std::to_string(*size);
///     return f;
/// }
/// OMNITRACE_REGISTER_VALIDATOR("romfs", validate_romfs);
/// ```
using Validator = std::function<std::optional<Finding>(const Span& span, std::uint64_t start,
                                                       const Signature& sig)>;

/// Name -> Validator, filled before `main()` by `OMNITRACE_REGISTER_VALIDATOR`.
/// `find()` and `names()` first force-link the built-in validators
/// (src/discovery/validators/builtin.cpp) so a static library keeps them.
class ValidatorRegistry {
   public:
    /// The process-wide registry.
    static ValidatorRegistry& instance();
    /// Register or replace `name`. Static-init time only; not synchronized.
    void add(const std::string& name, Validator v);
    /// The validator named `name`, or `nullptr`. The pointer stays valid for the
    /// life of the process (nothing is ever erased).
    const Validator* find(const std::string& name) const;
    /// Every registered name, sorted.
    std::vector<std::string> names() const;

   private:
    std::map<std::string, Validator> validators_;
};

// Static registration helper: `OMNITRACE_REGISTER_VALIDATOR("squashfs", fn);` at namespace scope.
/// Constructing one registers `v` under `name`; the macro below makes one at
/// namespace scope so registration happens at static initialization.
struct ValidatorRegistrar {
    /// Registers immediately.
    ValidatorRegistrar(const char* name, Validator v) {
        ValidatorRegistry::instance().add(name, std::move(v));
    }
};
/// Register validator function `fn` under the TOML name `name`. Put it at
/// namespace scope in the validator's .cpp, together with
/// `OMNITRACE_VALIDATOR_ANCHOR` and a line in validators/builtin.cpp.
#define OMNITRACE_REGISTER_VALIDATOR(name, fn)                                    \
    static ::omnitrace::discovery::ValidatorRegistrar _omnitrace_validator_##fn { \
        name, fn                                                                  \
    }

// Signature sets.
/// An ordered list of Signatures. `scan()` takes one; the builtin set is the
/// embedded `signatures/*.toml`, and `load_file`/`load_toml` append more.
struct SignatureSet {
    std::vector<Signature>
        signatures;  ///< In load order (file order, files sorted by name for the builtin set).
    /// Parse `toml_text` and append its `[[signature]]` tables. All-or-nothing:
    /// on any error the set is untouched and the Status reads
    /// "<origin>: signature[i] (name): <what>" (schema rules in docs/formats/signatures.md).
    Status load_toml(const std::string& toml_text, const std::string& origin);
    /// Read `path` and `load_toml` it with the path as origin.
    Status load_file(const std::string& path);
    // Signatures compiled into the binary from signatures/*.toml.
    /// The signatures compiled into the binary. Loaded once on first use;
    /// throws `std::logic_error` if the embedded files fail to parse, which is
    /// a build defect, not bad input.
    static const SignatureSet& builtin();
};

/// Knobs for `scan()`.
struct ScanOptions {
    bool validate =
        true;  ///< Run validators; false reports every magic hit at `Confidence::Magic`.
    bool resolve_conflicts = true;  ///< Deterministic overlap resolution (highest confidence, then
                                    ///< earliest, then largest); losers move to `also_matched`.
    std::uint64_t max_hits =
        1'000'000;  ///< Stop after this many findings; the last one gets "scan-hit-limit".
};

// Scan the whole Span for every signature; validated, sorted by offset, deduped.
/// Find every signature in `span`: magic search in 16 MiB chunks, validation,
/// same-signature coverage skipping, then (with `resolve_conflicts`) the
/// deterministic overlap resolution described in docs/formats/signatures.md.
/// Output is sorted by (offset, -confidence, -size, signature, format) and is
/// byte-identical run to run. Never fails; an unreadable Source just ends the scan.
std::vector<Finding> scan(const Span& span, const SignatureSet& sigs, const ScanOptions& opts = {});

}  // namespace omnitrace::discovery
